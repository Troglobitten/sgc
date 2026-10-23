package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/announce"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/certcontrol"
	"github.com/Troglobitten/sgc/internal/dnsnames"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/proxycontrol"
	"github.com/Troglobitten/sgc/internal/services"
)

// parts are the pieces of SGC that hand out names: the gateway's own, the
// services', and how they reach AdGuard Home and Traefik. They depend on
// each other (a service's name must not be the gateway's, the proxy routes
// the services), so they are put together here, in one place.
type parts struct {
	gateway   *gateway.Control
	names     *dnsnames.Service
	catalog   *services.Catalog
	announcer *announce.Service
	proxy     *proxycontrol.Service
}

type partsDeps struct {
	db       *sql.DB
	stateDir string
	helper   *helper.Client
	audit    *audit.Log
	log      *slog.Logger
	domain   *domaincontrol.Service
	cert     *certcontrol.Service
	// alert reports something the owner should know at once.
	alert func(ctx context.Context, title, body string)
}

func newParts(d partsDeps) *parts {
	p := &parts{}
	lan := netinfo.Reader{}.Find
	domainOf := func(ctx context.Context) (string, bool, error) {
		domain, _, _, configured, err := d.domain.Account(ctx)
		return domain, configured, err
	}
	if d.alert == nil {
		d.alert = func(ctx context.Context, title, body string) { d.log.Warn(title, "detail", body) }
	}

	p.gateway = gateway.NewControl(gateway.ControlConfig{
		DB:      d.db,
		Audit:   d.audit,
		Domain:  domainOf,
		LAN:     lan,
		WebPort: layout.WebPort,
		Taken: func(ctx context.Context, label string) (string, error) {
			return p.catalog.HasName(ctx, label)
		},
		ProxyOn: func(ctx context.Context) bool { return p.proxy.On(ctx) },
		Log:     d.log,
	})

	p.catalog = services.New(services.Config{
		DB:     d.db,
		Audit:  d.audit,
		Domain: domainOf,
		LAN:    lan,
		Reserved: func(ctx context.Context) (map[string]string, error) {
			name, err := gateway.Name(ctx, d.db)
			if err != nil {
				return nil, err
			}
			return map[string]string{name: "SGC's page", gateway.AdGuardName: "AdGuard Home's page"}, nil
		},
		Changed: func() {
			p.names.Kick()
			p.proxy.Kick()
		},
		Icons: services.NewIconFetcher(),
		Log:   d.log,
	})

	p.announcer = announce.New(announce.Config{
		DB:       d.db,
		Audit:    d.audit,
		Services: p.catalog,
		Alert:    d.alert,
		Log:      d.log,
	})

	p.proxy = proxycontrol.New(proxycontrol.Config{
		DB:       d.db,
		Helper:   d.helper,
		Audit:    d.audit,
		HTTP:     &http.Client{Timeout: 10 * time.Minute},
		SpoolDir: filepath.Join(d.stateDir, "components"),
		Arch:     runtime.GOARCH,
		Build: func(ctx context.Context) (proxy.Config, error) {
			domain, configured, err := domainOf(ctx)
			if err != nil {
				return proxy.Config{}, err
			}
			if !configured {
				return proxy.Config{}, problem.New("The proxy needs your domain first (System, Domain).")
			}
			pair, err := d.cert.Serving(ctx)
			if err != nil {
				return proxy.Config{}, err
			}
			if pair == nil {
				return proxy.Config{}, problem.New("The proxy needs the certificate for your domain first (System, Certificate).")
			}
			name, err := gateway.Name(ctx, d.db)
			if err != nil {
				return proxy.Config{}, err
			}
			routes, err := p.catalog.ProxyServices(ctx, nil)
			if err != nil {
				return proxy.Config{}, err
			}
			return proxy.Config{
				Domain: domain, GatewayName: name, WebPort: layout.WebPort,
				CertificatePEM: pair.CertificatePEM, PrivateKeyPEM: pair.PrivateKeyPEM,
				Services: routes, Reserved: []int{22},
			}, nil
		},
		Applied: func() { p.names.Kick() },
		Log:     d.log,
	})

	p.names = dnsnames.New(dnsnames.Config{
		DB:      d.db,
		AdGuard: &dnsnames.Client{Base: "http://" + adguard.WebAddress, HTTP: &http.Client{Timeout: 15 * time.Second}},
		Desired: func(ctx context.Context) ([]dnsnames.Name, error) {
			own, err := p.gateway.Desired(ctx)
			if err != nil {
				return nil, err
			}
			theirs, err := p.catalog.Names(ctx, p.proxy.On(ctx))
			if err != nil {
				return nil, err
			}
			return append(own, theirs...), nil
		},
		Log: d.log,
	})
	p.gateway.UseNames(p.names)
	return p
}

// run starts the parts' background work.
func (p *parts) run(ctx context.Context, start func(func())) {
	start(func() { p.names.Run(ctx) })
	start(func() { p.catalog.Run(ctx, nil) })
	start(func() { p.proxy.Run(ctx) })
}
