package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/announce"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/certcontrol"
	"github.com/Troglobitten/sgc/internal/dnsnames"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/proxycontrol"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/vpncontrol"
	"github.com/Troglobitten/sgc/internal/zone"
)

// publicIPVariable names a stand-in for the services that tell the home's
// public address, for the whole-machine test. It is honoured only while
// Zone.eu is a stand-in too: a made-up address must never reach the
// owner's real zone.
const publicIPVariable = "SGC_PUBLIC_IP_URL"

// parts are the pieces of SGC that hand out names and let people in: the
// gateway's own name, the services, the proxy, people and their VPN
// devices. They depend on each other (a service's name must not be the
// VPN's, the proxy keeps out VPN devices whose person does not have a
// service, the VPN lets devices reach the services on their list), so
// they are put together here, in one place.
type parts struct {
	gateway   *gateway.Control
	names     *dnsnames.Service
	catalog   *services.Catalog
	announcer *announce.Service
	proxy     *proxycontrol.Service
	people    *people.Service
	vpn       *vpncontrol.Service
	endpoint  *vpncontrol.Endpoint
}

type partsDeps struct {
	db       *sql.DB
	stateDir string
	helper   *helper.Client
	audit    *audit.Log
	auth     *auth.Service
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
	// Labels under the domain that other parts hold.
	reserved := func(ctx context.Context) (map[string]string, error) {
		name, err := gateway.Name(ctx, d.db)
		if err != nil {
			return nil, err
		}
		taken := map[string]string{name: "SGC's page", gateway.AdGuardName: "AdGuard Home's page"}
		if p.vpn.On(ctx) {
			taken[p.vpn.Label(ctx)] = "the VPN"
		}
		return taken, nil
	}
	everythingChanged := func() {
		p.names.Kick()
		p.proxy.Kick()
		p.vpn.Kick()
	}

	p.gateway = gateway.NewControl(gateway.ControlConfig{
		DB:      d.db,
		Audit:   d.audit,
		Domain:  domainOf,
		LAN:     lan,
		WebPort: layout.WebPort,
		Taken: func(ctx context.Context, label string) (string, error) {
			if p.vpn.On(ctx) && label == p.vpn.Label(ctx) {
				return "the VPN", nil
			}
			return p.catalog.HasName(ctx, label)
		},
		ProxyOn: func(ctx context.Context) bool { return p.proxy.On(ctx) },
		Log:     d.log,
	})

	p.catalog = services.New(services.Config{
		DB:       d.db,
		Audit:    d.audit,
		Domain:   domainOf,
		LAN:      lan,
		Reserved: reserved,
		ReservedPorts: func(ctx context.Context) []int {
			return []int{p.vpn.Settings(ctx).Port}
		},
		Changed: everythingChanged,
		Icons:   services.NewIconFetcher(),
		Log:     d.log,
	})

	p.announcer = announce.New(announce.Config{
		DB:       d.db,
		Audit:    d.audit,
		Services: p.catalog,
		Alert:    d.alert,
		Log:      d.log,
	})

	p.people = people.New(people.Config{
		DB:            d.db,
		Audit:         d.audit,
		Changed:       everythingChanged,
		AdminUsername: d.auth.AdminUsername,
		Log:           d.log,
	})

	zoneEndpointAddress, zoneStandIn := zoneEndpoint()
	var publicIP func(ctx context.Context) (netip.Addr, error)
	if url := os.Getenv(publicIPVariable); url != "" && zoneStandIn {
		d.log.Warn("asking a stand-in for the home's public address", "address", url)
		client := &http.Client{Timeout: 10 * time.Second}
		publicIP = func(ctx context.Context) (netip.Addr, error) { return vpncontrol.AskPublicIP(ctx, client, url) }
	}
	p.endpoint = vpncontrol.NewEndpoint(vpncontrol.EndpointConfig{
		DB:       d.db,
		Audit:    d.audit,
		Settings: func(ctx context.Context) vpncontrol.Settings { return p.vpn.Settings(ctx) },
		Zone: func(ctx context.Context) (*zone.Client, string, bool, error) {
			domain, username, apiKey, configured, err := d.domain.Account(ctx)
			if err != nil || !configured {
				return nil, "", false, err
			}
			client, err := zone.NewClient(zoneEndpointAddress, username, apiKey, "sgc/"+sgc.Version(), &http.Client{Timeout: 20 * time.Second})
			return client, domain, err == nil, err
		},
		PublicIP: publicIP,
		HTTP:     &http.Client{Timeout: 15 * time.Second},
		Alert:    d.alert,
		Log:      d.log,
	})
	p.vpn = vpncontrol.New(vpncontrol.Config{
		DB:       d.db,
		Helper:   d.helper,
		Audit:    d.audit,
		People:   p.people,
		Services: p.catalog,
		Domain:   domainOf,
		LAN:      lan,
		VerifyAdmin: func(ctx context.Context, password, remote string) error {
			return d.auth.VerifyAdminPassword(ctx, password, remote)
		},
		Endpoint: p.endpoint,
		Changed: func() {
			p.names.Kick()
			p.proxy.Kick()
		},
		Log: d.log,
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
			routes, err := p.catalog.ProxyServices(ctx, p.vpn.AllowFor(ctx))
			if err != nil {
				return proxy.Config{}, err
			}
			return proxy.Config{
				Domain: domain, GatewayName: name, WebPort: layout.WebPort,
				CertificatePEM: pair.CertificatePEM, PrivateKeyPEM: pair.PrivateKeyPEM,
				Services: routes, Reserved: []int{22, p.vpn.Settings(ctx).Port},
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
			vpnNames, err := p.vpn.Names(ctx)
			if err != nil {
				return nil, err
			}
			return append(append(own, theirs...), vpnNames...), nil
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
	start(func() { p.people.Run(ctx) })
	start(func() { p.vpn.Run(ctx) })
}
