package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/announce"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/certcontrol"
	"github.com/Troglobitten/sgc/internal/dnsnames"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/iconpack"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/maintenance"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/proxycontrol"
	"github.com/Troglobitten/sgc/internal/public"
	"github.com/Troglobitten/sgc/internal/publiccontrol"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/vpncontrol"
)

// publicIPVariable names a stand-in for the services that tell the home's
// public address, for the whole-machine test. It is honoured only while
// Zone.eu is a stand-in too: a made-up address must never reach the
// owner's real zone.
const publicIPVariable = "SGC_PUBLIC_IP_URL"

// iconPackVariable names a stand-in for where the icon pack is published,
// honoured like publicIPVariable only while Zone.eu is a stand-in too: the
// whole-machine test, which must not fetch the real pack from GitHub.
const iconPackVariable = "SGC_ICON_PACK_URL"

// fireholVariable and dbipVariable name stand-ins for where FireHOL's and
// DB-IP's lists are fetched, honoured like the others only while Zone.eu is
// a stand-in too.
const (
	fireholVariable = "SGC_FIREHOL_URL"
	dbipVariable    = "SGC_DBIP_URL"
)

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
	icons     *iconpack.Service
	public    *publiccontrol.Service
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
	// alertInternet is for what concerns the internet (a service opened or
	// closed); alertLogins for someone guessing a password.
	alertInternet func(ctx context.Context, title, body string)
	alertLogins   func(ctx context.Context, title, body string)
	// firewallOn reports whether SGC's firewall is on.
	firewallOn func(ctx context.Context) bool
}

func newParts(d partsDeps) *parts {
	p := &parts{}
	_, zoneStandInForIcons := zoneEndpoint()
	iconPackURL := iconpack.DefaultManifestURL
	if url := os.Getenv(iconPackVariable); url != "" && zoneStandInForIcons {
		d.log.Warn("asking a stand-in for the icon pack", "address", url)
		iconPackURL = url
	}
	p.icons = iconpack.New(iconpack.Config{
		Dir:         filepath.Join(d.stateDir, "icons"),
		ManifestURL: iconPackURL,
		HTTP:        &http.Client{Timeout: 5 * time.Minute},
		// The pack (about 20 MB) is fetched once there is a service to find
		// an icon for, and only while the owner's switch is on.
		Wanted: func(ctx context.Context) bool {
			settings, err := p.catalog.Settings(ctx)
			if err != nil || !settings.IconCatalogue {
				return false
			}
			list, err := p.catalog.List(ctx)
			return err == nil && len(list) > 0
		},
		Installed: func() { p.catalog.RefreshCollectionIcons(context.Background()) },
		Log:       d.log,
	})
	lan := netinfo.Reader{}.Find
	domainOf := func(ctx context.Context) (string, bool, error) {
		account, configured, err := d.domain.Account(ctx)
		return account.Domain, configured, err
	}
	if d.alert == nil {
		d.alert = func(ctx context.Context, title, body string) { d.log.Warn(title, "detail", body) }
	}
	if d.alertInternet == nil {
		d.alertInternet = d.alert
	}
	if d.alertLogins == nil {
		d.alertLogins = d.alert
	}
	if d.firewallOn == nil {
		d.firewallOn = func(context.Context) bool { return false }
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
		p.public.Kick()
		// The first service: the icon pack is fetched now, not tomorrow.
		if !p.icons.Status().Installed {
			p.icons.Kick()
		}
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
		Closed: func(ctx context.Context, name, why string) {
			d.alertInternet(ctx, name+" was closed to the internet",
				name+" was reachable from the internet, and SGC closed it: "+why+". Open it again in SGC's page if that is still wanted.")
		},
		Icons: services.NewIconFetcher(p.icons),
		Log:   d.log,
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
		Slowed: func(ctx context.Context, username, remote string) {
			d.alertLogins(ctx, "Someone may be guessing a person's password",
				"Wrong passwords for the login "+username+", the last from "+remote+". Its sign-ins are slowed down now.")
		},
		Log: d.log,
	})

	_, zoneStandIn := zoneEndpoint()
	if url := os.Getenv(publicIPVariable); url != "" && zoneStandIn {
		d.log.Warn("asking a stand-in for the home's public address", "address", url)
	}
	p.endpoint = vpncontrol.NewEndpoint(vpncontrol.EndpointConfig{
		DB:       d.db,
		Audit:    d.audit,
		Settings: func(ctx context.Context) vpncontrol.Settings { return p.vpn.Settings(ctx) },
		DNS:      d.domain.Open,
		PublicIP: homePublicIP(zoneStandIn),
		HTTP:     &http.Client{Timeout: 15 * time.Second},
		// Problems with the public name are told while they last, by the
		// notifications' own look (cmd/sgc/watch.go).
		Log: d.log,
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
			// Internet access (docs/design.md §14): the public door, and how
			// its visitors are filtered.
			door := p.public.On(ctx)
			var filters *public.Settings
			if door {
				if filters, err = p.public.BuildPublic(ctx); err != nil {
					return proxy.Config{}, err
				}
			}
			routes, err := p.catalog.ProxyServices(ctx, p.vpn.AllowFor(ctx), door)
			if err != nil {
				return proxy.Config{}, err
			}
			return proxy.Config{
				Domain: domain, GatewayName: name, WebPort: layout.WebPort,
				CertificatePEM: pair.CertificatePEM, PrivateKeyPEM: pair.PrivateKeyPEM,
				Services: routes, Reserved: []int{22, p.vpn.Settings(ctx).Port},
				Door: door, Public: filters,
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
	fireholBase, dbipBase := "", ""
	if zoneStandIn {
		if url := os.Getenv(fireholVariable); url != "" {
			d.log.Warn("asking a stand-in for FireHOL's lists", "address", url)
			fireholBase = url
		}
		if url := os.Getenv(dbipVariable); url != "" {
			d.log.Warn("asking a stand-in for DB-IP's country list", "address", url)
			dbipBase = url
		}
	}
	p.public = publiccontrol.New(publiccontrol.Config{
		DB:         d.db,
		Audit:      d.audit,
		Helper:     d.helper,
		Catalog:    p.catalog,
		FirewallOn: d.firewallOn,
		ProxyOn:    func(ctx context.Context) bool { return p.proxy.On(ctx) },
		Apply:      func(ctx context.Context) error { return p.proxy.ApplyNow(ctx) },
		DNS:        d.domain.Open,
		PublicIP:   homePublicIP(zoneStandIn),
		LAN:        lan,
		HTTP:       &http.Client{Timeout: 5 * time.Minute},
		// Where the root side reads them (public.DefaultPaths().ListsDir
		// for the service's own state folder).
		ListsDir:    filepath.Join(d.stateDir, "public"),
		FireHOLBase: fireholBase,
		DBIPBase:    dbipBase,
		Alert:       d.alertInternet,
		Window:      func(ctx context.Context) (int, int, error) { return maintenance.Window(ctx, d.db) },
		Log:         d.log,
	})
	p.gateway.UseNames(p.names)
	return p
}

// run starts the parts' background work.
func (p *parts) run(ctx context.Context, start func(func())) {
	start(func() { p.names.Run(ctx) })
	start(func() { p.catalog.Run(ctx, nil) })
	start(func() { p.icons.Run(ctx) })
	start(func() { p.proxy.Run(ctx) })
	start(func() { p.people.Run(ctx) })
	start(func() { p.vpn.Run(ctx) })
	start(func() { p.public.Run(ctx) })
}
