package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/proxycontrol"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
)

// partsReport is what the doctor's worker reads from the database about
// names, the proxy and the services.
type partsReport struct {
	Configured  bool     `json:"configured"`
	Domain      string   `json:"domain"`
	GatewayName string   `json:"gatewayName"`
	ProxyWanted bool     `json:"proxyWanted"`
	Down        []string `json:"down"`
	Abandoned   []string `json:"abandoned"`
	Pending     []string `json:"pending"`
}

func readParts(ctx context.Context, stateDir string) (partsReport, error) {
	var report partsReport
	var said bytes.Buffer
	if err := runAsServiceUser(ctx, []string{"doctor", "--as-service-user", "parts", "--state-dir", stateDir}, nil, &report, &said); err != nil {
		reason := strings.TrimSpace(said.String())
		if reason == "" {
			reason = err.Error()
		}
		return report, fmt.Errorf("%s", reason)
	}
	return report, nil
}

// lookUpAtAdGuard asks AdGuard Home for a name the way a device would.
func lookUpAtAdGuard(ctx context.Context, name string) ([]string, error) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", adguard.DNSPort))
	}}
	asked, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return resolver.LookupHost(asked, name)
}

// servedNames returns the names in the certificate a TLS server shows when
// asked for serverName.
func servedNames(ctx context.Context, address, serverName string) ([]string, error) {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: true}} //nolint:gosec // only the names are read
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate")
	}
	return certs[0].DNSNames, nil
}

// checkNames: the gateway's name answers with this device's address at
// AdGuard Home, and SGC's page shows the certificate for it.
func checkNames(stateDir string) doctor.Check {
	return func(ctx context.Context) []doctor.Result {
		lan, lanErr := netinfo.Reader{}.Find()
		if lanErr != nil {
			return one(doctor.Bad("This device's address in the home network could not be found: "+lanErr.Error(),
				"Check that the device is connected to the network (ip route should show a default route)."))
		}
		report, err := readParts(ctx, stateDir)
		if err != nil {
			return one(doctor.Warn("The names could not be read: "+err.Error(), ""))
		}
		results := one(doctor.Good(fmt.Sprintf("This device is %s in the home network (on %s); give it a fixed address in the router if it does not have one", lan.Address, lan.Interface)))
		if !report.Configured {
			return results
		}
		fqdn := report.GatewayName + "." + report.Domain
		if !adguard.Installed(adguard.DefaultPaths()) {
			return append(results, doctor.Warn("DNS is off, so "+fqdn+" works nowhere", "Switch DNS on (SGC's System page, or sudo sgc dns on)."))
		}
		addresses, err := lookUpAtAdGuard(ctx, fqdn)
		switch {
		case err != nil:
			results = append(results, doctor.Bad(fqdn+" has no answer at AdGuard Home: "+err.Error(),
				"SGC puts the name in place within a minute of starting. If it stays missing: the System page, Names, says why; SGC's log has more (sudo journalctl -u sgc --no-pager -n 50)."))
		case !slices.Contains(addresses, lan.Address.String()):
			results = append(results, doctor.Bad(fmt.Sprintf("%s points at %s, not at this device (%s)", fqdn, strings.Join(addresses, ", "), lan.Address),
				"A rewrite of your own in AdGuard Home may hold the name; the System page, Names, says so. Remove it in AdGuard Home's page."))
		default:
			results = append(results, doctor.Good(fqdn+" points at this device in AdGuard Home"))
		}
		names, err := servedNames(ctx, fmt.Sprintf("127.0.0.1:%d", layout.WebPort), fqdn)
		switch {
		case err != nil:
			results = append(results, doctor.Warn("SGC's page could not be asked for its certificate: "+err.Error(), ""))
		case slices.Contains(names, "*."+report.Domain):
			results = append(results, doctor.Good("SGC's page shows the certificate for *."+report.Domain+" at "+fqdn))
		default:
			results = append(results, doctor.Good("SGC's page shows its own certificate at "+fqdn+" until there is one for *."+report.Domain))
		}
		return results
	}
}

// checkProxy: switched on means Traefik runs, answers its health check and
// holds the web ports. Services that are down are listed.
func checkProxy(stateDir string) doctor.Check {
	return func(ctx context.Context) []doctor.Result {
		report, err := readParts(ctx, stateDir)
		if err != nil {
			return one(doctor.Warn("The proxy's state could not be read: "+err.Error(), ""))
		}
		paths := proxy.DefaultPaths()
		const traefikLog = "Its log: sudo journalctl -u sgc-traefik --no-pager -n 30"
		var results []doctor.Result
		switch {
		case !report.ProxyWanted && !proxy.Installed(paths):
			results = append(results, doctor.Good("The proxy is off; Traefik is not on this device yet (switching it on, on the Services page, installs it)"))
		case !report.ProxyWanted:
			results = append(results, doctor.Good("The proxy is off (Traefik "+proxy.InstalledVersion(paths)+" stays on the device)"))
		default:
			state, _ := ask(ctx, "/usr/bin/systemctl", "is-active", proxy.ServiceUnit)
			if state != "active" {
				results = append(results, doctor.Bad("The proxy is switched on but Traefik is not running ("+state+")",
					"Start it: sudo systemctl start sgc-traefik\n"+traefikLog))
				break
			}
			client := &http.Client{Timeout: 4 * time.Second}
			resp, err := client.Get("http://" + proxy.TraefikAPI + "/ping")
			if err != nil {
				results = append(results, doctor.Bad("Traefik runs but does not answer its health check: "+err.Error(), traefikLog))
				break
			}
			resp.Body.Close()
			results = append(results, doctor.Good("The proxy runs: Traefik "+proxy.InstalledVersion(paths)+" answers for the services' names"))
		}
		if len(report.Pending) > 0 {
			results = append(results, doctor.Warn("Announced and waiting for your approval: "+strings.Join(report.Pending, ", "), "Approve or remove them on SGC's Services page."))
		}
		if len(report.Down) > 0 {
			results = append(results, doctor.Warn("Not answering: "+strings.Join(report.Down, ", "),
				"Is the device switched on, and does it still have the address SGC knows (Services page)?"))
		}
		if len(report.Abandoned) > 0 {
			results = append(results, doctor.Warn("Down for a long time, so they look abandoned: "+strings.Join(report.Abandoned, ", "),
				"Remove them on SGC's Services page if they are gone for good."))
		}
		return results
	}
}

// readPartsReport is the worker's side: what the database says.
func readPartsReport(ctx context.Context, db *sql.DB, domain *domaincontrol.Service, log *slog.Logger) (partsReport, error) {
	var report partsReport
	name, _, _, configured, err := domain.Account(ctx)
	if err != nil {
		return report, err
	}
	report.Configured, report.Domain = configured, name
	if report.GatewayName, err = gateway.Name(ctx, db); err != nil {
		return report, err
	}
	wanted, _, err := store.Setting(ctx, db, proxycontrol.SettingEnabled)
	if err != nil {
		return report, err
	}
	report.ProxyWanted = wanted == "true"
	catalog := services.New(services.Config{
		DB: db, Audit: audit.New(db), Log: log,
		Domain:   func(context.Context) (string, bool, error) { return name, configured, nil },
		LAN:      netinfo.Reader{}.Find,
		Reserved: func(context.Context) (map[string]string, error) { return nil, nil },
	})
	list, err := catalog.List(ctx)
	if err != nil {
		return report, err
	}
	report.Down, report.Abandoned, report.Pending = []string{}, []string{}, []string{}
	for _, s := range list {
		switch {
		case s.Pending:
			report.Pending = append(report.Pending, s.Name)
		case !s.Enabled:
		case s.Health.Abandoned:
			report.Abandoned = append(report.Abandoned, s.Name)
		case s.Health.State == "down":
			report.Down = append(report.Down, s.Name)
		}
	}
	return report, nil
}
