package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsprovider"
	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/vpncontrol"
)

// Environment variable naming another address for Zone.eu's API. The tests
// set it, so that they never talk to the real Zone.eu. Only root can set the
// service's environment, and SGC says in its log when it is in use: the API
// key is sent to whatever address this names.
const zoneEndpointVariable = "SGC_ZONE_API"

// newDomainControl keeps the owner's domain and the account at their DNS
// provider, and asks the provider about them.
func newDomainControl(db *sql.DB, auditLog *audit.Log, log *slog.Logger) *domaincontrol.Service {
	options := dnsOptions()
	if options.StandIn {
		log.Warn("talking to a stand-in instead of Zone.eu; no other DNS provider is used", "address", options.ZoneEndpoint)
	}
	return domaincontrol.New(domaincontrol.Config{
		DB:    db,
		Audit: auditLog,
		Log:   log,
		DNS:   options,
		Now:   time.Now,
	})
}

// dnsOptions is what opening the owner's DNS provider needs, for every part
// that does (the domain, the certificate, the VPN's name). With a stand-in
// for Zone.eu in the environment (the tests), no other provider is opened.
func dnsOptions() dnsprovider.Options {
	endpoint, standIn := zoneEndpoint()
	return dnsprovider.Options{
		HTTP:         &http.Client{Timeout: 20 * time.Second},
		UserAgent:    "sgc/" + sgc.Version(),
		ZoneEndpoint: endpoint,
		StandIn:      standIn,
		PublicIP:     homePublicIP(standIn),
	}
}

// homePublicIP asks what the home's address on the internet is: the
// services in vpncontrol.PublicIPServices, or the stand-in that
// publicIPVariable names while Zone.eu is a stand-in too.
func homePublicIP(standIn bool) func(ctx context.Context) (netip.Addr, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	if url := os.Getenv(publicIPVariable); url != "" && standIn {
		return func(ctx context.Context) (netip.Addr, error) { return vpncontrol.AskPublicIP(ctx, client, url) }
	}
	return func(ctx context.Context) (netip.Addr, error) {
		var last error
		for _, url := range vpncontrol.PublicIPServices {
			addr, err := vpncontrol.AskPublicIP(ctx, client, url)
			if err == nil {
				return addr, nil
			}
			last = err
		}
		return netip.Addr{}, last
	}
}

// checkDomain reports how SGC's last question to the DNS provider ended. It
// does not ask the provider itself: the doctor runs as root, and the key
// stays with the service. What it shows is therefore as old as that last
// question.
func checkDomain(stateDir string) doctor.Check {
	return func(ctx context.Context) []doctor.Result {
		var status domaincontrol.Status
		var said bytes.Buffer
		// The database belongs to the service user; root does not open it.
		if err := runAsServiceUser(ctx, []string{"doctor", "--as-service-user", "domain", "--state-dir", stateDir}, nil, &status, &said); err != nil {
			reason := strings.TrimSpace(said.String())
			if reason == "" {
				reason = err.Error()
			}
			return one(doctor.Warn("The state of the domain could not be read: "+reason, ""))
		}
		provider := status.ProviderName
		kind, _ := dnsprovider.Lookup(status.Provider)
		switch {
		case !status.Configured:
			return one(doctor.Good("No domain is set up yet (that is done on SGC's System page, under Domain)"))
		case status.CheckedAt == nil:
			return one(doctor.Good("The domain is " + status.Domain + "; SGC has not asked " + provider + " about it yet"))
		case status.OK:
			return one(doctor.Good(provider + " accepted the saved " + kind.Credentials + " for " + status.Domain + " when SGC last asked"))
		default:
			since := ""
			if status.FailingSince != nil {
				since = " (since " + status.FailingSince.Local().Format("2 January 15:04") + ")"
			}
			return one(doctor.Bad("The domain "+status.Domain+": "+status.Problem+since,
				"If the "+kind.Credentials+" were replaced or withdrawn at "+provider+": make new ones there, and enter them on SGC's System page, under Domain.\n"+
					"If this device does not reach the internet, that is the thing to put right first.\n"+
					"SGC asks "+provider+" again every hour; \"Ask "+provider+" now\" on that page does it at once."))
		}
	}
}

// doctorWorker is the part of `sgc doctor` that runs as the service user.
func doctorWorker(ctx context.Context, task, stateDir string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitFailed
	}
	syscall.Umask(0o077)
	db, err := store.Open(ctx, filepath.Join(stateDir, layout.DatabaseFile))
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	domainControl := newDomainControl(db, audit.New(db), quiet)
	// Both read what SGC has recorded; neither asks anybody.
	var status any
	switch task {
	case "domain":
		status, err = domainControl.Status(ctx)
	case "certificate":
		status, err = newCertControl(db, audit.New(db), quiet, domainControl).Status(ctx)
	case "parts":
		status, err = readPartsReport(ctx, db, domainControl, quiet)
	default:
		return fail(fmt.Errorf("unknown task %q", task))
	}
	if err != nil {
		return fail(err)
	}
	if err := json.NewEncoder(stdout).Encode(status); err != nil {
		return fail(err)
	}
	return exitOK
}
