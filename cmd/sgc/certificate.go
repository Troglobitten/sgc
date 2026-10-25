package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/lego"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/certcontrol"
	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
	"github.com/Troglobitten/sgc/internal/zone"
)

// Environment variables that put stand-ins in the place of Let's Encrypt.
// Like SGC_ZONE_API they exist for the tests, which never talk to the real
// thing; only root can set the service's environment.
const (
	// The addresses of the authority's directory and of its test authority's.
	acmeDirectoryVariable      = "SGC_ACME_DIRECTORY"
	acmeTrialDirectoryVariable = "SGC_ACME_TRIAL_DIRECTORY"
	// A file with the certificate the stand-in authorities show.
	acmeRootsVariable = "SGC_ACME_ROOTS"
	// The DNS server to ask whether a proof shows (the stand-in for Zone.eu's
	// name servers), as "address:port".
	acmeDNSVariable = "SGC_ACME_DNS"
)

// zoneEndpoint is where Zone.eu's API is: the real one, unless the
// environment names another.
func zoneEndpoint() (endpoint string, standIn bool) {
	if address := os.Getenv(zoneEndpointVariable); address != "" {
		return address, true
	}
	return zone.DefaultEndpoint, false
}

// newCertControl gets and renews the certificate for the owner's domain.
//
// The outside world is either all real or all stand-ins. An SGC whose
// environment replaces Zone.eu but not Let's Encrypt, or the other way
// round, gets no certificates at all: half of a test set-up must never ask
// the real Let's Encrypt for a certificate for a made-up domain, or publish
// test records in the owner's real zone.
func newCertControl(db *sql.DB, auditLog *audit.Log, log *slog.Logger, domain *domaincontrol.Service) *certcontrol.Service {
	options := dnsOptions()
	zoneStandIn := options.StandIn
	cfg := certcontrol.Config{
		DB:             db,
		Audit:          auditLog,
		Log:            log,
		Account:        domain.Account,
		DNS:            options,
		UserAgent:      "sgc/" + sgc.Version(),
		Directory:      lego.LEDirectoryProduction,
		TrialDirectory: lego.LEDirectoryStaging,
		AuthorityHTTP:  &http.Client{Timeout: 30 * time.Second},
		// As long as the provider's name servers need to show a change
		// (dnsprovider.Kind.Propagation: ten minutes for Zone.eu, an hour
		// for Namecheap).
		PropagationTimeout:  0,
		PropagationInterval: 10 * time.Second,
		// Let's Encrypt asks from several places in the world, and name
		// servers far away can be behind the ones nearby. How far is not
		// known: a change took 40 to 50 seconds to show nearby, and without
		// any wait the first real attempt failed (see internal/certcontrol).
		// So SGC waits two minutes after it sees the proof itself, a few
		// times what was measured, and two minutes between the trial and the
		// real request, whose proofs go under the same name: Let's Encrypt's
		// own resolvers remember an answer for up to a minute. A failure
		// costs the owner a quarter of an hour and counts against Let's
		// Encrypt's limit; waiting costs nothing but time nobody watches.
		Settle:   2 * time.Minute,
		TrialGap: 2 * time.Minute,
		// Let's Encrypt allows five failed proofs an hour, and five
		// certificates for the same names a week. The button stays well
		// below both. (Renewals that SGC makes by itself are not held back
		// by these two: they have their own, slower pace.)
		RetryAfterFailure: 15 * time.Minute,
		RenewAgainAfter:   48 * time.Hour,
		Now:               time.Now,
	}

	directory, trial := os.Getenv(acmeDirectoryVariable), os.Getenv(acmeTrialDirectoryVariable)
	roots, resolver := os.Getenv(acmeRootsVariable), os.Getenv(acmeDNSVariable)
	if !zoneStandIn && directory == "" && trial == "" && roots == "" && resolver == "" {
		return certcontrol.New(cfg)
	}
	if !zoneStandIn || directory == "" || trial == "" || roots == "" || resolver == "" {
		cfg.Disabled = "This SGC is set up half for testing: its environment replaces some of Zone.eu and Let's Encrypt with stand-ins, but not all. It gets no certificates until all of " +
			strings.Join([]string{zoneEndpointVariable, acmeDirectoryVariable, acmeTrialDirectoryVariable, acmeRootsVariable, acmeDNSVariable}, ", ") + " are set, or none."
		log.Error("certificates are switched off", "reason", cfg.Disabled)
		return certcontrol.New(cfg)
	}
	pem, err := os.ReadFile(roots)
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		cfg.Disabled = "This SGC is set up for testing, but the certificate of the stand-in for Let's Encrypt cannot be read from " + roots + "."
		log.Error("certificates are switched off", "reason", cfg.Disabled, "error", err)
		return certcontrol.New(cfg)
	}
	log.Warn("talking to stand-ins instead of Let's Encrypt", "directory", directory, "trial", trial, "dns", resolver)
	cfg.Directory, cfg.TrialDirectory, cfg.DNSResolver = directory, trial, resolver
	cfg.AuthorityHTTP = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	// A stand-in answers at once and counts nothing.
	cfg.PropagationTimeout, cfg.PropagationInterval = 30*time.Second, 500*time.Millisecond
	cfg.Settle, cfg.TrialGap = time.Second, time.Second
	cfg.RetryAfterFailure, cfg.RenewAgainAfter = 0, 0
	return certcontrol.New(cfg)
}

// checkCertificate reports on the certificate as SGC has it. Like the check
// of the domain it reads SGC's own records and asks nobody.
func checkCertificate(stateDir string) doctor.Check {
	return func(ctx context.Context) []doctor.Result {
		var status certcontrol.Status
		var said bytes.Buffer
		if err := runAsServiceUser(ctx, []string{"doctor", "--as-service-user", "certificate", "--state-dir", stateDir}, standInEnvironment(), &status, &said); err != nil {
			reason := strings.TrimSpace(said.String())
			if reason == "" {
				reason = err.Error()
			}
			return one(doctor.Warn("The state of the certificate could not be read: "+reason, ""))
		}
		const where = "SGC's System page, under Domain and names"
		c := status.Certificate
		switch {
		case status.Disabled != "":
			return one(doctor.Warn(status.Disabled, ""))
		case c == nil && status.Domain == "":
			return one(doctor.Good("No certificate yet: it needs a domain first"))
		case c == nil && status.LastAttempt != nil && !status.LastAttempt.OK:
			return one(doctor.Bad("No certificate yet, and the last attempt failed: "+status.LastAttempt.Message,
				"When what it names is put right, ask again on "+where+"."))
		case c == nil:
			return one(doctor.Good("No certificate yet (it is requested on " + where + ")"))
		}
		names := strings.Join(c.Names, ", ")
		days := int(math.Floor(time.Until(c.NotAfter).Hours() / 24))
		until := c.NotAfter.Local().Format("2 January 2006")
		failing := status.LastAttempt != nil && !status.LastAttempt.OK && status.LastAttempt.Kind == certcontrol.KindRenewal
		switch {
		case !c.ForDomain:
			return one(doctor.Warn("The certificate is for "+names+", which is not the domain that is set up now",
				"Request one for the present domain on "+where+"."))
		case days < 0:
			return one(doctor.Bad("The certificate for "+names+" ran out on "+until,
				"Request a new one on "+where+". If that fails, the page says why."))
		case failing && days < 14:
			return one(doctor.Bad(fmt.Sprintf("The certificate for %s runs out in %d days, and renewing it fails: %s", names, days, status.LastAttempt.Message),
				"SGC tries again twice a day. \"Renew now\" on "+where+" tries at once."))
		case failing:
			return one(doctor.Warn(fmt.Sprintf("Renewing the certificate for %s fails (it is valid for %d more days): %s", names, days, status.LastAttempt.Message),
				"SGC tries again twice a day. \"Renew now\" on "+where+" tries at once."))
		default:
			return one(doctor.Good(fmt.Sprintf("The certificate for %s is valid for %d more days, and SGC renews it by itself", names, days)))
		}
	}
}

// standInEnvironment passes the stand-ins' addresses on to the part of a
// command that runs as the service user, so that it sees the same set-up as
// the service.
func standInEnvironment() []string {
	var env []string
	for _, name := range []string{zoneEndpointVariable, acmeDirectoryVariable, acmeTrialDirectoryVariable, acmeRootsVariable, acmeDNSVariable} {
		if value := os.Getenv(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}
