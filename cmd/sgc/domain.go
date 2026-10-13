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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/zone"
)

// Environment variable naming another address for Zone.eu's API. The tests
// set it, so that they never talk to the real Zone.eu. Only root can set the
// service's environment, and SGC says in its log when it is in use: the API
// key is sent to whatever address this names.
const zoneEndpointVariable = "SGC_ZONE_API"

// newDomainControl keeps the owner's domain and Zone.eu account, and asks
// Zone.eu about them.
func newDomainControl(db *sql.DB, auditLog *audit.Log, log *slog.Logger) *domaincontrol.Service {
	endpoint := zone.DefaultEndpoint
	if address := os.Getenv(zoneEndpointVariable); address != "" {
		endpoint = address
		log.Warn("talking to a non-default address instead of Zone.eu", "address", address)
	}
	return domaincontrol.New(domaincontrol.Config{
		DB:        db,
		Audit:     auditLog,
		Log:       log,
		Endpoint:  endpoint,
		HTTP:      &http.Client{Timeout: 20 * time.Second},
		UserAgent: "sgc/" + sgc.Version(),
		Now:       time.Now,
	})
}

// checkDomain reports how SGC's last question to Zone.eu ended. It does not
// ask Zone.eu itself: the doctor runs as root, and the key stays with the
// service. What it shows is therefore as old as that last question.
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
		switch {
		case !status.Configured:
			return one(doctor.Good("No domain is set up yet (that is done on SGC's System page, under Domain)"))
		case status.CheckedAt == nil:
			return one(doctor.Good("The domain is " + status.Domain + "; SGC has not asked Zone.eu about it yet"))
		case status.OK:
			return one(doctor.Good("Zone.eu accepted the saved API key for " + status.Domain + " when SGC last asked"))
		default:
			since := ""
			if status.FailingSince != nil {
				since = " (since " + status.FailingSince.Local().Format("2 January 15:04") + ")"
			}
			return one(doctor.Bad("The domain "+status.Domain+": "+status.Problem+since,
				"If the API key was replaced or withdrawn at Zone.eu: make a new one in your ZoneID account there, and enter it on SGC's System page, under Domain.\n"+
					"If this device does not reach the internet, that is the thing to put right first.\n"+
					"SGC asks Zone.eu again every hour; \"Ask Zone.eu now\" on that page does it at once."))
		}
	}
}

// doctorWorker is the part of `sgc doctor` that runs as the service user.
func doctorWorker(ctx context.Context, task, stateDir string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitFailed
	}
	if task != "domain" {
		return fail(fmt.Errorf("unknown task %q", task))
	}
	syscall.Umask(0o077)
	db, err := store.Open(ctx, filepath.Join(stateDir, layout.DatabaseFile))
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	status, err := newDomainControl(db, audit.New(db), slog.New(slog.NewTextHandler(io.Discard, nil))).Status(ctx)
	if err != nil {
		return fail(err)
	}
	if err := json.NewEncoder(stdout).Encode(status); err != nil {
		return fail(err)
	}
	return exitOK
}
