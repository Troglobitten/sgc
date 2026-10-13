package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/components"
	"github.com/Troglobitten/sgc/internal/dnscontrol"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

// newDNSControl is the web process's side of AdGuard Home, for the service
// and for `sgc dns`. The folder it downloads to is inside SGC's own.
func newDNSControl(db *sql.DB, stateDir string, helperClient *helper.Client, auditLog *audit.Log, log *slog.Logger) *dnscontrol.Service {
	paths := adguard.DefaultPaths()
	paths.SpoolDir = filepath.Join(stateDir, "components")
	return dnscontrol.New(dnscontrol.Config{
		DB:        db,
		Helper:    helperClient,
		Audit:     auditLog,
		Paths:     paths,
		Component: components.AdGuardHome,
		Arch:      runtime.GOARCH,
		HTTP:      &http.Client{Timeout: 10 * time.Minute},
		Log:       log,
	})
}

// dnsCommand is `sgc dns`: say whether DNS (AdGuard Home) is on, or switch it
// on or off from the machine itself. It does what the switch in SGC's page
// does, through the same code.
//
// The installer runs "sgc dns first-install": on a device nobody has decided
// about yet it switches DNS on, which downloads and installs AdGuard Home; on
// any other device it does nothing.
func dnsCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const usage = "usage: sgc dns [status|on|off]"
	flags := flag.NewFlagSet("sgc dns", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", defaultStateDir(), "folder for the database and certificate")
	helperSocket := flags.String("helper-socket", layout.HelperSocket, "socket of the root helper")
	// Internal: the part that runs as the service user.
	worker := flags.String("as-service-user", "", "")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "sgc: "+format+"\n", a...)
		return exitFailed
	}
	if *worker != "" {
		return dnsWorker(ctx, *worker, *stateDir, *helperSocket, stdout, stderr)
	}

	action := "status"
	if flags.NArg() > 0 {
		action = flags.Arg(0)
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	switch action {
	case "status":
		return dnsStatus(ctx, stdout)
	case "on", "off", "first-install":
	default:
		fmt.Fprintf(stderr, "sgc: unknown dns command %q\n%s\n", action, usage)
		return exitUsage
	}
	if os.Geteuid() != 0 {
		return fail("this command needs root. Run: sudo sgc dns %s", action)
	}

	// The database and the download belong to the service user; root touches
	// neither.
	work := func(task string) (dnsAnswer, int) {
		var answer dnsAnswer
		err := runAsServiceUser(ctx, []string{"dns", "--as-service-user", task, "--state-dir", *stateDir, "--helper-socket", *helperSocket}, nil, &answer, stderr)
		switch {
		case err == nil:
			return answer, exitOK
		case errors.Is(err, errWorkerFailed):
			// It has said why.
			return answer, exitFailed
		default:
			return answer, fail("%v", err)
		}
	}
	if action == "first-install" {
		answer, code := work("due")
		if code != exitOK || !answer.Due {
			return code
		}
		action = "on"
	}
	if action == "on" && !adguard.Installed(adguard.DefaultPaths()) {
		fmt.Fprintf(stdout, "Installing AdGuard Home %s, the DNS server (about a minute) ...\n", components.AdGuardHome.Version)
	}
	answer, code := work(action)
	if code == exitOK {
		fmt.Fprintln(stdout, answer.Message)
	}
	return code
}

// dnsStatus asks the machine itself, so it also answers when SGC does not.
func dnsStatus(ctx context.Context, stdout io.Writer) int {
	const how = "Switch it on in SGC's page, or with: sudo sgc dns on"
	paths := adguard.DefaultPaths()
	if !adguard.Installed(paths) {
		fmt.Fprintln(stdout, "DNS is off: AdGuard Home is not on this device. "+how)
		return exitOK
	}
	version := adguard.InstalledVersion(paths)
	active, _ := ask(ctx, "/usr/bin/systemctl", "is-active", adguard.ServiceUnit)
	enabled, _ := ask(ctx, "/usr/bin/systemctl", "is-enabled", adguard.ServiceUnit)
	switch {
	case active == "active":
		fmt.Fprintf(stdout, "DNS is on: AdGuard Home %s is running.\n", version)
	case enabled == "enabled":
		fmt.Fprintf(stdout, "DNS is switched on, but AdGuard Home %s is not running (%s). What is wrong: sudo sgc doctor\n", version, active)
	default:
		fmt.Fprintf(stdout, "DNS is off. AdGuard Home %s and its settings are on this device. %s\n", version, how)
	}
	return exitOK
}

// dnsAnswer is what the part running as the service user prints.
type dnsAnswer struct {
	// Due: this is a device the installer should switch DNS on for.
	Due     bool   `json:"due,omitempty"`
	Message string `json:"message,omitempty"`
}

// dnsWorker is the part of `sgc dns` that runs as the service user.
func dnsWorker(ctx context.Context, task, stateDir, helperSocket string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "sgc: %v\n", err)
		return exitFailed
	}
	syscall.Umask(0o077)
	db, err := store.Open(ctx, filepath.Join(stateDir, layout.DatabaseFile))
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	// What goes wrong comes back as an error in words for the owner; the
	// details the service would log have no reader here.
	control := newDNSControl(db, stateDir, helper.NewClient(helperSocket), audit.New(db), slog.New(slog.NewTextHandler(io.Discard, nil)))

	var answer dnsAnswer
	switch task {
	case "due":
		authService, err := auth.NewService(db)
		if err != nil {
			return fail(err)
		}
		setupRequired, err := authService.SetupRequired(ctx)
		if err != nil {
			return fail(err)
		}
		if answer.Due, err = control.FirstInstallDue(ctx, setupRequired); err != nil {
			return fail(err)
		}
	case "on":
		if err := control.SetEnabled(ctx, audit.ActorConsole, "", true); err != nil {
			return fail(err)
		}
		answer.Message = "DNS is on: AdGuard Home answers the name lookups of your home network on this device's address.\n" +
			"To use it, enter that address as the DNS server in your router, or on single devices."
	case "off":
		if err := control.SetEnabled(ctx, audit.ActorConsole, "", false); err != nil {
			return fail(err)
		}
		answer.Message = "DNS is off. AdGuard Home and its settings stay on this device.\n" +
			"Switch it on again in SGC's page, or with: sudo sgc dns on"
	default:
		return fail(fmt.Errorf("unknown task %q", task))
	}
	if err := json.NewEncoder(stdout).Encode(answer); err != nil {
		return fail(err)
	}
	return exitOK
}
