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
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/log2ram"
	"github.com/Troglobitten/sgc/internal/logcontrol"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/proxycontrol"
	"github.com/Troglobitten/sgc/internal/public"
	"github.com/Troglobitten/sgc/internal/store"
)

// newLogControl is the web process's side of logs in memory (log2ram), for
// the service and for the installer's step.
func newLogControl(db *sql.DB, helperClient *helper.Client, auditLog *audit.Log, log *slog.Logger) *logcontrol.Service {
	return logcontrol.New(logcontrol.Config{DB: db, Helper: helperClient, Audit: auditLog, Log: log})
}

// firstInstallCommand is `sgc first-install`, which the installer runs once
// SGC itself is up. It brings the parts of SGC that are programs of their
// own, each through the same code as the switch in SGC's page:
//
//   - log2ram (logs in memory, for a device on an SD card), from Debian:
//     installed and left switched off;
//   - Traefik (the proxy): installed and left switched off;
//   - fail2ban (for services made public), from Debian: installed with
//     SGC's settings first (Debian's SSH jail off) and left switched off;
//   - AdGuard Home (DNS): installed and switched on.
//
// It only does that on a device nobody has decided about yet: one without an
// admin account. Run again on a device that is in use, it does nothing.
//
// A part that cannot be installed now is said, and is no reason to fail: SGC
// is installed, and switching the part on later installs it.
func firstInstallCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sgc first-install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", defaultStateDir(), "folder for the database and certificate")
	helperSocket := flags.String("helper-socket", layout.HelperSocket, "socket of the root helper")
	// Internal: the part that runs as the service user.
	worker := flags.String("as-service-user", "", "")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *worker != "" {
		return firstInstallWorker(ctx, *worker, *stateDir, *helperSocket, stdout, stderr)
	}
	if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: sgc first-install")
		return exitUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "sgc: this command needs root. It is run by SGC's installer.")
		return exitFailed
	}

	// The database and every download belong to the service user; root
	// touches neither.
	work := func(command, task string, answer any) error {
		return runAsServiceUser(ctx, []string{command, "--as-service-user", task, "--state-dir", *stateDir, "--helper-socket", *helperSocket}, nil, answer, stderr)
	}
	var due firstInstallAnswer
	if err := work("first-install", "due", &due); err != nil {
		if !errors.Is(err, errWorkerFailed) {
			fmt.Fprintf(stderr, "sgc: %v\n", err)
		}
		return exitFailed
	}
	if !due.NewDevice {
		return exitOK
	}

	if _, err := os.Stat(log2ram.DefaultPaths().Program); err != nil {
		fmt.Fprintln(stdout, "Installing log2ram from Debian (logs in memory, for a device on an SD card) ...")
		var answer firstInstallAnswer
		if err := work("first-install", "log2ram", &answer); err != nil {
			fmt.Fprintln(stdout, "log2ram could not be installed just now; the reason is above. Switching \"Logs in memory\" on later, on SGC's System page, installs it.")
		} else {
			fmt.Fprintln(stdout, answer.Message)
		}
	}
	if !proxy.Installed(proxy.DefaultPaths()) {
		fmt.Fprintf(stdout, "Installing Traefik %s, the proxy (switched off until you switch it on) ...\n", components.Traefik.Version)
		var answer firstInstallAnswer
		if err := work("first-install", "proxy", &answer); err != nil {
			fmt.Fprintln(stdout, "Traefik could not be installed just now; the reason is above. Switching the proxy on, on SGC's Services page, installs it.")
		} else {
			fmt.Fprintln(stdout, answer.Message)
		}
	}
	if !public.Fail2banInstalled() {
		fmt.Fprintln(stdout, "Installing fail2ban from Debian (for services you make public; switched off until you switch it on) ...")
		var answer firstInstallAnswer
		if err := work("first-install", "fail2ban", &answer); err != nil {
			fmt.Fprintln(stdout, "fail2ban could not be installed just now; the reason is above. Switching it on, on SGC's System page (Internet), installs it.")
		} else {
			fmt.Fprintln(stdout, answer.Message)
		}
	}
	if due.DNS {
		if !adguard.Installed(adguard.DefaultPaths()) {
			fmt.Fprintf(stdout, "Installing AdGuard Home %s, the DNS server (about a minute) ...\n", components.AdGuardHome.Version)
		}
		var answer dnsAnswer
		if err := work("dns", "on", &answer); err != nil {
			fmt.Fprintln(stdout, "AdGuard Home (DNS) could not be installed just now; the reason is above. Switch DNS on later on SGC's System page, or with: sudo sgc dns on")
		} else {
			fmt.Fprintln(stdout, answer.Message)
		}
	}
	return exitOK
}

// firstInstallAnswer is what the part running as the service user prints.
type firstInstallAnswer struct {
	// NewDevice: nobody has set this device up yet. DNS: nor chosen about DNS.
	NewDevice bool   `json:"newDevice,omitempty"`
	DNS       bool   `json:"dns,omitempty"`
	Message   string `json:"message,omitempty"`
}

// firstInstallWorker is the part of `sgc first-install` that runs as the
// service user.
func firstInstallWorker(ctx context.Context, task, stateDir, helperSocket string, stdout, stderr io.Writer) int {
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
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	helperClient := helper.NewClient(helperSocket)

	var answer firstInstallAnswer
	switch task {
	case "due":
		authService, err := auth.NewService(db)
		if err != nil {
			return fail(err)
		}
		if answer.NewDevice, err = authService.SetupRequired(ctx); err != nil {
			return fail(err)
		}
		dns := newDNSControl(db, stateDir, helperClient, audit.New(db), quiet)
		if answer.DNS, err = dns.FirstInstallDue(ctx, answer.NewDevice); err != nil {
			return fail(err)
		}
	case "log2ram":
		if _, err := newLogControl(db, helperClient, audit.New(db), quiet).EnsureInstalled(ctx); err != nil {
			return fail(err)
		}
		answer.Message = "log2ram is installed and switched off. If this device runs from an SD card, switch on \"Logs in memory\" on SGC's System page."
	case "fail2ban":
		if err := helperClient.InstallPackages(ctx, helper.PackagesFail2ban); err != nil {
			return fail(err)
		}
		answer.Message = "fail2ban is installed and switched off. It is for services you make reachable from the internet (System, Internet)."
	case "proxy":
		control := proxycontrol.New(proxycontrol.Config{
			DB: db, Helper: helperClient, Audit: audit.New(db), HTTP: &http.Client{Timeout: 10 * time.Minute},
			SpoolDir: filepath.Join(stateDir, "components"), Arch: runtime.GOARCH, Log: quiet,
			Build: func(context.Context) (proxy.Config, error) { return proxy.Config{}, nil },
		})
		if err := control.EnsureInstalled(ctx); err != nil {
			return fail(err)
		}
		answer.Message = "Traefik is installed and switched off. Once your domain and certificate are set up, switch the proxy on on SGC's Services page."
	default:
		return fail(fmt.Errorf("unknown task %q", task))
	}
	if err := json.NewEncoder(stdout).Encode(answer); err != nil {
		return fail(err)
	}
	return exitOK
}
