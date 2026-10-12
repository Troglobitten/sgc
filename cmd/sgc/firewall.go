package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/fwcontrol"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

// firewallCommand is `sgc firewall`: show the firewall's state, or switch it
// off from the machine itself.
//
// Switching it on is only offered in the web interface, because that is
// where a change can be confirmed over a new connection, which is what
// proves the owner is not locked out. Switching it off needs no such proof,
// and is the way back in for someone who can only reach the machine with a
// screen and keyboard.
func firewallCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sgc firewall", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", defaultStateDir(), "folder for the database and certificate")
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
		return firewallWorker(ctx, *worker, *stateDir, stderr)
	}

	action := "status"
	if flags.NArg() > 0 {
		action = flags.Arg(0)
	}
	switch {
	case flags.NArg() > 1:
		fmt.Fprintln(stderr, "usage: sgc firewall [status|off]")
		return exitUsage
	case action == "status":
		return firewallStatus(stdout, stderr)
	case action == "off":
		if os.Geteuid() != 0 {
			return fail("this command needs root. Run: sudo sgc firewall off")
		}
		if err := runHelperProgram(ctx, "firewall", "off"); err != nil {
			return fail("the firewall could not be switched off: %v", err)
		}
		// The database belongs to the service user; root does not touch it.
		if err := runAsServiceUser(ctx, []string{"firewall", "--as-service-user", "record-off", "--state-dir", *stateDir}, nil, nil, stderr); err != nil {
			fmt.Fprintln(stderr, "sgc: the firewall is off, but that could not be written into SGC's history:", err)
		}
		fmt.Fprintln(stdout, "The firewall is off. It can be switched on again in SGC's page.")
		return exitOK
	default:
		fmt.Fprintf(stderr, "sgc: unknown firewall command %q\nusage: sgc firewall [status|off]\n", action)
		return exitUsage
	}
}

func firewallStatus(stdout, stderr io.Writer) int {
	state, err := firewall.ReadState(firewall.DefaultPaths())
	if err != nil {
		fmt.Fprintln(stderr, "sgc: the firewall's state cannot be read:", err)
		return exitFailed
	}
	describe := func(cfg firewall.Config) string {
		if !cfg.Enabled {
			return "off"
		}
		ports := make([]string, len(cfg.SSHPorts))
		for i, port := range cfg.SSHPorts {
			ports[i] = strconv.Itoa(port)
		}
		letIn := fmt.Sprintf("SGC's page (port %d)", cfg.WebPort)
		if len(ports) > 0 {
			letIn += " and SSH (port " + strings.Join(ports, ", ") + ")"
		}
		return "on: from your home network, " + letIn + " can be reached; everything else is refused"
	}

	switch {
	case state.Pending != nil:
		left := 0
		if uptime, err := firewall.Uptime(); err == nil {
			left = state.Pending.SecondsLeft(uptime)
		}
		fmt.Fprintf(stdout, "A change is in effect and waiting for confirmation in SGC's page (%d seconds left).\n", left)
		fmt.Fprintf(stdout, "Right now the firewall is %s.\n", describe(state.Pending.Config))
		fmt.Fprintln(stdout, "Without confirmation it goes back to what it was.")
	case state.Confirmed != nil:
		fmt.Fprintf(stdout, "The firewall is %s.\n", describe(*state.Confirmed))
	default:
		fmt.Fprintln(stdout, "The firewall is off.")
	}
	return exitOK
}

// firewallWorker is the part of `sgc firewall` that runs as the service user.
func firewallWorker(ctx context.Context, task, stateDir string, stderr io.Writer) int {
	if task != "record-off" {
		fmt.Fprintf(stderr, "sgc: unknown task %q\n", task)
		return exitFailed
	}
	syscall.Umask(0o077)
	db, err := store.Open(ctx, filepath.Join(stateDir, layout.DatabaseFile))
	if err != nil {
		fmt.Fprintf(stderr, "sgc: %v\n", err)
		return exitFailed
	}
	defer db.Close()
	if err := fwcontrol.RecordSwitchedOffAtConsole(ctx, db, audit.New(db)); err != nil {
		fmt.Fprintf(stderr, "sgc: %v\n", err)
		return exitFailed
	}
	return exitOK
}

// consoleFirewall is the firewall as seen by a command run as root at the
// machine: it can ask nftables directly.
func consoleFirewall() *firewall.System {
	return &firewall.System{
		Paths:   firewall.DefaultPaths(),
		WebPort: layout.WebPort,
		Window:  firewall.ConfirmWindow,
		Run: func(ctx context.Context, program string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, program, args...)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			return cmd.CombinedOutput()
		},
		Exists: func(program string) bool { _, err := os.Stat(program); return err == nil },
		Uptime: firewall.Uptime,
		Now:    time.Now,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}
