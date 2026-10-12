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
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/sshcontrol"
	"github.com/Troglobitten/sgc/internal/sshd"
	"github.com/Troglobitten/sgc/internal/store"
)

// sshCommand is `sgc ssh`: show what SGC has set up for SSH, or allow
// password logins again from the device itself.
//
// Switching to "keys only" is only offered in the web interface, where the
// owner is walked through proving that a key works. Allowing passwords again
// takes no proof (it only adds a way in), and is what someone does who sits
// at the device because their key no longer works.
func sshCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sgc ssh", flag.ContinueOnError)
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
	const usage = "usage: sgc ssh [status|allow-passwords]"

	if *worker != "" {
		return sshWorker(ctx, *worker, *stateDir, stderr)
	}
	action := "status"
	if flags.NArg() > 0 {
		action = flags.Arg(0)
	}
	switch {
	case flags.NArg() > 1:
		fmt.Fprintln(stderr, usage)
		return exitUsage
	case action == "status":
		return sshStatus(stdout, stderr)
	case action == "allow-passwords":
		if os.Geteuid() != 0 {
			return fail("this command needs root. Run: sudo sgc ssh allow-passwords")
		}
		if err := runHelperProgram(ctx, "ssh", "allow-passwords"); err != nil {
			return fail("password logins could not be allowed again: %v", err)
		}
		if err := runAsServiceUser(ctx, []string{"ssh", "--as-service-user", "record-passwords-allowed", "--state-dir", *stateDir}, nil, nil, stderr); err != nil {
			fmt.Fprintln(stderr, "sgc: password logins are allowed again, but that could not be written into SGC's history:", err)
		}
		fmt.Fprintln(stdout, "Password logins over SSH are allowed again, as far as this device's own settings allow them.")
		fmt.Fprintln(stdout, "The keys added in SGC's page still work. \"Keys only\" can be switched on again in SGC's page.")
		return exitOK
	default:
		fmt.Fprintf(stderr, "sgc: unknown ssh command %q\n%s\n", action, usage)
		return exitUsage
	}
}

func sshStatus(stdout, stderr io.Writer) int {
	state, err := sshd.ReadState(sshd.DefaultPaths())
	if err != nil {
		fmt.Fprintln(stderr, "sgc: the SSH state cannot be read:", err)
		return exitFailed
	}
	describe := func(cfg sshd.Config) {
		if cfg.KeysOnly {
			fmt.Fprintln(stdout, "SSH accepts keys only: no passwords, and nobody logs in as root.")
		} else {
			fmt.Fprintln(stdout, "SGC has not restricted SSH: this device's own settings decide whether passwords are accepted.")
		}
		if n := len(cfg.Keys); n > 0 && cfg.Account != "" {
			fmt.Fprintf(stdout, "Keys added in SGC's page for the account %s: %d.\n", cfg.Account, n)
			for _, key := range cfg.Keys {
				fmt.Fprintf(stdout, "  %s %s\n", key.Kind(), key.Fingerprint)
			}
		} else {
			fmt.Fprintln(stdout, "No keys have been added in SGC's page.")
		}
	}
	if pending := state.Pending; pending != nil && pending.NeedsProof {
		left := 0
		if uptime, err := sshd.Uptime(); err == nil {
			left = pending.SecondsLeft(uptime)
		}
		fmt.Fprintf(stdout, "A change is in effect and waits for a login with a key (%d seconds left). Right now:\n", left)
		describe(pending.Config)
		fmt.Fprintln(stdout, "Without such a login it goes back to what it was.")
		return exitOK
	}
	describe(state.Confirmed)
	return exitOK
}

// runHelperProgram runs the root helper program, which sits next to this
// one and carries the knowledge of how, with fixed arguments.
func runHelperProgram(ctx context.Context, args ...string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, filepath.Join(filepath.Dir(self), "sgc-helper"), args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// sshWorker is the part of `sgc ssh` that runs as the service user.
func sshWorker(ctx context.Context, task, stateDir string, stderr io.Writer) int {
	if task != "record-passwords-allowed" {
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
	if err := sshcontrol.RecordPasswordsAllowedAtConsole(ctx, db, audit.New(db)); err != nil {
		fmt.Fprintf(stderr, "sgc: %v\n", err)
		return exitFailed
	}
	return exitOK
}

// consoleSSH is the SSH server as seen by a command run as root at the
// device: it can ask the server and read its log directly.
func consoleSSH() *sshd.System {
	return &sshd.System{
		Paths:  sshd.DefaultPaths(),
		Window: sshd.ProofWindow,
		Run: func(ctx context.Context, program string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, program, args...)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			return cmd.CombinedOutput()
		},
		Exists: func(program string) bool { _, err := os.Stat(program); return err == nil },
		Uptime: sshd.Uptime,
		Now:    time.Now,
		Sleep:  time.Sleep,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}
