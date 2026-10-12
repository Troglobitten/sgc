package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/sshd"
)

// The units that change the SSH server's keys and settings
// (installer/sgc-ssh-*.service).
const (
	sshChangeUnit = "sgc-ssh-change.service"
	sshRevertUnit = "sgc-ssh-revert.service"
)

// --- The helper service's side ------------------------------------------------

// sshStatus is answered by the helper itself rather than by a unit: it only
// reads (the SSH server's own account of its settings, the list of accounts,
// the SSH server's log), and it is asked often while the owner watches for
// their key login to show up.
func sshStatus() (sshd.Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), programTimeout)
	defer cancel()
	return sshSystem().Status(ctx)
}

// startSSHChange hands the requested configuration to the unit that carries
// it out, and returns once it is in effect. The configuration has been
// decoded strictly by internal/helper; the unit checks every part of it
// again before using it.
func startSSHChange(cfg sshd.Config) error {
	// The unit stays active while a change waits for its proof; starting an
	// active unit would do nothing and lose this request.
	if runSystemctl("is-active", "--quiet", sshChangeUnit) == nil {
		return errors.New("another change to SSH is still waiting for a login with a key")
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	path := sshd.DefaultPaths().RequestFile
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("hand over the request: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("hand over the request: %w", err)
	}
	return startChangeUnit(sshChangeUnit)
}

// undoSSHChange stops the unit that is waiting, which makes it put the
// confirmed settings back, and runs the revert unit as well in case nothing
// was waiting any more although a change is unconfirmed.
func undoSSHChange() error {
	stopErr := runSystemctl("stop", sshChangeUnit)
	if err := runSystemctl("start", sshRevertUnit); err != nil {
		return err
	}
	return stopErr
}

// --- The units' side -----------------------------------------------------------

func sshSystem() *sshd.System {
	return &sshd.System{
		Paths:  sshd.DefaultPaths(),
		Window: sshd.ProofWindow,
		Run:    runProgram,
		Exists: programExists,
		Uptime: sshd.Uptime,
		Now:    time.Now,
		Sleep:  time.Sleep,
		Log:    slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// runSSH is "sgc-helper ssh <job>".
func runSSH(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sgc-helper ssh change|revert|restore|allow-passwords")
	}
	if os.Geteuid() != 0 {
		return errors.New("changing the SSH server's settings needs root")
	}
	system := sshSystem()

	switch args[0] {
	case "change":
		// Stays running while a change waits for a key login. systemd stops
		// it (SIGTERM) for "undo" and at shutdown.
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		return system.Change(ctx, notifyReady)
	case "revert":
		return system.Revert(context.Background(), sshd.ResultUndone, "the wait for a login with a key was interrupted")
	case "restore":
		return system.Restore(context.Background())
	case "allow-passwords":
		// For someone at the device itself ("sudo sgc ssh allow-passwords").
		// A change still waiting for its proof is undone first.
		if runSystemctl("is-active", "--quiet", sshChangeUnit) == nil {
			if err := runSystemctl("stop", sshChangeUnit); err != nil {
				return err
			}
		}
		return system.AllowPasswords(context.Background())
	default:
		return fmt.Errorf("unknown SSH job %q", args[0])
	}
}
