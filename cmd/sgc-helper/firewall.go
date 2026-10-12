package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/layout"
)

// The units that change the firewall (installer/sgc-firewall-*.service).
const (
	firewallChangeUnit  = "sgc-firewall-change.service"
	firewallConfirmUnit = "sgc-firewall-confirm.service"
	firewallRevertUnit  = "sgc-firewall-revert.service"
)

// How long one run of nft or sshd may take. They answer in milliseconds;
// this only stops a stuck one from holding everything up.
const programTimeout = 20 * time.Second

// --- The helper service's side: start the right unit ------------------------

// startFirewallChange hands the request to the unit that carries it out and
// returns once the new rules are in effect. request has been decoded
// strictly by internal/helper; it holds one yes-or-no value.
func startFirewallChange(request firewall.Request) error {
	// The unit stays active while a change waits for confirmation, and
	// starting an active unit does nothing: the new request would be lost
	// while the caller believes it took effect.
	if runSystemctl("is-active", "--quiet", firewallChangeUnit) == nil {
		return errors.New("another firewall change is still waiting for confirmation")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	// A folder only root can enter (RuntimeDirectory= in sgc-helper.service),
	// so what the unit reads is what was checked here.
	path := firewall.DefaultPaths().RequestFile
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("hand over the request: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("hand over the request: %w", err)
	}
	return startChangeUnit(firewallChangeUnit)
}

// startChangeUnit starts a unit that carries out a change and waits until
// the change is in effect. If the unit refuses the change, the caller is
// told, and the unit's record of why is in its folder under /run. systemd
// would also keep showing the unit as "failed" from then on; that mark is
// cleared, because a refused request is not something wrong with the device.
// A unit that fails later, while waiting, keeps its mark: that one is worth
// seeing ("sgc doctor" lists it).
func startChangeUnit(unit string) error {
	err := runSystemctl("start", unit)
	if err != nil {
		runSystemctl("reset-failed", unit)
		return errors.New("the change was refused or could not be put into effect")
	}
	return nil
}

func confirmFirewallChange() error {
	return runSystemctl("start", firewallConfirmUnit)
}

// undoFirewallChange stops the unit that is waiting for confirmation. Being
// stopped is its cue to put the confirmed rules back. The revert unit is
// run as well, in case nothing was waiting any more although a change is
// still unconfirmed: it does the same, and nothing if there is nothing to
// undo. The call returns when the confirmed rules are back.
func undoFirewallChange() error {
	stopErr := runSystemctl("stop", firewallChangeUnit)
	if err := runSystemctl("start", firewallRevertUnit); err != nil {
		return err
	}
	return stopErr
}

// --- The units' side: do the work -------------------------------------------

func firewallSystem() *firewall.System {
	return &firewall.System{
		Paths:   firewall.DefaultPaths(),
		WebPort: layout.WebPort,
		Window:  firewall.ConfirmWindow,
		Run:     runProgram,
		Exists:  programExists,
		Uptime:  firewall.Uptime,
		Now:     time.Now,
		Log:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// runFirewall is "sgc-helper firewall <job>".
func runFirewall(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sgc-helper firewall change|confirm|revert|off")
	}
	if os.Geteuid() != 0 {
		return errors.New("changing the firewall needs root")
	}
	system := firewallSystem()

	switch args[0] {
	case "change":
		// Stays running while the change waits for confirmation. systemd
		// stops it (SIGTERM) for "undo now" and at shutdown.
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		return system.Change(ctx, notifyReady)
	case "confirm":
		return system.Confirm(context.Background())
	case "revert":
		// Run by systemd after the "change" process has ended, however it
		// ended (ExecStopPost). Normally there is nothing left to undo.
		return system.Revert(context.Background(), firewall.ResultUndone, "the wait for confirmation was interrupted")
	case "off":
		return turnFirewallOff(system)
	default:
		return fmt.Errorf("unknown firewall job %q", args[0])
	}
}

// turnFirewallOff is for someone at the machine itself ("sudo sgc firewall
// off"): no confirmation period, because there is no browser to confirm from.
func turnFirewallOff(system *firewall.System) error {
	// A change still waiting for confirmation is undone first.
	if runSystemctl("is-active", "--quiet", firewallChangeUnit) == nil {
		if err := runSystemctl("stop", firewallChangeUnit); err != nil {
			return err
		}
	}
	// Off also clears away a change that is unconfirmed with nothing waiting.
	return system.Off(context.Background())
}

func runProgram(ctx context.Context, program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, programTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	// A fixed environment, and messages in English whatever the system's language.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return cmd.CombinedOutput()
}

func programExists(program string) bool {
	info, err := os.Stat(program)
	return err == nil && info.Mode().IsRegular()
}

// notifyReady tells systemd that the unit has finished starting, which for
// the change unit means: the new rules are in effect (Type=notify). Whoever
// started the unit is waiting for exactly that.
//
// If the message does not get through, systemd gives up on the start after
// a while and stops the unit, which undoes the change. That is the safe
// direction, so a failure here is only logged.
func notifyReady() {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return // not started by systemd
	}
	if address[0] == '@' {
		// Linux "abstract" socket names are written with @ and start with a zero byte.
		address = "\x00" + address[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sgc-helper: tell systemd the change is in effect:", err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		fmt.Fprintln(os.Stderr, "sgc-helper: tell systemd the change is in effect:", err)
	}
}
