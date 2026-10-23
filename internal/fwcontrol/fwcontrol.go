// Package fwcontrol is the web process's side of the firewall.
//
// It cannot touch the firewall itself; nothing in the web process can. It
// reads the files in which the root side keeps the firewall's state, asks
// the root helper for changes, remembers what the owner wants in the
// database (which is what an export carries), and writes the history.
//
// The mechanics of a change, and why it cannot lock the owner out, are in
// internal/firewall.
package fwcontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// SettingEnabled holds what the owner last confirmed: "true" or "false".
	// It travels with an export. The rules themselves do not; on a restored
	// machine the owner switches the firewall on again, with the same
	// confirmation step, because it is a different machine in possibly a
	// different network.
	SettingEnabled = "firewall.enabled"
	// SettingOpenChange remembers a change that has been started and whose
	// end is not in the history yet. Bookkeeping of one installation; it is
	// left out of exports (internal/backup/tables.go).
	SettingOpenChange = "firewall.open_change"
)

// overdueGrace is how long past its deadline a change may still be in effect
// before this package steps in. The root side undoes a change at the
// deadline; this only matters if that failed.
const overdueGrace = 15 * time.Second

// States of the firewall as the interface shows them.
const (
	StateOff     = "off"
	StateOn      = "on"
	StatePending = "pending" // a change is in effect and waits for confirmation
)

var (
	ErrChangePending = errors.New("a firewall change is still waiting for confirmation")
	ErrNoChange      = errors.New("the firewall is already in that state")
	// ErrTooLate: the confirmation arrived after the change had been undone.
	ErrTooLate = errors.New("the change was not confirmed in time and has been undone")
)

// ChangeError is a failed change with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

// Helper is what this package asks the root helper to do.
type Helper interface {
	InstallPackages(ctx context.Context, feature string) error
	FirewallChange(ctx context.Context, request firewall.Request) error
	FirewallConfirm(ctx context.Context) error
	FirewallUndo(ctx context.Context) error
}

type Config struct {
	DB     *sql.DB
	Helper Helper
	Audit  *audit.Log
	Paths  firewall.Paths
	// Installed reports whether the firewall software (nftables) is there.
	Installed func() bool
	// Expected reports what the rules should let in besides SGC's page and
	// SSH, given what is installed and switched on now (the root side
	// decides the same from the same facts). nil: nothing besides.
	Expected func(ctx context.Context) Expected
	// Uptime is the clock a pending change's deadline is measured on.
	Uptime func() (float64, error)
	Log    *slog.Logger
}

type Service struct {
	cfg Config

	// One change, confirmation or undo at a time.
	mu sync.Mutex
	// Wakes Run up when a change has been started.
	started chan struct{}
}

func New(cfg Config) *Service {
	return &Service{cfg: cfg, started: make(chan struct{}, 1)}
}

type PendingStatus struct {
	// Enabled is what the pending change switches the firewall to.
	Enabled     bool `json:"enabled"`
	SecondsLeft int  `json:"secondsLeft"`
}

// Expected is what the rules should let in, as the parts of SGC are now.
type Expected struct {
	DNS        bool
	Proxy      bool
	ProxyPorts []string
	VPNPort    int
}

type Status struct {
	State string `json:"state"`
	// SoftwareInstalled is false on a clean Debian: nftables is installed the
	// first time the firewall is switched on.
	SoftwareInstalled bool `json:"softwareInstalled"`
	// Wanted is what the owner last confirmed, here or on the machine an
	// export came from. Wanted but off means: restored, not switched on yet.
	Wanted  bool           `json:"wanted"`
	Pending *PendingStatus `json:"pending"`
	// What is let in from inside while the firewall is on.
	// The fields older SGCs had come first, in their order.
	SSHPorts   []int    `json:"sshPorts"`
	DNS        bool     `json:"dns"`
	WebPort    int      `json:"webPort"`
	Proxy      bool     `json:"proxy"`
	ProxyPorts []string `json:"proxyPorts"`
	VPNPort    int      `json:"vpnPort"`
	// Behind lists, in words, what is switched on but not let in by the
	// rules in effect (they were made before). Bringing them up to date is
	// an ordinary change (Change with again).
	Behind []string `json:"behind"`
	// ConfirmSeconds is how long a change waits for its confirmation.
	ConfirmSeconds int `json:"confirmSeconds"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	state, err := firewall.ReadState(s.cfg.Paths)
	if err != nil {
		return Status{}, fmt.Errorf("read the firewall's state: %w", err)
	}
	wanted, _, err := store.Setting(ctx, s.cfg.DB, SettingEnabled)
	if err != nil {
		return Status{}, err
	}
	status := Status{
		State:             StateOff,
		SoftwareInstalled: s.cfg.Installed(),
		Wanted:            wanted == "true",
		SSHPorts:          []int{},
		ProxyPorts:        []string{},
		Behind:            []string{},
		ConfirmSeconds:    int(firewall.ConfirmWindow.Seconds()),
	}
	// What is in effect right now: the pending rules if there are any.
	effective := state.Confirmed
	if state.Pending != nil {
		effective = &state.Pending.Config
		uptime, err := s.cfg.Uptime()
		if err != nil {
			return Status{}, err
		}
		status.State = StatePending
		status.Pending = &PendingStatus{
			Enabled:     state.Pending.Config.Enabled,
			SecondsLeft: state.Pending.SecondsLeft(uptime),
		}
	} else if state.Confirmed != nil && state.Confirmed.Enabled {
		status.State = StateOn
	}
	if effective != nil && effective.Enabled {
		status.SSHPorts = append(status.SSHPorts, effective.SSHPorts...)
		status.DNS = effective.DNS
		status.Proxy, status.VPNPort = effective.Proxy, effective.VPNPort
		status.ProxyPorts = append(status.ProxyPorts, effective.ProxyPorts...)
		status.WebPort = effective.WebPort
	}
	if status.State == StateOn && s.cfg.Expected != nil {
		status.Behind = behind(s.cfg.Expected(ctx), *effective)
	}
	return status, nil
}

// behind says what the expected parts need that the rules in effect lack.
// Something the rules let in that is no longer needed is not listed: it is
// tidied up at the next change, and lets nothing in that answers.
func behind(want Expected, have firewall.Config) []string {
	out := []string{}
	if want.DNS && !have.DNS {
		out = append(out, "DNS")
	}
	if want.Proxy && !have.Proxy {
		out = append(out, "the proxy (ports 80 and 443)")
	}
	if want.Proxy {
		for _, port := range want.ProxyPorts {
			if !slices.Contains(have.ProxyPorts, port) {
				out = append(out, "the proxied service on port "+port)
			}
		}
	}
	if want.VPNPort != 0 && have.VPNPort != want.VPNPort {
		out = append(out, fmt.Sprintf("the VPN (port %d/udp, from the internet)", want.VPNPort))
	}
	return out
}

// openChange is what SettingOpenChange holds.
type openChange struct {
	ID      int64  `json:"id"`
	Enabled bool   `json:"enabled"`
	Actor   string `json:"actor"`
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

// Change switches the firewall on or off, pending confirmation. It installs
// the firewall software first if the machine does not have it, which can
// take a few minutes.
//
// again asks for the rules to be made afresh although the firewall is
// already on. That is how a firewall switched on before AdGuard Home was
// installed comes to let DNS in: the root side makes the rules from what is
// on the device now, and the owner confirms them like any other change.
func (s *Service) Change(ctx context.Context, actor, remoteAddr string, enabled, again bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A change whose end was never written down is written down first, so
	// the history stays in order.
	s.settle(ctx)

	before, err := firewall.ReadState(s.cfg.Paths)
	if err != nil {
		return fmt.Errorf("read the firewall's state: %w", err)
	}
	if before.Pending != nil {
		return ErrChangePending
	}
	if on := before.Confirmed != nil && before.Confirmed.Enabled; on == enabled && !(again && on) {
		return ErrNoChange
	}

	if !s.cfg.Installed() {
		if err := s.cfg.Helper.InstallPackages(ctx, helper.PackagesFirewall); err != nil {
			s.cfg.Log.Error("install the firewall software", "error", err)
			return &ChangeError{"The firewall software (nftables) could not be installed from Debian. " +
				"Check that this device can reach the internet, then try again. Nothing was changed."}
		}
		s.record(ctx, audit.ActorSystem, audit.ActionPackagesInstalled, "nftables, from Debian, for the firewall", "")
	}

	if err := s.cfg.Helper.FirewallChange(ctx, firewall.Request{Enabled: enabled}); err != nil {
		s.cfg.Log.Error("change the firewall", "enabled", enabled, "error", err)
		message := "The firewall could not be switched " + onOff(enabled) + ". Nothing was changed."
		// The root side says why, in the record of how its last change ended.
		if after, readErr := firewall.ReadState(s.cfg.Paths); readErr == nil && after.Last != nil &&
			after.Last.Result == firewall.ResultFailed && (before.Last == nil || after.Last.ID != before.Last.ID) {
			message = "The firewall could not be switched " + onOff(enabled) + ": " + after.Last.Message + ". Nothing was changed."
		}
		s.record(ctx, actor, audit.ActionFirewallChangeFailed, "switching "+onOff(enabled), remoteAddr)
		return &ChangeError{message}
	}

	s.record(ctx, actor, audit.ActionFirewallChangeStarted, "switching "+onOff(enabled), remoteAddr)
	after, err := firewall.ReadState(s.cfg.Paths)
	if err != nil || after.Pending == nil {
		// In effect and already gone again; whatever happened is in the
		// root side's record and will be settled from there.
		return nil
	}
	open, _ := json.Marshal(openChange{ID: after.Pending.ID, Enabled: enabled, Actor: actor})
	if err := store.SetSetting(ctx, s.cfg.DB, SettingOpenChange, string(open)); err != nil {
		s.cfg.Log.Error("remember the started firewall change", "error", err)
	}
	select {
	case s.started <- struct{}{}:
	default:
	}
	return nil
}

// Confirm keeps the pending change.
func (s *Service) Confirm(ctx context.Context, actor, remoteAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := firewall.ReadState(s.cfg.Paths)
	if err != nil {
		return fmt.Errorf("read the firewall's state: %w", err)
	}
	if state.Pending == nil {
		s.settle(ctx)
		return ErrTooLate
	}
	if err := s.cfg.Helper.FirewallConfirm(ctx); err != nil {
		s.cfg.Log.Error("confirm the firewall change", "error", err)
		// Most likely the time ran out between the two lines above.
		s.settle(ctx)
		return ErrTooLate
	}
	s.finish(ctx, state.Pending.Config.Enabled, actor, remoteAddr)
	return nil
}

// Undo goes back to the confirmed rules now, without waiting.
func (s *Service) Undo(ctx context.Context, actor, remoteAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := firewall.ReadState(s.cfg.Paths)
	if err != nil {
		return fmt.Errorf("read the firewall's state: %w", err)
	}
	if state.Pending == nil {
		s.settle(ctx)
		return nil // already undone, which is what was asked for
	}
	if err := s.cfg.Helper.FirewallUndo(ctx); err != nil {
		// Not undone on request, but it will be when the time runs out.
		return fmt.Errorf("undo the firewall change: %w", err)
	}
	s.record(ctx, actor, audit.ActionFirewallChangeUndone, "switching "+onOff(state.Pending.Config.Enabled), remoteAddr)
	s.clearOpenChange(ctx)
	return nil
}

// finish records a confirmed change: in the setting an export carries, and
// in the history.
func (s *Service) finish(ctx context.Context, enabled bool, actor, remoteAddr string) {
	// Written even if the request that confirmed has gone away meanwhile:
	// the change itself is already confirmed on the root side.
	ctx = context.WithoutCancel(ctx)
	if err := store.SetSetting(ctx, s.cfg.DB, SettingEnabled, strconv.FormatBool(enabled)); err != nil {
		s.cfg.Log.Error("save the firewall setting", "error", err)
	}
	s.record(ctx, actor, audit.ActionFirewallChangeConfirmed, "firewall switched "+onOff(enabled), remoteAddr)
	s.clearOpenChange(ctx)
}

// RecordSwitchedOffAtConsole writes down that the firewall was switched off
// with "sgc firewall off" at the machine itself: in the setting, so the
// interface does not go on calling it wanted, and in the history.
func RecordSwitchedOffAtConsole(ctx context.Context, db *sql.DB, auditLog *audit.Log) error {
	if err := store.SetSetting(ctx, db, SettingEnabled, "false"); err != nil {
		return err
	}
	// Whatever change was waiting has been cleared away with it.
	if err := store.SetSetting(ctx, db, SettingOpenChange, ""); err != nil {
		return err
	}
	return auditLog.Record(ctx, audit.ActorConsole, audit.ActionFirewallChangeConfirmed, "firewall switched off", "")
}

// Run writes into the history how changes ended that nobody ended by hand:
// those undone because the confirmation never came. It also keeps an eye on
// the root side's promise to undo an unconfirmed change (see rescue). It
// runs until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	// Once at the start: SGC may have been restarted, or the whole machine,
	// while a change was waiting.
	watching := true
	for {
		s.mu.Lock()
		if s.rescue(ctx) {
			watching = true
		}
		if watching {
			watching = s.settle(ctx)
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-s.started:
			watching = true
		case <-ticker.C:
		}
	}
}

// rescue is the third and last safety net. An unconfirmed change is undone
// by the process that waits for its confirmation; failing that, by systemd,
// in two independent ways (installer/sgc-firewall-change.service). Should a
// change still be in effect well past its deadline, all of that has failed,
// and this asks for it to be undone once more. It reports whether it did.
// The caller holds the lock.
func (s *Service) rescue(ctx context.Context) bool {
	state, err := firewall.ReadState(s.cfg.Paths)
	if err != nil || state.Pending == nil {
		return false
	}
	uptime, err := s.cfg.Uptime()
	if err != nil || uptime < state.Pending.DeadlineUptime+overdueGrace.Seconds() {
		return false
	}
	s.cfg.Log.Error("a firewall change is past its confirmation time and still in effect; undoing it", "id", state.Pending.ID)
	if err := s.cfg.Helper.FirewallUndo(ctx); err != nil {
		s.cfg.Log.Error("undo the overdue firewall change", "error", err)
		return false
	}
	return true
}

// settle looks at the change remembered as open. If it has ended, the end is
// written into the history. It reports whether a change is still open. The
// caller holds the lock.
func (s *Service) settle(ctx context.Context) (stillOpen bool) {
	raw, found, err := store.Setting(ctx, s.cfg.DB, SettingOpenChange)
	if err != nil {
		if ctx.Err() == nil {
			s.cfg.Log.Error("read the open firewall change", "error", err)
		}
		return true // try again later
	}
	if !found || raw == "" {
		return false
	}
	var open openChange
	if err := json.Unmarshal([]byte(raw), &open); err != nil {
		s.clearOpenChange(ctx)
		return false
	}
	state, err := firewall.ReadState(s.cfg.Paths)
	if err != nil {
		s.cfg.Log.Error("read the firewall's state", "error", err)
		return true
	}
	if state.Pending != nil && state.Pending.ID == open.ID {
		return true // still waiting for its confirmation
	}

	what := "switching " + onOff(open.Enabled) + ", started by " + open.Actor
	switch last := state.Last; {
	case last != nil && last.ID == open.ID && last.Result == firewall.ResultConfirmed:
		// Confirmed, but SGC stopped before it could write that down.
		s.finish(ctx, open.Enabled, open.Actor, "")
		return false
	case last != nil && last.ID == open.ID && last.Result == firewall.ResultExpired:
		s.record(ctx, audit.ActorSystem, audit.ActionFirewallChangeExpired, what, "")
	case last != nil && last.ID == open.ID && last.Result == firewall.ResultFailed:
		s.record(ctx, audit.ActorSystem, audit.ActionFirewallChangeFailed, what+": "+last.Message, "")
	default:
		// Undone without a record of this change: the wait was interrupted,
		// or the machine restarted and came up with the confirmed rules.
		s.record(ctx, audit.ActorSystem, audit.ActionFirewallChangeUndone, what+" (the wait for confirmation was interrupted)", "")
	}
	s.clearOpenChange(ctx)
	return false
}

func (s *Service) clearOpenChange(ctx context.Context) {
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingOpenChange, ""); err != nil {
		s.cfg.Log.Error("forget the finished firewall change", "error", err)
	}
}

func (s *Service) record(ctx context.Context, actor, action, detail, remoteAddr string) {
	// The history must be written even when the request that caused the
	// entry has gone away in the meantime.
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remoteAddr); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}
