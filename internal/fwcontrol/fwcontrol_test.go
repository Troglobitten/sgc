package fwcontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

// rootSide stands in for the root helper and the units behind it: it keeps
// the same files the real ones keep, without touching any firewall.
type rootSide struct {
	t      *testing.T
	paths  firewall.Paths
	runDir string

	installed    bool
	installErr   error
	changeErr    error
	changeReason string // written as the failed change's message
	confirmErr   error
	calls        []string
	nextID       int64
	uptime       float64
}

func (r *rootSide) write(name string, v any) {
	r.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.MkdirAll(r.runDir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.runDir, name), data, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rootSide) pending() *firewall.Pending {
	state, err := firewall.ReadState(r.paths)
	if err != nil {
		r.t.Fatal(err)
	}
	return state.Pending
}

func (r *rootSide) end(result string) {
	p := r.pending()
	os.Remove(filepath.Join(r.runDir, "pending.json"))
	r.write("last.json", firewall.Outcome{ID: p.ID, Result: result, At: time.Now()})
}

func (r *rootSide) InstallPackages(context.Context) error {
	r.calls = append(r.calls, "install")
	if r.installErr == nil {
		r.installed = true
	}
	return r.installErr
}

func (r *rootSide) FirewallChange(_ context.Context, request firewall.Request) error {
	r.calls = append(r.calls, "change "+onOff(request.Enabled))
	r.nextID++
	if r.changeErr != nil {
		r.write("last.json", firewall.Outcome{ID: r.nextID, Result: firewall.ResultFailed, Message: r.changeReason, At: time.Now()})
		return r.changeErr
	}
	r.write("pending.json", firewall.Pending{
		ID:             r.nextID,
		Config:         firewall.Config{Enabled: request.Enabled, SSHPorts: []int{22}, WebPort: 8443},
		DeadlineUptime: r.uptime + 60,
	})
	return nil
}

func (r *rootSide) FirewallConfirm(context.Context) error {
	r.calls = append(r.calls, "confirm")
	if r.confirmErr != nil {
		return r.confirmErr
	}
	p := r.pending()
	rules, err := firewall.Render(p.Config)
	if err != nil {
		r.t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(r.paths.ConfirmedFile), 0o755)
	if err := os.WriteFile(r.paths.ConfirmedFile, []byte(rules), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.end(firewall.ResultConfirmed)
	return nil
}

func (r *rootSide) FirewallUndo(context.Context) error {
	r.calls = append(r.calls, "undo")
	r.end(firewall.ResultUndone)
	return nil
}

type env struct {
	t       *testing.T
	db      *sql.DB
	root    *rootSide
	service *Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	runDir := filepath.Join(dir, "run")
	root := &rootSide{
		t:      t,
		runDir: runDir,
		paths:  firewall.Paths{ConfirmedFile: filepath.Join(dir, "etc", "firewall.nft"), RunDir: runDir},
		uptime: 500,
	}
	service := New(Config{
		DB:        db,
		Helper:    root,
		Audit:     audit.New(db),
		Paths:     root.paths,
		Installed: func() bool { return root.installed },
		Uptime:    func() (float64, error) { return root.uptime, nil },
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return &env{t: t, db: db, root: root, service: service}
}

func (e *env) status() Status {
	e.t.Helper()
	status, err := e.service.Status(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return status
}

// history returns the audit log, oldest first, as "actor action detail".
func (e *env) history() []string {
	e.t.Helper()
	entries, err := audit.New(e.db).Recent(context.Background(), 50)
	if err != nil {
		e.t.Fatal(err)
	}
	var lines []string
	for i := len(entries) - 1; i >= 0; i-- {
		lines = append(lines, strings.TrimSpace(entries[i].Actor+" "+entries[i].Action+" "+entries[i].Detail))
	}
	return lines
}

func (e *env) expectHistory(want ...string) {
	e.t.Helper()
	got := e.history()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		e.t.Errorf("history:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func (e *env) setting(key string) string {
	e.t.Helper()
	value, _, err := store.Setting(context.Background(), e.db, key)
	if err != nil {
		e.t.Fatal(err)
	}
	return value
}

func TestSwitchingOnAndConfirming(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if s := e.status(); s.State != StateOff || s.SoftwareInstalled || s.Wanted || s.Pending != nil || s.ConfirmSeconds != 60 {
		t.Fatalf("fresh machine: %+v", s)
	}

	if err := e.service.Change(ctx, "alex", "192.168.1.10", true); err != nil {
		t.Fatal(err)
	}
	// The software is installed first, because a clean Debian lacks it.
	if got := strings.Join(e.root.calls, ", "); got != "install, change on" {
		t.Errorf("root side was asked: %s", got)
	}
	e.root.uptime += 15
	s := e.status()
	if s.State != StatePending || s.Pending == nil || !s.Pending.Enabled || s.Pending.SecondsLeft != 45 {
		t.Fatalf("after switching on: %+v pending %+v", s, s.Pending)
	}
	if s.Wanted {
		t.Error("an unconfirmed change already counts as what the owner wants")
	}
	if len(s.SSHPorts) != 1 || s.SSHPorts[0] != 22 || s.WebPort != 8443 {
		t.Errorf("what is let in: SSH %v, page %d", s.SSHPorts, s.WebPort)
	}

	if err := e.service.Confirm(ctx, "alex", "192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.State != StateOn || !s.Wanted || s.Pending != nil || !s.SoftwareInstalled {
		t.Fatalf("after confirming: %+v", s)
	}
	if e.setting(SettingEnabled) != "true" || e.setting(SettingOpenChange) != "" {
		t.Errorf("settings: enabled=%q open=%q", e.setting(SettingEnabled), e.setting(SettingOpenChange))
	}
	e.expectHistory(
		"system system.packages_installed nftables, from Debian, for the firewall",
		"alex firewall.change_started switching on",
		"alex firewall.change_confirmed firewall switched on",
	)

	// Switching on what is on, or starting a second change, is refused.
	if err := e.service.Change(ctx, "alex", "", true); !errors.Is(err, ErrNoChange) {
		t.Errorf("switching on twice: %v", err)
	}
	if err := e.service.Change(ctx, "alex", "", false); err != nil {
		t.Fatal(err)
	}
	if err := e.service.Change(ctx, "alex", "", true); !errors.Is(err, ErrChangePending) {
		t.Errorf("a second change while one waits: %v", err)
	}
}

func TestUndo(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root.installed = true

	if err := e.service.Change(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	if err := e.service.Undo(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.State != StateOff || s.Wanted {
		t.Fatalf("after undoing: %+v", s)
	}
	e.expectHistory("alex firewall.change_started switching on", "alex firewall.change_undone switching on")
	if e.setting(SettingOpenChange) != "" {
		t.Error("the undone change is still remembered as open")
	}
	// Undoing when nothing waits is not an error: the wish is fulfilled.
	if err := e.service.Undo(ctx, "alex", ""); err != nil {
		t.Errorf("undoing again: %v", err)
	}
}

func TestAChangeNobodyConfirmsIsWrittenDownOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root.installed = true

	if err := e.service.Change(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	// Still waiting: nothing to write down.
	if open := e.service.settle(ctx); !open {
		t.Fatal("a waiting change was settled")
	}
	// The root side undoes it when the time is up.
	e.root.end(firewall.ResultExpired)

	if open := e.service.settle(ctx); open {
		t.Fatal("the expired change is still open")
	}
	e.service.settle(ctx)
	e.expectHistory(
		"alex firewall.change_started switching on",
		"system firewall.change_expired switching on, started by alex",
	)

	// A confirmation that arrives now is told why it is too late.
	if err := e.service.Confirm(ctx, "alex", ""); !errors.Is(err, ErrTooLate) {
		t.Errorf("confirming afterwards: %v", err)
	}
	if e.status().Wanted {
		t.Error("an expired change counts as what the owner wants")
	}
}

// The machine restarts while a change waits: it comes up with the confirmed
// rules and without any record of the change.
func TestAChangeLostToARestartIsWrittenDown(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root.installed = true
	if err := e.service.Change(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(e.root.runDir) // what a restart does to /run

	e.service.settle(ctx)
	e.expectHistory(
		"alex firewall.change_started switching on",
		"system firewall.change_undone switching on, started by alex (the wait for confirmation was interrupted)",
	)
}

// SGC stops right after the root side confirmed, before writing it down.
func TestAConfirmationSGCMissedIsCaughtUp(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root.installed = true
	if err := e.service.Change(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	e.root.FirewallConfirm(ctx)

	e.service.settle(ctx)
	if e.setting(SettingEnabled) != "true" {
		t.Error("the confirmed state did not reach the setting")
	}
	e.expectHistory(
		"alex firewall.change_started switching on",
		"alex firewall.change_confirmed firewall switched on",
	)
}

func TestFailuresAreExplained(t *testing.T) {
	ctx := context.Background()
	var failure *ChangeError

	// The software cannot be installed: nothing else is attempted.
	e := newEnv(t)
	e.root.installErr = errors.New("no network")
	err := e.service.Change(ctx, "alex", "", true)
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, "could not be installed") {
		t.Errorf("error: %v", err)
	}
	if got := strings.Join(e.root.calls, ", "); got != "install" {
		t.Errorf("root side was asked: %s", got)
	}

	// The rules are refused: the reason comes from the root side's record.
	e = newEnv(t)
	e.root.installed = true
	e.root.changeErr = errors.New("unit failed")
	e.root.changeReason = "nftables did not accept the new rules: syntax error"
	err = e.service.Change(ctx, "alex", "", true)
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, "syntax error") || !strings.Contains(failure.Message, "Nothing was changed") {
		t.Errorf("error: %v", err)
	}
	e.expectHistory("alex firewall.change_failed switching on")
	if e.status().State != StateOff {
		t.Error("a failed change left something behind")
	}

	// The confirmation loses a race with the clock.
	e = newEnv(t)
	e.root.installed = true
	if err := e.service.Change(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	e.root.confirmErr = errors.New("nothing pending")
	if err := e.service.Confirm(ctx, "alex", ""); !errors.Is(err, ErrTooLate) {
		t.Errorf("error: %v", err)
	}
}

// After restoring an export the setting says "on", the machine says "off".
func TestWantedButOffAfterARestore(t *testing.T) {
	e := newEnv(t)
	if err := store.SetSetting(context.Background(), e.db, SettingEnabled, "true"); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.State != StateOff || !s.Wanted {
		t.Errorf("status: %+v", s)
	}
}

// Both of the root side's safety nets failed: the change is past its deadline
// and still in effect. SGC asks for it to be undone.
func TestAnOverdueChangeIsUndone(t *testing.T) {
	e := newEnv(t)
	e.root.installed = true
	if err := e.service.Change(context.Background(), "alex", "", true); err != nil {
		t.Fatal(err)
	}

	e.root.uptime += 60 + overdueGrace.Seconds() - 1
	if e.service.rescue(context.Background()) {
		t.Fatal("stepped in before the root side had its chance")
	}
	e.root.uptime += 2
	if !e.service.rescue(context.Background()) {
		t.Fatal("an overdue change was left in effect")
	}
	if got := e.root.calls[len(e.root.calls)-1]; got != "undo" {
		t.Errorf("last request to the root side: %s", got)
	}
	if e.status().State != StateOff {
		t.Errorf("status: %+v", e.status())
	}
	// With nothing pending there is nothing to rescue.
	if e.service.rescue(context.Background()) {
		t.Error("stepped in with nothing pending")
	}
}

func TestRunSettlesWhatWasLeftOpen(t *testing.T) {
	e := newEnv(t)
	e.root.installed = true
	if err := e.service.Change(context.Background(), "alex", "", true); err != nil {
		t.Fatal(err)
	}
	e.root.end(firewall.ResultExpired)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.service.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.history()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	e.expectHistory(
		"alex firewall.change_started switching on",
		"system firewall.change_expired switching on, started by alex",
	)
}
