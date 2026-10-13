package logcontrol

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/log2ram"
	"github.com/Troglobitten/sgc/internal/store"
)

const megabyte = 1 << 20

// rootSide stands in for the root helper.
type rootSide struct {
	status log2ram.Status
	calls  []string
	// What the root side says when it refuses to switch, or to install.
	refuse        string
	refuseInstall bool
	gone          bool
}

func (r *rootSide) Log2ramStatus(context.Context) (log2ram.Status, error) {
	if r.gone {
		return log2ram.Status{}, errors.New("no answer")
	}
	return r.status, nil
}

func (r *rootSide) Log2ramSetEnabled(_ context.Context, enabled bool) error {
	if enabled {
		r.calls = append(r.calls, "on")
	} else {
		r.calls = append(r.calls, "off")
	}
	if r.refuse != "" {
		return errors.New(r.refuse)
	}
	r.status.Enabled = enabled
	return nil
}

func (r *rootSide) InstallPackages(_ context.Context, feature string) error {
	r.calls = append(r.calls, "install "+feature)
	if r.refuseInstall {
		return errors.New("could not install the packages")
	}
	// Installed, and switched off again at once by the root side.
	r.status.Installed = true
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
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{t: t, db: db, root: &rootSide{status: log2ram.Status{SizeBytes: 128 * megabyte}}}
	e.service = New(Config{DB: db, Helper: e.root, Audit: audit.New(db), Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return e
}

func (e *env) status() Status {
	e.t.Helper()
	status, err := e.service.Status(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return status
}

func (e *env) history(count int) string {
	e.t.Helper()
	entries, err := audit.New(e.db).Recent(context.Background(), count)
	if err != nil {
		e.t.Fatal(err)
	}
	var lines []string
	for _, entry := range entries {
		lines = append(lines, entry.Actor+" "+entry.Action)
	}
	return strings.Join(lines, ", ")
}

func TestTheInstallerInstallsItSwitchedOff(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if s := e.status(); !s.Available || s.Installed || s.Enabled || s.Largest == nil {
		t.Fatalf("to begin with: %+v", s)
	}
	installed, err := e.service.EnsureInstalled(ctx)
	if err != nil || !installed {
		t.Fatalf("installing: %v, %v", installed, err)
	}
	if got := strings.Join(e.root.calls, ", "); got != "install "+helper.PackagesLog2ram {
		t.Errorf("asked of the root side: %s", got)
	}
	if s := e.status(); !s.Installed || s.Enabled || s.Active || s.RestartNeeded || s.Wanted {
		t.Errorf("after installing: %+v", s)
	}
	if e.history(1) != "system system.packages_installed" {
		t.Errorf("history: %s", e.history(1))
	}
	// Nothing was chosen by installing.
	if _, found, _ := store.Setting(ctx, e.db, SettingEnabled); found {
		t.Error("installing recorded a choice")
	}
	// A second time there is nothing to do.
	if installed, err := e.service.EnsureInstalled(ctx); err != nil || installed || len(e.root.calls) != 1 {
		t.Errorf("a second time: %v, %v, %v", installed, err, e.root.calls)
	}
}

func TestSwitchingOnAndOff(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root.status.Installed = true

	if err := e.service.SetEnabled(ctx, "alex", "192.168.1.10", true); err != nil {
		t.Fatal(err)
	}
	// On, and not in effect until the device restarts.
	if s := e.status(); !s.Enabled || s.Active || !s.RestartNeeded || s.StartFailed {
		t.Errorf("switched on: %+v", s)
	}
	if e.history(1) != "alex log2ram.switched_on" {
		t.Errorf("history: %s", e.history(1))
	}
	// After the restart: in memory.
	e.root.status.Active, e.root.status.UsedBytes = true, 20*megabyte
	if s := e.status(); !s.Active || s.RestartNeeded || s.NearlyFull || s.UsedBytes != 20*megabyte || s.SizeBytes != 128*megabyte {
		t.Errorf("in memory: %+v", s)
	}
	// Nearly full is said from four fifths on.
	e.root.status.UsedBytes = 103 * megabyte
	e.root.status.Largest = []log2ram.Entry{{Name: "big-program.log", Bytes: 80 * megabyte}}
	if s := e.status(); !s.NearlyFull || len(s.Largest) != 1 || s.Largest[0].Name != "big-program.log" {
		t.Errorf("nearly full: %+v", s)
	}

	// Off: still in memory until the restart.
	if err := e.service.SetEnabled(ctx, "alex", "", false); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Enabled || !s.Active || !s.RestartNeeded || s.Wanted {
		t.Errorf("switched off: %+v", s)
	}
	if e.history(1) != "alex log2ram.switched_off" {
		t.Errorf("history: %s", e.history(1))
	}
	if got := strings.Join(e.root.calls, ", "); got != "on, off" {
		t.Errorf("asked of the root side: %s", got)
	}
}

func TestSwitchingOnInstallsItWhereItIsNotThere(t *testing.T) {
	// A device updated from a version that did not install log2ram.
	e := newEnv(t)
	ctx := context.Background()
	if err := e.service.SetEnabled(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.root.calls, ", "); got != "install log2ram, on" {
		t.Errorf("asked of the root side: %s", got)
	}
	if e.history(2) != "alex log2ram.switched_on, system system.packages_installed" {
		t.Errorf("history: %s", e.history(2))
	}

	// Debian cannot be reached: said in words, nothing chosen.
	e = newEnv(t)
	e.root.refuseInstall = true
	var failure *ChangeError
	if err := e.service.SetEnabled(ctx, "alex", "", true); !errors.As(err, &failure) || !strings.Contains(failure.Message, "could not be installed from Debian") {
		t.Errorf("an installation that fails: %v", err)
	}
	if _, found, _ := store.Setting(ctx, e.db, SettingEnabled); found || len(e.root.calls) != 1 {
		t.Errorf("after the failure: choice recorded %v, calls %v", found, e.root.calls)
	}
	// Switching off where it is not installed asks nothing of the root side.
	e = newEnv(t)
	if err := e.service.SetEnabled(ctx, "alex", "", false); err != nil || len(e.root.calls) != 0 {
		t.Errorf("switching off without log2ram: %v, %v", err, e.root.calls)
	}
}

func TestARefusalIsPassedOnInWords(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root.status.Installed = true
	e.root.refuse = "the logs of this device would take 143 MB, and must fit in 85 MB to leave room in memory. The largest in the log folder: big-program.log (118 MB)"
	var failure *ChangeError
	err := e.service.SetEnabled(ctx, "alex", "", true)
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, "big-program.log (118 MB)") || !strings.Contains(failure.Message, "Nothing was changed") {
		t.Fatalf("a refusal: %v", err)
	}
	if s := e.status(); s.Enabled || s.Wanted {
		t.Errorf("after a refusal: %+v", s)
	}
	// The helper does not answer.
	e.root.gone = true
	if err := e.service.SetEnabled(ctx, "alex", "", true); !errors.As(err, &failure) {
		t.Errorf("without the helper: %v", err)
	}
	if s := e.status(); s.Available {
		t.Errorf("without the helper: %+v", s)
	}
}

func TestStartUpWithLogsThatDidNotFit(t *testing.T) {
	e := newEnv(t)
	e.root.status = log2ram.Status{Installed: true, Enabled: true, StartFailed: true, SizeBytes: 128 * megabyte, UsedBytes: 143 * megabyte}
	// Not "restart needed": a restart alone changes nothing.
	if s := e.status(); !s.StartFailed || s.RestartNeeded || s.Active || s.NearlyFull {
		t.Errorf("logs that did not fit: %+v", s)
	}
}

func TestAfterARestoreTheChoiceIsShownAndNotActedOn(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// The setting came with the export; this device has log2ram from its
	// installer, switched off.
	e.root.status.Installed = true
	store.SetSetting(ctx, e.db, SettingEnabled, "true")
	if s := e.status(); !s.Wanted || s.Enabled || len(e.root.calls) != 0 {
		t.Errorf("on the restored device: %+v, %v", s, e.root.calls)
	}
	if err := e.service.SetEnabled(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Wanted || !s.Enabled {
		t.Errorf("after switching it on there: %+v", s)
	}
}
