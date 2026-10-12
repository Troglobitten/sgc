package oscontrol

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
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/store"
)

// rootSide stands in for the root helper and the units behind it. It keeps
// the files the real ones keep, without apt.
type rootSide struct {
	t     *testing.T
	paths osupdate.Paths
	calls []string

	settings osupdate.Settings
	// The helper cannot be reached.
	down bool
	// The next change of mode is refused, with this reason.
	refuse string
	// Installing Debian's tool fails.
	noInternet bool
	nextID     int64
	now        time.Time
}

func (r *rootSide) write(path string, v any) {
	r.t.Helper()
	data, _ := json.Marshal(v)
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rootSide) reportFile() string { return filepath.Join(r.paths.RunDir, "report.json") }

func (r *rootSide) report() osupdate.Report {
	r.t.Helper()
	report, err := osupdate.ReadReport(r.paths)
	if err != nil {
		r.t.Fatal(err)
	}
	return report
}

func (r *rootSide) InstallPackages(_ context.Context, feature string) error {
	r.calls = append(r.calls, "packages for "+feature)
	if r.noInternet {
		return errors.New("apt-get failed")
	}
	r.settings.ToolInstalled = true
	return nil
}

func (r *rootSide) OSUpdateSettings(context.Context) (osupdate.Settings, error) {
	if r.down {
		return osupdate.Settings{}, errors.New("helper not reachable")
	}
	return r.settings, nil
}

func (r *rootSide) OSUpdateSetMode(_ context.Context, request osupdate.ModeRequest) error {
	r.calls = append(r.calls, "mode "+string(request.Mode()))
	r.now = r.now.Add(time.Second)
	outcome := osupdate.ModeOutcome{Mode: request.Mode(), At: r.now}
	if r.refuse != "" {
		outcome.Error = r.refuse
		r.write(filepath.Join(r.paths.RunDir, "mode.json"), outcome)
		return errors.New("the settings were refused or could not be put into effect")
	}
	r.write(filepath.Join(r.paths.RunDir, "mode.json"), outcome)
	os.MkdirAll(filepath.Dir(r.paths.ConfigFile), 0o755)
	if err := os.WriteFile(r.paths.ConfigFile, []byte(osupdate.Render(request.Mode())), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.settings.Periodic, r.settings.Timers = request.Automatic, true
	return nil
}

func (r *rootSide) OSUpdateStart(_ context.Context, job string) (int64, error) {
	r.calls = append(r.calls, "start "+job)
	if r.down {
		return 0, errors.New("helper not reachable")
	}
	report := r.report()
	if report.Running != "" {
		return 0, errors.New("SGC helper: could not start it: a look for updates or an installation is already running")
	}
	r.nextID++
	since := r.now
	report.Running, report.RunningID, report.RunningSince = job, r.nextID, &since
	r.write(r.reportFile(), report)
	return r.nextID, nil
}

// finish ends the running job the way the root side would.
func (r *rootSide) finish(waiting []string, install *osupdate.Install, checkError string) {
	r.t.Helper()
	report := r.report()
	if report.Running == "" {
		r.t.Fatal("nothing is running")
	}
	now := r.now
	if checkError != "" {
		report.CheckError, report.CheckFailedAt = checkError, &now
	} else {
		report.Waiting, report.CheckedAt, report.CheckError, report.CheckFailedAt = waiting, &now, "", nil
	}
	if install != nil {
		install.ID = report.RunningID
		report.LastInstall = install
	}
	report.Running, report.RunningID, report.RunningSince = "", 0, nil
	r.write(r.reportFile(), report)
}

type env struct {
	t       *testing.T
	db      *sql.DB
	root    *rootSide
	service *Service
	uptime  float64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	root := &rootSide{
		t: t,
		paths: osupdate.Paths{
			ConfigFile:      filepath.Join(dir, "apt.conf.d", "52sgc-updates"),
			RunDir:          filepath.Join(dir, "run"),
			StampFile:       filepath.Join(dir, "upgrade-stamp"),
			RestartFile:     filepath.Join(dir, "reboot-required"),
			RestartPackages: filepath.Join(dir, "reboot-required.pkgs"),
		},
		// A Debian that installs its updates by itself, as its cloud images do.
		settings: osupdate.Settings{ToolInstalled: true, Periodic: true, Timers: true},
		now:      time.Date(2026, 10, 12, 14, 0, 0, 0, time.UTC),
	}
	e := &env{t: t, db: db, root: root, uptime: 3600}
	e.service = New(Config{
		DB:     db,
		Helper: root,
		Audit:  audit.New(db),
		Paths:  root.paths,
		Uptime: func() (float64, error) { return e.uptime, nil },
		Now:    func() time.Time { return root.now },
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
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

func (e *env) calls() string { return strings.Join(e.root.calls, ", ") }

// chooseByHand sets the device up and lets the look that follows the choice
// finish with nothing waiting.
func (e *env) chooseByHand() {
	e.t.Helper()
	if err := e.service.SetMode(context.Background(), "alex", "", false); err != nil {
		e.t.Fatal(err)
	}
	e.root.finish([]string{}, nil, "")
}

func TestBeforeTheOwnerHasChosen(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.status()
	if !s.Available || s.Mode != "" || s.Wanted != "" || !s.Daily || s.Problem != "" || s.CheckedAt != nil || len(s.Waiting) != 0 {
		t.Fatalf("status: %+v", s)
	}
	// Until then SGC runs no package tools on the device, asked or unasked.
	if err := e.service.Check(ctx); !errors.Is(err, ErrNotSetUp) {
		t.Errorf("a look: %v", err)
	}
	if err := e.service.Install(ctx, "alex", ""); !errors.Is(err, ErrNotSetUp) {
		t.Errorf("an installation: %v", err)
	}
	e.service.lookIfDue(ctx)
	if e.calls() != "" {
		t.Errorf("the root side was asked: %s", e.calls())
	}
	e.expectHistory()
}

func TestChoosingTheMode(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.service.SetMode(ctx, "alex", "192.168.1.10", false); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Mode != "by-hand" || s.Wanted != "by-hand" || s.Daily || s.Problem != "" {
		t.Fatalf("by hand: %+v", s)
	}
	if err := e.service.SetMode(ctx, "alex", "192.168.1.10", true); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Mode != "automatic" || s.Wanted != "automatic" || !s.Daily {
		t.Fatalf("automatic: %+v", s)
	}
	// Choosing the same again is carried out: it is how a stopped timer is started.
	if err := e.service.SetMode(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	// Each choice is followed by a look, so that the page has something to
	// show; a look that is still running is not started a second time.
	if e.calls() != "mode by-hand, start check, mode automatic, mode automatic" {
		t.Errorf("the root side was asked: %s", e.calls())
	}
	if s := e.status(); s.Running != "check" {
		t.Errorf("no look is running after the choice: %+v", s)
	}
	e.expectHistory(
		"alex os_updates.mode_by_hand updates for the device are started in SGC's page",
		"alex os_updates.mode_automatic updates for the device install by themselves",
		"alex os_updates.mode_automatic updates for the device install by themselves",
	)
}

func TestOnADeviceWithoutDebiansTool(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root.settings = osupdate.Settings{}
	if s := e.status(); s.ToolInstalled || s.Daily {
		t.Fatalf("status: %+v", s)
	}

	// It cannot be fetched: said so, nothing changed.
	e.root.noInternet = true
	var changeErr *ChangeError
	if err := e.service.SetMode(ctx, "alex", "", true); !errors.As(err, &changeErr) || !strings.Contains(changeErr.Message, "reach the internet") {
		t.Fatalf("without a connection: %v", err)
	}
	if s := e.status(); s.Mode != "" || s.Wanted != "" {
		t.Errorf("after the failure: %+v", s)
	}

	e.root.noInternet = false
	if err := e.service.SetMode(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	// Only what this feature needs was asked for.
	if e.calls() != "packages for updates, packages for updates, mode automatic, start check" {
		t.Errorf("the root side was asked: %s", e.calls())
	}
	e.expectHistory(
		"system system.packages_installed unattended-upgrades, from Debian, for the device's updates",
		"alex os_updates.mode_automatic updates for the device install by themselves",
	)
}

func TestAChoiceThatIsRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.chooseByHand()
	e.root.refuse = "another settings file on this device overrules SGC's (APT::Periodic::Unattended-Upgrade)"
	var changeErr *ChangeError
	err := e.service.SetMode(ctx, "alex", "", true)
	if !errors.As(err, &changeErr) || !strings.Contains(changeErr.Message, "overrules SGC's") || !strings.Contains(changeErr.Message, "Nothing was changed") {
		t.Fatalf("a refused choice: %v", err)
	}
	// What the owner wants is what was last put into effect.
	if s := e.status(); s.Mode != "by-hand" || s.Wanted != "by-hand" {
		t.Errorf("after the refusal: %+v", s)
	}
	if got := e.history(); got[len(got)-1] != "alex os_updates.change_failed updates for the device install by themselves" {
		t.Errorf("last entry: %s", got[len(got)-1])
	}

	// The helper cannot be reached at all.
	e.root.down = true
	if err := e.service.SetMode(ctx, "alex", "", true); !errors.As(err, &changeErr) {
		t.Errorf("without the helper: %v", err)
	}
	if s := e.status(); s.Available || s.Mode != "by-hand" {
		t.Errorf("status without the helper: %+v", s)
	}
}

func TestProblemsAreSaidInWords(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.service.SetMode(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	e.root.settings.Timers = false
	if s := e.status(); !strings.Contains(s.Problem, "timers are not running") || s.Daily {
		t.Errorf("stopped timers: %+v", s)
	}
	e.root.settings.Timers, e.root.settings.Overridden, e.root.settings.Periodic = true, "APT::Periodic::Unattended-Upgrade", false
	if s := e.status(); !strings.Contains(s.Problem, "overrules SGC's (APT::Periodic::Unattended-Upgrade)") {
		t.Errorf("overruled: %+v", s)
	}
	e.root.settings = osupdate.Settings{}
	if s := e.status(); !strings.Contains(s.Problem, "no longer on this device") {
		t.Errorf("tool removed: %+v", s)
	}
}

func TestLookingAndInstalling(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.chooseByHand()

	if err := e.service.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Running != "check" {
		t.Fatalf("while looking: %+v", s)
	}
	// One thing at a time.
	if err := e.service.Check(ctx); !errors.Is(err, ErrBusy) {
		t.Errorf("a second look: %v", err)
	}
	if err := e.service.Install(ctx, "alex", ""); !errors.Is(err, ErrBusy) {
		t.Errorf("an installation during a look: %v", err)
	}
	e.root.finish([]string{"liblzma5", "xz-utils"}, nil, "")
	if s := e.status(); s.Running != "" || strings.Join(s.Waiting, " ") != "liblzma5 xz-utils" || s.CheckedAt == nil {
		t.Fatalf("after the look: %+v", s)
	}

	if err := e.service.Install(ctx, "alex", "192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	if !e.service.Installing() {
		t.Error("an installation at work is not reported as one")
	}
	e.service.settle(ctx)
	if got := e.history(); got[len(got)-1] != "alex os_updates.install_started" {
		t.Errorf("while installing, last entry: %s", got[len(got)-1])
	}
	e.root.finish([]string{}, &osupdate.Install{Packages: []string{"liblzma5", "xz-utils"}, Result: osupdate.ResultOK}, "")
	// Asking for the state is enough to get the end into the history.
	if s := e.status(); s.Running != "" || len(s.Waiting) != 0 || s.LastInstall == nil || s.LastInstall.Result != osupdate.ResultOK {
		t.Fatalf("after the installation: %+v", s)
	}
	if e.service.Installing() {
		t.Error("a finished installation is still reported as at work")
	}
	e.expectHistory(
		"alex os_updates.mode_by_hand updates for the device are started in SGC's page",
		"alex os_updates.install_started",
		"system os_updates.installed 2 updates: liblzma5, xz-utils, started by alex",
	)
	// Once.
	e.service.settle(ctx)
	e.status()
	if len(e.history()) != 3 {
		t.Errorf("the end was recorded more than once: %v", e.history())
	}
}

func TestHowAnInstallationCanEnd(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.chooseByHand()
	last := func() string { got := e.history(); return got[len(got)-1] }

	// It fails half-way.
	if err := e.service.Install(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	e.root.finish([]string{"broken-package"}, &osupdate.Install{Packages: []string{"libc6"}, Result: osupdate.ResultFailed, Message: "Installing failed."}, "")
	e.service.settle(ctx)
	if last() != "system os_updates.install_failed Installing failed. Installed before that: 1 update: libc6." {
		t.Errorf("a failure: %s", last())
	}

	// Nothing was waiting.
	if err := e.service.Install(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	e.root.finish([]string{}, &osupdate.Install{Packages: []string{}, Result: osupdate.ResultOK, Message: "Nothing was waiting."}, "")
	e.service.settle(ctx)
	if last() != "system os_updates.installed nothing was waiting, started by alex" {
		t.Errorf("nothing waiting: %s", last())
	}

	// The device restarts in the middle: the report in /run is gone.
	if err := e.service.Install(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(e.root.paths.RunDir)
	e.service.settle(ctx)
	if !strings.Contains(last(), "os_updates.install_failed The device restarted before") {
		t.Errorf("a restart in the middle: %s", last())
	}
	count := len(e.history())
	e.service.settle(ctx)
	if len(e.history()) != count {
		t.Error("recorded again")
	}

	// Many packages are not all spelled out.
	var many []string
	for i := range 40 {
		many = append(many, "package-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if err := e.service.Install(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	e.root.finish([]string{}, &osupdate.Install{Packages: many, Result: osupdate.ResultOK}, "")
	e.service.settle(ctx)
	if !strings.Contains(last(), "40 updates: package-aa, ") || !strings.Contains(last(), " and 25 more, started by alex") {
		t.Errorf("many packages: %s", last())
	}
}

func TestLookingOnceADay(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// A device set up before its last restart: the settings file is there,
	// and the report, which lives in /run, is not.
	e.chooseByHand()
	os.RemoveAll(e.root.paths.RunDir)
	e.root.calls = nil
	looks := func() int { return strings.Count(e.calls(), "start check") }

	// Not right after the device has started.
	e.uptime = 60
	e.service.lookIfDue(ctx)
	if looks() != 0 {
		t.Fatal("looked a minute after start-up")
	}
	e.uptime = 3600
	e.service.lookIfDue(ctx)
	if looks() != 1 {
		t.Fatalf("no look on a device that has never been looked at: %s", e.calls())
	}
	// Not while one runs.
	e.service.lookIfDue(ctx)
	if looks() != 1 {
		t.Fatal("a second look while the first runs")
	}
	e.root.finish([]string{}, nil, "")

	e.root.now = e.root.now.Add(23 * time.Hour)
	e.service.lookIfDue(ctx)
	if looks() != 1 {
		t.Fatal("looked again within the day")
	}
	e.root.now = e.root.now.Add(2 * time.Hour)
	e.service.lookIfDue(ctx)
	if looks() != 2 {
		t.Fatal("no look after a day")
	}

	// A look that failed is tried again after an hour, not after a day.
	e.root.finish(nil, nil, "Debian's servers could not be reached.")
	e.root.now = e.root.now.Add(30 * time.Minute)
	e.service.lookIfDue(ctx)
	if looks() != 2 {
		t.Fatal("tried again within the hour")
	}
	e.root.now = e.root.now.Add(40 * time.Minute)
	e.service.lookIfDue(ctx)
	if looks() != 3 {
		t.Fatal("not tried again after an hour")
	}
	e.root.finish([]string{}, nil, "")

	// If the helper cannot be reached, it is not asked every ten seconds.
	e.root.now = e.root.now.Add(25 * time.Hour)
	e.root.down = true
	e.service.lookIfDue(ctx)
	e.service.lookIfDue(ctx)
	e.root.now = e.root.now.Add(time.Minute)
	e.service.lookIfDue(ctx)
	if looks() != 4 {
		t.Fatalf("asked %d times while the helper was down", looks()-3)
	}
	e.root.down = false
	e.root.now = e.root.now.Add(20 * time.Minute)
	e.service.lookIfDue(ctx)
	if looks() != 5 {
		t.Fatal("not asked again once the helper was back")
	}

	// Debian's own daily run has been at work since the last look: what was
	// seen waiting is out of date, so SGC looks again without waiting for
	// the day to pass.
	e.root.finish([]string{"liblzma5"}, nil, "")
	e.service.lookIfDue(ctx)
	if looks() != 5 {
		t.Fatal("looked again right after a look")
	}
	os.WriteFile(e.root.paths.StampFile, nil, 0o644)
	os.Chtimes(e.root.paths.StampFile, e.root.now.Add(time.Hour), e.root.now.Add(time.Hour))
	e.root.now = e.root.now.Add(2 * time.Hour)
	e.service.lookIfDue(ctx)
	if looks() != 6 {
		t.Fatal("no look after Debian's daily run")
	}
	e.root.finish([]string{}, nil, "")
	e.service.lookIfDue(ctx)
	if looks() != 6 {
		t.Fatal("looked a second time for the same daily run")
	}
}

func TestRestartNeededAndARestoredMachine(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	os.WriteFile(e.root.paths.RestartFile, nil, 0o644)
	os.WriteFile(e.root.paths.RestartPackages, []byte("linux-image-6.12.48+deb13-amd64\n"), 0o644)
	if s := e.status(); !s.RestartNeeded || strings.Join(s.RestartPackages, " ") != "linux-image-6.12.48+deb13-amd64" {
		t.Errorf("status: %+v", s)
	}

	// An export from a device where updates installed by themselves, restored
	// on a new one: known, shown, and not acted on.
	if err := store.SetSetting(ctx, e.db, SettingMode, "automatic"); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Wanted != "automatic" || s.Mode != "" {
		t.Errorf("after a restore: %+v", s)
	}
	e.service.lookIfDue(ctx)
	if e.calls() != "" {
		t.Errorf("the root side was asked on a device the owner has not set up: %s", e.calls())
	}
}
