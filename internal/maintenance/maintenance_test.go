package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/update"
)

// world stands in for everything around the window: the clock, the device,
// the root helper and SGC's knowledge of its own versions.
type world struct {
	t       *testing.T
	db      *sql.DB
	service *Service
	calls   []string

	now          time.Time
	uptime       float64
	synchronised bool
	needed       bool
	installing   bool
	dailyRunning bool
	helperDown   bool
	latest       string // a newer version of SGC, if any
	autoCheck    bool
	fetchErr     error
}

func newWorld(t *testing.T) *world {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	w := &world{
		t: t, db: db,
		// Three in the morning, device time.
		now:          time.Date(2026, 10, 12, 3, 0, 0, 0, time.FixedZone("EEST", 3*3600)),
		uptime:       86400,
		synchronised: true,
	}
	w.service = New(Config{
		DB: db, Updates: w, Helper: w, Audit: audit.New(db),
		RestartNeeded:     func() (bool, []string) { return w.needed, []string{"linux-image-6.12.48+deb13-arm64"} },
		Installing:        func() bool { return w.installing },
		Uptime:            func() (float64, error) { return w.uptime, nil },
		ClockSynchronised: func() bool { return w.synchronised },
		Now:               func() time.Time { return w.now },
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return w
}

func (w *world) Status(context.Context) (update.Status, error) {
	return update.Status{Current: "1.0.0", Latest: w.latest, UpdateAvailable: w.latest != "", AutoCheck: w.autoCheck}, nil
}
func (w *world) Fetch(_ context.Context, version string) error {
	w.calls = append(w.calls, "fetch "+version)
	return w.fetchErr
}
func (w *world) SetAutoCheck(_ context.Context, enabled bool) error {
	w.autoCheck = enabled
	return nil
}
func (w *world) RestartDevice(context.Context) error {
	w.calls = append(w.calls, "restart")
	return nil
}
func (w *world) StartUpdate(_ context.Context, version string) error {
	w.calls = append(w.calls, "install "+version)
	return nil
}
func (w *world) OSUpdateSettings(context.Context) (osupdate.Settings, error) {
	if w.helperDown {
		return osupdate.Settings{}, errors.New("helper not reachable")
	}
	return osupdate.Settings{DailyRunning: w.dailyRunning}, nil
}

func (w *world) window(enabled bool, start, end string) {
	w.t.Helper()
	if err := w.service.Set(context.Background(), "alex", "192.168.1.10", enabled, start, end); err != nil {
		w.t.Fatal(err)
	}
}

// tick looks at the window once and returns what was asked of the device.
func (w *world) tick() string {
	w.calls = nil
	w.service.tick(context.Background())
	return strings.Join(w.calls, ", ")
}

func (w *world) pass(d time.Duration) { w.now = w.now.Add(d); w.uptime += d.Seconds() }

func (w *world) history() []string {
	w.t.Helper()
	entries, err := audit.New(w.db).Recent(context.Background(), 50)
	if err != nil {
		w.t.Fatal(err)
	}
	var lines []string
	for i := len(entries) - 1; i >= 0; i-- {
		lines = append(lines, strings.TrimSpace(entries[i].Actor+" "+entries[i].Action+" "+entries[i].Detail))
	}
	return lines
}

func TestInWindow(t *testing.T) {
	at := func(clock string) time.Time {
		parsed, _ := time.Parse("15:04", clock)
		return parsed
	}
	for _, c := range []struct {
		now, start, end string
		want            bool
	}{
		{"04:00", "04:00", "05:00", true},
		{"04:59", "04:00", "05:00", true},
		{"05:00", "04:00", "05:00", false},
		{"03:59", "04:00", "05:00", false},
		// Over midnight.
		{"23:30", "23:00", "01:00", true},
		{"00:30", "23:00", "01:00", true},
		{"01:00", "23:00", "01:00", false},
		{"12:00", "23:00", "01:00", false},
		// Not a window at all.
		{"04:00", "04:00", "04:00", false},
		{"04:00", "4:00", "05:00", false},
		{"04:00", "04:00", "25:00", false},
		{"04:00", "", "", false},
	} {
		if got := inWindow(at(c.now), c.start, c.end); got != c.want {
			t.Errorf("%s in %s-%s: %v", c.now, c.start, c.end, got)
		}
	}
}

func TestSettings(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	s, err := w.service.Status(ctx)
	if err != nil || s.Enabled || s.Start != "04:00" || s.End != "05:00" || s.AutoUpdate || s.UpdateWaitDays != 3 {
		t.Fatalf("to begin with: %+v, %v", s, err)
	}
	if s.DeviceTime != "03:00" || s.TimeZone != "EEST (UTC+3)" || s.InWindow {
		t.Errorf("the device's time: %+v", s)
	}
	var input *InputError
	for _, bad := range [][2]string{{"4", "5"}, {"04:00", "04:00"}, {"24:00", "05:00"}, {"04:60", "05:00"}, {"", ""}, {"04:00; reboot", "05:00"}} {
		if err := w.service.Set(ctx, "alex", "", true, bad[0], bad[1]); !errors.As(err, &input) {
			t.Errorf("window %q to %q: %v", bad[0], bad[1], err)
		}
	}
	w.window(true, "02:30", "03:30")
	if s, _ := w.service.Status(ctx); !s.Enabled || s.Start != "02:30" || !s.InWindow {
		t.Errorf("after setting: %+v", s)
	}
	// Letting SGC update itself needs the daily look for new versions.
	if err := w.service.SetAutoUpdate(ctx, "alex", "", true); err != nil || !w.autoCheck {
		t.Errorf("auto update: %v, daily look %v", err, w.autoCheck)
	}
	want := []string{
		"alex setting.changed maintenance window: every day from 02:30 to 03:30",
		"alex setting.changed SGC's own updates install by themselves in the maintenance window",
	}
	if got := w.history(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("history: %v", got)
	}
}

func TestRestartOnlyInTheWindowAndOnlyWhenNeeded(t *testing.T) {
	w := newWorld(t)
	w.needed = true

	// Nothing is switched on.
	if got := w.tick(); got != "" {
		t.Fatalf("with the window off: %s", got)
	}
	w.window(true, "04:00", "05:00")
	if got := w.tick(); got != "" {
		t.Fatalf("an hour before the window: %s", got)
	}
	w.pass(time.Hour) // 04:00

	// Each of these alone keeps the device up.
	for name, hold := range map[string]*bool{"updates being installed": &w.installing, "Debian's daily run at work": &w.dailyRunning, "the helper not answering": &w.helperDown} {
		*hold = true
		if got := w.tick(); got != "" {
			t.Errorf("with %s: %s", name, got)
		}
		*hold = false
	}
	w.synchronised = false
	if got := w.tick(); got != "" {
		t.Errorf("with a clock that is not synchronised: %s", got)
	}
	w.synchronised = true
	up := w.uptime
	w.uptime = 120
	if got := w.tick(); got != "" {
		t.Errorf("two minutes after start-up: %s", got)
	}
	w.uptime = up
	w.needed = false
	if got := w.tick(); got != "" {
		t.Errorf("with no restart needed: %s", got)
	}
	w.needed = true

	if got := w.tick(); got != "restart" {
		t.Fatalf("in the window, with a restart needed: %q", got)
	}
	if got := w.history(); got[len(got)-1] != "system device.restart in the maintenance window, needed by linux-image-6.12.48+deb13-arm64" {
		t.Errorf("history: %s", got[len(got)-1])
	}
	if s, _ := w.service.Status(context.Background()); s.LastRestart == nil {
		t.Error("the restart is not remembered")
	}

	// Whatever claims a restart is needed afterwards: not again in this window.
	w.pass(10 * time.Minute)
	if got := w.tick(); got != "" {
		t.Fatalf("a second restart ten minutes later: %s", got)
	}
	w.pass(50 * time.Minute) // 05:00, the window is over
	w.pass(23 * time.Hour)   // 04:00 the next day
	if got := w.tick(); got != "restart" {
		t.Errorf("in the next day's window: %q", got)
	}
}

func TestSGCUpdatesItselfAfterThreeDays(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.window(true, "03:00", "04:00") // now
	w.latest = "1.1.0"

	// Not switched on: the version is noted, nothing more.
	if got := w.tick(); got != "" {
		t.Fatalf("without auto update: %s", got)
	}
	if err := w.service.SetAutoUpdate(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	s, _ := w.service.Status(ctx)
	if s.UpdateVersion != "1.1.0" || s.UpdateInstallableFrom == nil || !s.UpdateInstallableFrom.Equal(w.now.Add(72*time.Hour)) {
		t.Fatalf("what the page is told: %+v", s)
	}
	for day := 1; day <= 2; day++ {
		w.pass(24 * time.Hour)
		if got := w.tick(); got != "" {
			t.Fatalf("after %d day(s): %s", day, got)
		}
	}
	// A newer version appears: the three days start again for that one.
	w.latest = "1.2.0"
	w.pass(24 * time.Hour)
	if got := w.tick(); got != "" {
		t.Fatalf("a version first seen today: %s", got)
	}
	w.pass(48 * time.Hour)
	if got := w.tick(); got != "" {
		t.Fatalf("two days after it appeared: %s", got)
	}
	w.pass(24 * time.Hour)
	// Outside the window nothing happens, however long it has been.
	w.pass(2 * time.Hour)
	if got := w.tick(); got != "" {
		t.Fatalf("outside the window: %s", got)
	}
	w.pass(22 * time.Hour)
	if got := w.tick(); got != "fetch 1.2.0, install 1.2.0" {
		t.Fatalf("after three days, in the window: %q", got)
	}
	if got := w.history(); got[len(got)-1] != "system update.started to 1.2.0, by itself in the maintenance window" {
		t.Errorf("history: %s", got[len(got)-1])
	}
	// Once per window, also if it did not work.
	if got := w.tick(); got != "" {
		t.Errorf("a second try in the same window: %s", got)
	}

	// A download that is refused is said so, and nothing is installed.
	w.pass(24 * time.Hour)
	w.fetchErr = errors.New("the signature is not valid")
	if got := w.tick(); got != "fetch 1.2.0" {
		t.Errorf("a refused download: %q", got)
	}
	if got := w.history(); !strings.Contains(got[len(got)-1], "update.failed to 1.2.0: the signature is not valid") {
		t.Errorf("history: %s", got[len(got)-1])
	}
}

// A version seen while the clock is not known to be right is not counted
// from then: a device that starts with its clock years off would otherwise
// find the three days long over.
func TestTheWaitIsNotCountedOnAnUnsetClock(t *testing.T) {
	w := newWorld(t)
	w.window(true, "03:00", "04:00")
	w.service.SetAutoUpdate(context.Background(), "alex", "", true)
	w.latest = "1.1.0"
	w.synchronised = false
	w.now = w.now.AddDate(-5, 0, 0)
	w.tick()
	w.now = w.now.AddDate(5, 0, 0)
	w.synchronised = true
	if got := w.tick(); got != "" {
		t.Fatalf("installed at once: %s", got)
	}
	if s, _ := w.service.Status(context.Background()); s.UpdateInstallableFrom == nil || !s.UpdateInstallableFrom.Equal(w.now.Add(72*time.Hour)) {
		t.Errorf("the wait: %+v", s)
	}
}

// Both are due: SGC's own update goes first, the restart follows.
func TestUpdateBeforeRestart(t *testing.T) {
	w := newWorld(t)
	w.window(true, "03:00", "04:00")
	w.service.SetAutoUpdate(context.Background(), "alex", "", true)
	w.latest = "1.1.0"
	w.tick()
	w.pass(72 * time.Hour)
	w.needed = true
	if got := w.tick(); got != "fetch 1.1.0, install 1.1.0" {
		t.Fatalf("first: %q", got)
	}
	if got := w.tick(); got != "restart" {
		t.Fatalf("then: %q", got)
	}
}
