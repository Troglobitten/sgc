// Package maintenance is the maintenance window: a daily period, chosen by
// the owner, in which SGC may do by itself what interrupts the device.
//
// Two things happen in it, each only if the owner switched it on:
//
//   - The device is restarted, if an installed update needs a restart to take
//     effect (internal/osupdate knows whether one does).
//   - SGC installs its own newest version, once this device has known that
//     version for three days.
//
// Everything here runs in the unprivileged web process and uses operations
// it already had: "restart the device" and "install this downloaded SGC
// version". Nothing new is asked of the root side. The price, accepted by
// the owner: while SGC itself is not running, nothing happens in the window.
package maintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/update"
)

// Settings the owner makes. They travel with an export.
const (
	SettingEnabled    = "maintenance.enabled" // "true" or "false"
	SettingStart      = "maintenance.start"   // "04:00", in the device's own time
	SettingEnd        = "maintenance.end"
	SettingAutoUpdate = "update.auto_install" // SGC's own updates install in the window
)

// Bookkeeping of one installation; left out of exports
// (internal/backup/tables.go).
const (
	settingLastRestart   = "maintenance.last_restart"    // when SGC last restarted the device by itself
	settingLastUpdateTry = "maintenance.last_update_try" // when SGC last tried to update itself by itself
	settingFirstSeen     = "update.first_seen"           // the newest version, and when this device first saw it
)

const (
	DefaultStart = "04:00"
	DefaultEnd   = "05:00"

	// UpdateWait is how long this device must have known a version of SGC
	// before it installs it by itself (the owner's choice). Time for a
	// faulty or tampered release to be noticed and withdrawn. It is counted
	// from when this device first saw the version, not from a date the
	// release carries, which whoever published it could have set.
	UpdateWait = 72 * time.Hour

	// Not in the first minutes after start-up: the clock may not be set yet,
	// and a device that restarts must never do so again straight away.
	quietAfterStart = 5 * time.Minute
	// At most one automatic restart, and one try at an update, per window.
	oncePer = 20 * time.Hour
	// How often the window is looked at.
	tickEvery = 30 * time.Second
)

// InputError is something wrong with what the owner entered.
type InputError struct{ Message string }

func (e *InputError) Error() string { return e.Message }

// Updates is what this package needs to know and do about SGC's own versions.
type Updates interface {
	Status(ctx context.Context) (update.Status, error)
	Fetch(ctx context.Context, version string) error
	SetAutoCheck(ctx context.Context, enabled bool) error
}

// Helper is what this package asks the root helper to do.
type Helper interface {
	RestartDevice(ctx context.Context) error
	StartUpdate(ctx context.Context, version string) error
	OSUpdateSettings(ctx context.Context) (osupdate.Settings, error)
}

type Config struct {
	DB      *sql.DB
	Updates Updates
	Helper  Helper
	Audit   *audit.Log
	// RestartNeeded reports whether an installed update waits for a restart,
	// and which packages asked for one.
	RestartNeeded func() (bool, []string)
	// Installing reports whether updates for the device are being installed.
	Installing func() bool
	// Uptime is how long the device has been running, in seconds.
	Uptime func() (float64, error)
	// ClockSynchronised reports whether the device's clock has been set from
	// the network since it started. A window is a time of day; on a clock
	// that is wrong it would be some other time of day.
	ClockSynchronised func() bool
	// Now is the device's own time, in its own time zone.
	Now func() time.Time
	Log *slog.Logger
}

type Service struct {
	cfg Config
	mu  sync.Mutex
}

func New(cfg Config) *Service { return &Service{cfg: cfg} }

// --- State as the interface shows it ----------------------------------------------

type Status struct {
	Enabled bool   `json:"enabled"`
	Start   string `json:"start"`
	End     string `json:"end"`
	// DeviceTime and TimeZone say what the window's times mean: the device's
	// clock, which need not be the clock of whoever looks at the page.
	DeviceTime string `json:"deviceTime"`
	TimeZone   string `json:"timeZone"`
	InWindow   bool   `json:"inWindow"`
	// ClockSynchronised false means nothing happens in the window for now.
	ClockSynchronised bool `json:"clockSynchronised"`
	// RestartNeeded: an installed update waits for a restart.
	RestartNeeded bool `json:"restartNeeded"`
	// LastRestart is when SGC last restarted the device by itself.
	LastRestart *time.Time `json:"lastRestart"`

	// AutoUpdate: SGC's own updates install in the window.
	AutoUpdate     bool `json:"autoUpdate"`
	UpdateWaitDays int  `json:"updateWaitDays"`
	// UpdateVersion is a newer version of SGC this device knows of, and
	// UpdateInstallableFrom when it has known it long enough.
	UpdateVersion         string     `json:"updateVersion"`
	UpdateInstallableFrom *time.Time `json:"updateInstallableFrom"`
}

type settings struct {
	enabled, autoUpdate bool
	start, end          string
}

func (s *Service) settings(ctx context.Context) (settings, error) {
	cfg := settings{start: DefaultStart, end: DefaultEnd}
	for key, target := range map[string]*string{SettingStart: &cfg.start, SettingEnd: &cfg.end} {
		value, found, err := store.Setting(ctx, s.cfg.DB, key)
		if err != nil {
			return cfg, err
		}
		// A value that is not a time of day is not acted on.
		if _, ok := minutes(value); found && ok {
			*target = value
		}
	}
	for key, target := range map[string]*bool{SettingEnabled: &cfg.enabled, SettingAutoUpdate: &cfg.autoUpdate} {
		value, _, err := store.Setting(ctx, s.cfg.DB, key)
		if err != nil {
			return cfg, err
		}
		*target = value == "true"
	}
	return cfg, nil
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	cfg, err := s.settings(ctx)
	if err != nil {
		return Status{}, err
	}
	now := s.cfg.Now()
	needed, _ := s.cfg.RestartNeeded()
	status := Status{
		Enabled: cfg.enabled, Start: cfg.start, End: cfg.end,
		DeviceTime: now.Format("15:04"), TimeZone: zoneName(now),
		InWindow:          inWindow(now, cfg.start, cfg.end),
		ClockSynchronised: s.cfg.ClockSynchronised(),
		RestartNeeded:     needed,
		AutoUpdate:        cfg.autoUpdate,
		UpdateWaitDays:    int(UpdateWait.Hours() / 24),
	}
	if at := s.moment(ctx, settingLastRestart); !at.IsZero() {
		status.LastRestart = &at
	}
	if seen := s.firstSeen(ctx); seen.Version != "" {
		if current, err := s.cfg.Updates.Status(ctx); err == nil && current.UpdateAvailable && current.Latest == seen.Version {
			from := time.Unix(seen.At, 0).Add(UpdateWait).UTC()
			status.UpdateVersion, status.UpdateInstallableFrom = seen.Version, &from
		}
	}
	return status, nil
}

// zoneName describes the device's time zone: "UTC", "EEST (UTC+3)".
func zoneName(now time.Time) string {
	name, offset := now.Zone()
	if offset == 0 {
		return name
	}
	sign := "+"
	if offset < 0 {
		sign, offset = "-", -offset
	}
	text := fmt.Sprintf("UTC%s%d", sign, offset/3600)
	if minutes := offset % 3600 / 60; minutes != 0 {
		text += fmt.Sprintf(":%02d", minutes)
	}
	if name == "" || strings.HasPrefix(name, "+") || strings.HasPrefix(name, "-") {
		return text
	}
	return name + " (" + text + ")"
}

// minutes reads "HH:MM" as minutes since midnight.
func minutes(text string) (int, bool) {
	if len(text) != 5 || text[2] != ':' {
		return 0, false
	}
	hours, err1 := strconv.Atoi(text[:2])
	mins, err2 := strconv.Atoi(text[3:])
	if err1 != nil || err2 != nil || hours < 0 || hours > 23 || mins < 0 || mins > 59 {
		return 0, false
	}
	return hours*60 + mins, true
}

// inWindow reports whether now lies in the window. A window whose end is
// earlier than its start runs over midnight.
func inWindow(now time.Time, start, end string) bool {
	from, ok1 := minutes(start)
	to, ok2 := minutes(end)
	if !ok1 || !ok2 || from == to {
		return false
	}
	at := now.Hour()*60 + now.Minute()
	if from < to {
		return at >= from && at < to
	}
	return at >= from || at < to
}

// --- Settings the owner makes ---------------------------------------------------------

// Set switches the window on or off and sets its times.
func (s *Service) Set(ctx context.Context, actor, remote string, enabled bool, start, end string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	from, ok1 := minutes(start)
	to, ok2 := minutes(end)
	switch {
	case !ok1 || !ok2:
		return &InputError{"Give both times as hours and minutes, like 04:00."}
	case from == to:
		return &InputError{"The window must end at another time than it begins."}
	}
	for key, value := range map[string]string{SettingEnabled: strconv.FormatBool(enabled), SettingStart: start, SettingEnd: end} {
		if err := store.SetSetting(ctx, s.cfg.DB, key, value); err != nil {
			return err
		}
	}
	detail := "maintenance window switched off"
	if enabled {
		detail = "maintenance window: every day from " + start + " to " + end
	}
	s.record(ctx, actor, audit.ActionSettingChanged, detail, remote)
	return nil
}

// SetAutoUpdate lets SGC's own updates install by themselves in the window,
// or not. Switching it on switches the daily look for new versions on as
// well: without it there would never be anything to install.
func (s *Service) SetAutoUpdate(ctx context.Context, actor, remote string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled {
		if err := s.cfg.Updates.SetAutoCheck(ctx, true); err != nil {
			return err
		}
	}
	if err := store.SetSetting(ctx, s.cfg.DB, SettingAutoUpdate, strconv.FormatBool(enabled)); err != nil {
		return err
	}
	detail := "SGC's own updates are installed by hand again"
	if enabled {
		detail = "SGC's own updates install by themselves in the maintenance window"
	}
	s.record(ctx, actor, audit.ActionSettingChanged, detail, remote)
	return nil
}

// --- What happens in the window -----------------------------------------------------------

// Run looks at the window twice a minute until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		s.tick(ctx)
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tick does at most one thing. The caller holds the lock.
func (s *Service) tick(ctx context.Context) {
	now := s.cfg.Now()
	// Noted all the time, window or not, so that the three days are counted
	// from when the version first appeared.
	latest := s.noteLatest(ctx, now)

	cfg, err := s.settings(ctx)
	if err != nil || !cfg.enabled || !inWindow(now, cfg.start, cfg.end) {
		return
	}
	if uptime, err := s.cfg.Uptime(); err != nil || uptime < quietAfterStart.Seconds() {
		return
	}
	if !s.cfg.ClockSynchronised() || s.cfg.Installing() {
		return
	}

	// SGC's own update first: it restarts SGC, not the device, and a restart
	// of the device that is also due follows at the next look.
	if cfg.autoUpdate && latest.Version != "" && now.Sub(time.Unix(latest.At, 0)) >= UpdateWait &&
		now.Sub(s.moment(ctx, settingLastUpdateTry)) >= oncePer {
		s.update(ctx, now, latest.Version)
		return
	}

	needed, packages := s.cfg.RestartNeeded()
	if !needed || now.Sub(s.moment(ctx, settingLastRestart)) < oncePer {
		return
	}
	// Not while Debian's own daily run is installing something.
	if device, err := s.cfg.Helper.OSUpdateSettings(ctx); err != nil || device.DailyRunning {
		return
	}
	// Written down before the restart, and the restart is not asked for if
	// that fails: whatever else goes wrong, this cannot become a device that
	// restarts over and over.
	if err := s.setMoment(ctx, settingLastRestart, now); err != nil {
		s.cfg.Log.Error("note the restart", "error", err)
		return
	}
	detail := "in the maintenance window"
	if len(packages) > 0 {
		detail += ", needed by " + strings.Join(packages, ", ")
	}
	s.record(ctx, audit.ActorSystem, audit.ActionDeviceRestart, detail, "")
	s.cfg.Log.Info("restarting the device in the maintenance window", "packages", packages)
	if err := s.cfg.Helper.RestartDevice(ctx); err != nil {
		s.cfg.Log.Error("restart the device", "error", err)
		s.record(ctx, audit.ActorSystem, audit.ActionDeviceRestartFailed, detail, "")
	}
}

// update installs SGC's newest version the way the button does: download and
// verify without privileges, then hand over to the root updater, which
// verifies again and rolls back if the new version does not come up.
func (s *Service) update(ctx context.Context, now time.Time, version string) {
	if err := s.setMoment(ctx, settingLastUpdateTry, now); err != nil {
		s.cfg.Log.Error("note the update attempt", "error", err)
		return
	}
	detail := "to " + version + ", by itself in the maintenance window"
	s.record(ctx, audit.ActorSystem, audit.ActionUpdateStarted, detail, "")
	if err := s.cfg.Updates.Fetch(ctx, version); err != nil {
		s.cfg.Log.Error("download the update", "version", version, "error", err)
		s.record(ctx, audit.ActorSystem, audit.ActionUpdateFailed, "to "+version+": "+err.Error()+". Nothing was changed.", "")
		return
	}
	if err := s.cfg.Helper.StartUpdate(ctx, version); err != nil {
		s.cfg.Log.Error("start the update", "version", version, "error", err)
		s.record(ctx, audit.ActorSystem, audit.ActionUpdateFailed, "to "+version+": the update could not be started. Nothing was changed.", "")
	}
}

// seen is what settingFirstSeen holds.
type seen struct {
	Version string `json:"version"`
	At      int64  `json:"at"`
}

func (s *Service) firstSeen(ctx context.Context) seen {
	var value seen
	if raw, _, err := store.Setting(ctx, s.cfg.DB, settingFirstSeen); err == nil && raw != "" {
		json.Unmarshal([]byte(raw), &value)
	}
	return value
}

// noteLatest remembers when the newest version first appeared, and returns
// it with that moment. It returns nothing while there is no newer version.
func (s *Service) noteLatest(ctx context.Context, now time.Time) seen {
	current, err := s.cfg.Updates.Status(ctx)
	if err != nil || !current.UpdateAvailable || current.Latest == "" {
		return seen{}
	}
	// Three days are only three days on a clock that is right.
	if !s.cfg.ClockSynchronised() {
		return seen{}
	}
	known := s.firstSeen(ctx)
	if known.Version == current.Latest && known.At > 0 && known.At <= now.Unix() {
		return known
	}
	known = seen{Version: current.Latest, At: now.Unix()}
	raw, _ := json.Marshal(known)
	if err := store.SetSetting(ctx, s.cfg.DB, settingFirstSeen, string(raw)); err != nil {
		s.cfg.Log.Error("note the new version", "error", err)
		return seen{} // not remembered, so not counted
	}
	return known
}

func (s *Service) moment(ctx context.Context, key string) time.Time {
	raw, _, err := store.Setting(ctx, s.cfg.DB, key)
	seconds, convErr := strconv.ParseInt(raw, 10, 64)
	if err != nil || convErr != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}

func (s *Service) setMoment(ctx context.Context, key string, at time.Time) error {
	if at.IsZero() {
		return errors.New("no time")
	}
	return store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, key, strconv.FormatInt(at.Unix(), 10))
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}
