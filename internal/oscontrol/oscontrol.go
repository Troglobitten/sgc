// Package oscontrol is the web process's side of "updates for the device":
// Debian's packages, as opposed to SGC itself (internal/update).
//
// The web process installs nothing and writes no settings. It remembers how
// the owner wants the device to get its updates (which is what an export
// carries), asks the root helper to set that up, to look for updates and to
// install them, reads the report the root side keeps, and writes the
// history.
//
// What the root side does with those requests is in internal/osupdate.
package oscontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// SettingMode holds what the owner last chose: "automatic" or "by-hand".
	// It travels with an export. Like the firewall's setting it is not acted
	// on by itself on a restored machine: the page shows it, and setting the
	// new device up is the owner's step.
	SettingMode = "os_updates.mode"
	// SettingOpenInstall remembers an installation started here whose end is
	// not in the history yet. Bookkeeping of one installation; left out of
	// exports (internal/backup/tables.go).
	SettingOpenInstall = "os_updates.open_install"
)

const (
	// How often SGC looks for updates by itself, and how soon it tries again
	// after a look that failed (no connection, say).
	lookEvery  = 24 * time.Hour
	retryAfter = time.Hour
	// Not in the first minutes after start-up: the network may not be there
	// yet, and Debian's own daily run likes to start then.
	quietAfterStart = 5 * time.Minute
	// After the helper could not even start a look, leave it be for a while.
	startRetry = 15 * time.Minute
	// How many package names a history entry spells out.
	namesInHistory = 15
)

var (
	ErrBusy     = errors.New("a look for updates or an installation is already running")
	ErrNotSetUp = errors.New("choose first how this device gets its updates")
)

// ChangeError is a failed request with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

// Helper is what this package asks the root helper to do.
type Helper interface {
	InstallPackages(ctx context.Context, feature string) error
	OSUpdateSettings(ctx context.Context) (osupdate.Settings, error)
	OSUpdateSetMode(ctx context.Context, request osupdate.ModeRequest) error
	OSUpdateStart(ctx context.Context, job string) (int64, error)
}

type Config struct {
	DB     *sql.DB
	Helper Helper
	Audit  *audit.Log
	Paths  osupdate.Paths
	// Uptime is how long the device has been running, in seconds.
	Uptime func() (float64, error)
	Now    func() time.Time
	Log    *slog.Logger
}

type Service struct {
	cfg Config
	// One request to the root side at a time.
	mu sync.Mutex
	// Wakes Run up when an installation has been started.
	started chan struct{}
	// Not before this moment does Run ask for another look by itself.
	nextLook time.Time
}

func New(cfg Config) *Service {
	return &Service{cfg: cfg, started: make(chan struct{}, 1)}
}

// --- State as the interface shows it ----------------------------------------------

type Status struct {
	// Available is false when the root helper could not be asked. The rest
	// is then what the files say, without what only the helper knows.
	Available bool `json:"available"`
	// ToolInstalled is false on a device that has never had automatic
	// updates. Debian's tool is installed when the owner first chooses.
	ToolInstalled bool `json:"toolInstalled"`

	// Mode is how SGC has set this device up: "automatic", "by-hand", or
	// empty if the owner has not chosen here yet.
	Mode string `json:"mode"`
	// Wanted is what the owner last chose, here or on the device an export
	// came from. Wanted with Mode empty means: restored, not set up yet.
	Wanted string `json:"wanted"`
	// Daily: updates install by themselves on this device right now, whoever
	// arranged that. On a device the owner has not set up, this is what it
	// does of its own accord.
	Daily bool `json:"daily"`
	// Problem says why the device does not do what Mode says, if it does not.
	Problem string `json:"problem"`

	// LastRun is when Debian's own daily run last ran the update tool here.
	// What SGC starts does not count.
	LastRun *time.Time `json:"lastRun"`
	// Running is "check" or "install" while SGC has the tool running.
	Running string `json:"running"`
	// DailyRunning: Debian's own daily run is at work.
	DailyRunning bool `json:"dailyRunning"`

	// Waiting are the updates the latest look found, CheckedAt when that
	// was (nil: not looked since the device started), CheckError why the
	// latest look failed, if it did.
	CheckedAt  *time.Time `json:"checkedAt"`
	Waiting    []string   `json:"waiting"`
	CheckError string     `json:"checkError"`
	// LastInstall is the latest installation started from SGC's page.
	LastInstall *osupdate.Install `json:"lastInstall"`

	// RestartNeeded: an installed update takes effect only after a restart;
	// RestartPackages are the packages that said so.
	RestartNeeded   bool     `json:"restartNeeded"`
	RestartPackages []string `json:"restartPackages"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	// An installation that has ended is written into the history first, so
	// that the page and the history never tell two stories (see the same in
	// internal/sshcontrol).
	if s.mu.TryLock() {
		s.settle(ctx)
		s.mu.Unlock()
	}

	status := Status{Waiting: []string{}, RestartPackages: []string{}}
	wanted, _, err := store.Setting(ctx, s.cfg.DB, SettingMode)
	if err != nil {
		return status, err
	}
	status.Wanted = wanted

	mode, found, err := osupdate.ReadMode(s.cfg.Paths.ConfigFile)
	if err != nil {
		s.cfg.Log.Warn("read SGC's update settings file", "error", err)
	} else if found {
		status.Mode = string(mode)
	}

	report, err := osupdate.ReadReport(s.cfg.Paths)
	if err != nil {
		return status, fmt.Errorf("read the report on updates: %w", err)
	}
	status.Running = report.Running
	status.CheckedAt, status.Waiting, status.CheckError = report.CheckedAt, report.Waiting, report.CheckError
	status.LastInstall = report.LastInstall
	status.RestartNeeded, status.RestartPackages = osupdate.RestartNeeded(s.cfg.Paths)

	settings, err := s.cfg.Helper.OSUpdateSettings(ctx)
	if err != nil {
		s.cfg.Log.Warn("ask the helper about the device's update settings", "error", err)
		return status, nil
	}
	status.Available = true
	status.ToolInstalled = settings.ToolInstalled
	status.Daily = settings.Daily()
	status.LastRun = settings.LastRun
	status.DailyRunning = settings.DailyRunning
	status.Problem = problem(mode, found, settings)
	return status, nil
}

// problem says in words why the device does not do what SGC set it up to do.
func problem(mode osupdate.Mode, setUp bool, settings osupdate.Settings) string {
	switch {
	case !setUp:
		return ""
	case !settings.ToolInstalled:
		return "Debian's update tool (unattended-upgrades) is no longer on this device. Choose again below to put it back."
	case settings.Overridden != "":
		return "Another settings file on this device overrules SGC's (" + settings.Overridden +
			"). Look in /etc/apt/apt.conf.d for a file whose name sorts after 52sgc-updates."
	case mode == osupdate.Automatic && !settings.Timers:
		return "Debian's daily timers are not running, so nothing installs by itself. Choose \"by themselves\" again to start them."
	}
	return ""
}

// Installing reports whether an installation started from SGC's page is at
// work. The device should not be restarted in the middle of one.
func (s *Service) Installing() bool {
	report, err := osupdate.ReadReport(s.cfg.Paths)
	return err == nil && report.Running == osupdate.JobInstall
}

// --- Requests -------------------------------------------------------------------

// SetMode sets the device up so that updates install by themselves, or only
// when the owner starts them here. Choosing what is already chosen is
// allowed: it writes the settings again and starts Debian's timers if
// somebody stopped them.
func (s *Service) SetMode(ctx context.Context, actor, remote string, automatic bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	request := osupdate.ModeRequest{Automatic: automatic}
	action, detail := audit.ActionOSUpdatesByHand, "updates for the device are started in SGC's page"
	if automatic {
		action, detail = audit.ActionOSUpdatesAutomatic, "updates for the device install by themselves"
	}

	settings, err := s.cfg.Helper.OSUpdateSettings(ctx)
	if err != nil {
		s.cfg.Log.Error("ask the helper about the device's update settings", "error", err)
		return &ChangeError{"The device could not be asked about its update settings. Nothing was changed."}
	}
	if !settings.ToolInstalled {
		if err := s.cfg.Helper.InstallPackages(ctx, helper.PackagesUpdates); err != nil {
			s.cfg.Log.Error("install Debian's update tool", "error", err)
			return &ChangeError{"Debian's update tool (unattended-upgrades) could not be installed. " +
				"Check that this device can reach the internet, then try again. Nothing was changed."}
		}
		s.record(ctx, audit.ActorSystem, audit.ActionPackagesInstalled, "unattended-upgrades, from Debian, for the device's updates", "")
	}

	before, _, _ := osupdate.ReadModeOutcome(s.cfg.Paths)
	if err := s.cfg.Helper.OSUpdateSetMode(ctx, request); err != nil {
		s.cfg.Log.Error("set up the device's updates", "error", err)
		message := "That did not work. Nothing was changed."
		// The root side says why, in the record of how its last change ended.
		if after, found, readErr := osupdate.ReadModeOutcome(s.cfg.Paths); readErr == nil && found && after.Error != "" && !after.At.Equal(before.At) {
			message = "That did not work: " + after.Error + ". Nothing was changed."
		}
		s.record(ctx, actor, audit.ActionOSUpdatesChangeFailed, detail, remote)
		return &ChangeError{message}
	}
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingMode, string(request.Mode())); err != nil {
		return err
	}
	s.record(ctx, actor, action, detail, remote)
	// A device that has just been set up is looked at straight away: the
	// owner is on the page and wants to see what is waiting. If that cannot
	// be started now, the daily look gets to it.
	if _, err := s.start(ctx, osupdate.JobCheck); err != nil && !errors.Is(err, ErrBusy) {
		s.cfg.Log.Warn("look for updates after setting the device up", "error", err)
	}
	return nil
}

// Check starts a look for updates.
func (s *Service) Check(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.start(ctx, osupdate.JobCheck)
	return err
}

// Install starts the installation of what is waiting. It returns once the
// installation is running; how it ends is in the status and the history.
func (s *Service) Install(ctx context.Context, actor, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settle(ctx)
	id, err := s.start(ctx, osupdate.JobInstall)
	if err != nil {
		return err
	}
	open, _ := json.Marshal(openInstall{ID: id, Actor: actor, Remote: remote})
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingOpenInstall, string(open)); err != nil {
		s.cfg.Log.Error("remember the started installation", "error", err)
	}
	s.record(ctx, actor, audit.ActionOSUpdatesInstallStarted, "", remote)
	s.wake()
	return nil
}

func (s *Service) start(ctx context.Context, job string) (int64, error) {
	if _, found, err := osupdate.ReadMode(s.cfg.Paths.ConfigFile); err != nil || !found {
		// Until the owner has chosen, SGC runs no package tools on the device.
		return 0, ErrNotSetUp
	}
	if report, err := osupdate.ReadReport(s.cfg.Paths); err == nil && report.Running != "" {
		return 0, ErrBusy
	}
	id, err := s.cfg.Helper.OSUpdateStart(ctx, job)
	if err != nil {
		if strings.Contains(err.Error(), "already running") {
			return 0, ErrBusy
		}
		s.cfg.Log.Error("start a job for the device's updates", "job", job, "error", err)
		return 0, &ChangeError{"It could not be started. Details are in the SGC log."}
	}
	return id, nil
}

func (s *Service) wake() {
	select {
	case s.started <- struct{}{}:
	default:
	}
}

// --- What happens without the owner -----------------------------------------------

// openInstall is what SettingOpenInstall holds.
type openInstall struct {
	ID     int64  `json:"id"`
	Actor  string `json:"actor"`
	Remote string `json:"remote"`
}

// Run writes installations that have ended into the history, and looks for
// updates once a day on a device the owner has set up. It runs until ctx is
// cancelled.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		s.settle(ctx)
		s.lookIfDue(ctx)
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-s.started:
		case <-ticker.C:
		}
	}
}

// settle looks at the installation remembered as open and, if it has ended,
// writes how into the history. The caller holds the lock.
func (s *Service) settle(ctx context.Context) {
	raw, _, err := store.Setting(ctx, s.cfg.DB, SettingOpenInstall)
	if err != nil || raw == "" {
		return
	}
	var open openInstall
	if json.Unmarshal([]byte(raw), &open) != nil {
		s.clearOpenInstall(ctx)
		return
	}
	report, err := osupdate.ReadReport(s.cfg.Paths)
	if err != nil {
		s.cfg.Log.Error("read the report on updates", "error", err)
		return
	}
	last := report.LastInstall
	switch {
	case last != nil && last.ID == open.ID && last.Result == osupdate.ResultOK:
		s.record(ctx, audit.ActorSystem, audit.ActionOSUpdatesInstalled, installed(last.Packages)+", started by "+open.Actor, "")
	case last != nil && last.ID == open.ID:
		detail := last.Message
		if len(last.Packages) > 0 {
			detail += " Installed before that: " + installed(last.Packages) + "."
		}
		s.record(ctx, audit.ActorSystem, audit.ActionOSUpdatesInstallFailed, detail, "")
	case report.RunningID == open.ID:
		return // still at it
	default:
		// The report is kept in /run and knows nothing of this installation:
		// the device restarted in the middle of it.
		s.record(ctx, audit.ActorSystem, audit.ActionOSUpdatesInstallFailed,
			"The device restarted before the installation had finished. What is left installs with the next one.", "")
	}
	s.clearOpenInstall(ctx)
}

// installed puts a list of packages into words for the history.
func installed(packages []string) string {
	switch n := len(packages); {
	case n == 0:
		return "nothing was waiting"
	case n == 1:
		return "1 update: " + packages[0]
	case n > namesInHistory:
		return fmt.Sprintf("%d updates: %s and %d more", n, strings.Join(packages[:namesInHistory], ", "), n-namesInHistory)
	default:
		return fmt.Sprintf("%d updates: %s", n, strings.Join(packages, ", "))
	}
}

// lookIfDue asks for a look if the last one is a day old. Only on a device
// the owner has set up: until then SGC runs no package tools. The caller
// holds the lock.
func (s *Service) lookIfDue(ctx context.Context) {
	now := s.cfg.Now()
	if now.Before(s.nextLook) {
		return
	}
	if _, found, err := osupdate.ReadMode(s.cfg.Paths.ConfigFile); err != nil || !found {
		return
	}
	if uptime, err := s.cfg.Uptime(); err != nil || uptime < quietAfterStart.Seconds() {
		return
	}
	report, err := osupdate.ReadReport(s.cfg.Paths)
	if err != nil || report.Running != "" {
		return
	}
	switch {
	case report.CheckFailedAt != nil && now.Sub(*report.CheckFailedAt) < retryAfter:
		return
	case report.CheckFailedAt == nil && report.CheckedAt != nil && now.Sub(*report.CheckedAt) < lookEvery &&
		!s.dailyRunSince(*report.CheckedAt):
		return
	}
	if _, err := s.start(ctx, osupdate.JobCheck); err != nil {
		s.nextLook = now.Add(startRetry)
	}
}

// dailyRunSince reports whether Debian's own daily run has run the update
// tool since the given moment. What SGC last saw waiting is then out of date:
// most likely it has been installed.
func (s *Service) dailyRunSince(t time.Time) bool {
	info, err := os.Stat(s.cfg.Paths.StampFile)
	return err == nil && info.ModTime().After(t)
}

func (s *Service) clearOpenInstall(ctx context.Context) {
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingOpenInstall, ""); err != nil {
		s.cfg.Log.Error("forget the finished installation", "error", err)
	}
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}
