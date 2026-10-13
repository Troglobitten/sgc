// Package logcontrol is the web process's side of "logs in memory"
// (log2ram), for a device that runs from an SD card.
//
// log2ram is part of SGC: the installer installs Debian's package and leaves
// it switched off. Whether the device runs from an SD card is for the owner
// to say, with the switch in the page; SGC does not try to find out. This
// package asks the root helper to switch it, remembers the choice (which is
// what an export carries) and reports how log2ram is doing: waiting for a
// restart, in memory and how full, or left on the disk at start-up because
// the logs did not fit.
//
// What the root side does, and what happens when the logs do not fit, is in
// internal/log2ram.
package logcontrol

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"sync"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/log2ram"
	"github.com/Troglobitten/sgc/internal/store"
)

// SettingEnabled is the owner's choice: "true" for logs in memory. On a
// device restored from an export it is shown and not acted on: whether that
// device runs from an SD card is not something an export knows.
const SettingEnabled = "log2ram.enabled"

// Above four fifths, the space in memory counts as nearly full.
const nearlyFullNumerator, nearlyFullDenominator = 4, 5

// ChangeError is a failed request with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

// Helper is what this package asks the root helper to do.
type Helper interface {
	Log2ramStatus(ctx context.Context) (log2ram.Status, error)
	Log2ramSetEnabled(ctx context.Context, enabled bool) error
	InstallPackages(ctx context.Context, feature string) error
}

type Config struct {
	DB     *sql.DB
	Helper Helper
	Audit  *audit.Log
	Log    *slog.Logger
}

type Service struct {
	cfg Config
	// One change at a time.
	mu sync.Mutex
}

func New(cfg Config) *Service { return &Service{cfg: cfg} }

type Status struct {
	// Available is false when the root helper could not be asked.
	Available bool `json:"available"`
	Installed bool `json:"installed"`
	// Enabled is what the switch shows: log2ram takes the logs into memory
	// at start-up. Active: they are in memory right now.
	Enabled bool `json:"enabled"`
	Active  bool `json:"active"`
	// RestartNeeded: the two differ, and a restart of the device ends that.
	RestartNeeded bool `json:"restartNeeded"`
	// StartFailed: switched on, but at the last start-up the logs did not
	// fit in memory, and log2ram left them on the disk.
	StartFailed bool `json:"startFailed"`
	// NearlyFull: in memory, and more than four fifths of the space used.
	NearlyFull bool `json:"nearlyFull"`
	// Wanted: on on the device an export came from, not switched on here.
	Wanted bool `json:"wanted"`
	// SizeBytes is the space in memory, UsedBytes what the logs take (in
	// memory when Active, on the disk otherwise), Largest what takes most.
	SizeBytes int64           `json:"sizeBytes"`
	UsedBytes int64           `json:"usedBytes"`
	Largest   []log2ram.Entry `json:"largest"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	status := Status{Largest: []log2ram.Entry{}}
	wanted, _, err := store.Setting(ctx, s.cfg.DB, SettingEnabled)
	if err != nil {
		return status, err
	}
	device, err := s.cfg.Helper.Log2ramStatus(ctx)
	if err != nil {
		s.cfg.Log.Warn("ask the helper about log2ram", "error", err)
		return status, nil
	}
	status.Available = true
	status.Installed, status.Enabled, status.Active = device.Installed, device.Enabled, device.Active
	status.StartFailed = device.StartFailed
	status.RestartNeeded = device.Enabled != device.Active && !device.StartFailed
	status.SizeBytes, status.UsedBytes = device.SizeBytes, device.UsedBytes
	status.NearlyFull = device.Active && device.UsedBytes*nearlyFullDenominator >= device.SizeBytes*nearlyFullNumerator
	status.Wanted = wanted == "true" && !device.Enabled
	if device.Largest != nil {
		status.Largest = device.Largest
	}
	return status, nil
}

// SetEnabled switches logs in memory on or off; either takes effect when the
// device restarts. Switching on installs Debian's package first if it is not
// on this device: on one that was updated from a version that did not
// install it, or where the installer could not. An error means the device is
// as it was.
func (s *Service) SetEnabled(ctx context.Context, actor, remote string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, err := s.cfg.Helper.Log2ramStatus(ctx)
	if err != nil {
		s.cfg.Log.Error("ask the helper about log2ram", "error", err)
		return &ChangeError{"The device could not be asked about log2ram. Nothing was changed."}
	}
	if enabled && !device.Installed {
		if err := s.install(ctx); err != nil {
			return err
		}
	}
	if enabled || device.Installed {
		if err := s.cfg.Helper.Log2ramSetEnabled(ctx, enabled); err != nil {
			s.cfg.Log.Error("switch log2ram", "on", enabled, "error", err)
			if enabled {
				return &ChangeError{"Logs in memory could not be switched on: " + err.Error() + ". Nothing was changed."}
			}
			return &ChangeError{"Logs in memory could not be switched off: " + err.Error() + "."}
		}
	}
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingEnabled, strconv.FormatBool(enabled)); err != nil {
		return err
	}
	action := audit.ActionLog2ramSwitchedOff
	if enabled {
		action = audit.ActionLog2ramSwitchedOn
	}
	s.record(ctx, actor, action, "takes effect when the device restarts", remote)
	return nil
}

// EnsureInstalled installs Debian's log2ram package if it is not on this
// device, and leaves it switched off. It says whether it installed anything.
// The installer does this on a new device.
func (s *Service) EnsureInstalled(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, err := s.cfg.Helper.Log2ramStatus(ctx)
	if err != nil {
		return false, &ChangeError{"The device could not be asked about log2ram."}
	}
	if device.Installed {
		return false, nil
	}
	return true, s.install(ctx)
}

// install has Debian's package installed. The root side switches a freshly
// installed log2ram off again at once: Debian's package would otherwise take
// the logs into memory at the next start-up by itself.
func (s *Service) install(ctx context.Context) error {
	if err := s.cfg.Helper.InstallPackages(ctx, helper.PackagesLog2ram); err != nil {
		s.cfg.Log.Error("install log2ram", "error", err)
		return &ChangeError{"log2ram could not be installed from Debian. Check that this device can reach the internet, then try again. Nothing was changed."}
	}
	s.record(ctx, audit.ActorSystem, audit.ActionPackagesInstalled, "log2ram and rsync, from Debian, for logs in memory", "")
	return nil
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}
