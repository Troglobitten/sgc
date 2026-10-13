// Package dnscontrol is the web process's side of AdGuard Home.
//
// AdGuard Home is part of SGC: the installer installs it and switches it on,
// and in the page it is switched off and on, not installed and removed. This
// package downloads the pinned release and checks it, asks the root helper to
// install it or to switch it, and remembers the owner's choice (which is what
// an export carries, together with a copy of AdGuard Home's settings file).
// After a restore it puts those settings back into AdGuard Home.
//
// It does not configure AdGuard Home: after the first start its settings are
// the owner's, made in AdGuard Home's own page, which SGC serves behind its
// login (internal/web).
//
// What the root side does is in internal/adguard.
package dnscontrol

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/components"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// SettingEnabled is the owner's choice: "true" for DNS switched on,
	// "false" for switched off. Absent on a device where nobody chose yet (one
	// that was updated from a version that did not install AdGuard Home).
	SettingEnabled = "adguard.enabled"
	// SettingInstalled is what SGC 0.11.0 wrote instead, when AdGuard Home
	// was installed and removed with buttons. It is only read: in a database
	// or an export of that version, "true" counts as switched on.
	SettingInstalled = "adguard.installed"
	// SettingSettingsFile holds AdGuard Home's settings file as it was at
	// the last export. It is how the owner's DNS settings travel.
	SettingSettingsFile = "adguard.settings_file"
	// SettingRestorePending is "true" from the moment an export was restored
	// until its DNS part is in place on this device. Bookkeeping of one
	// installation; an export does not carry it.
	SettingRestorePending = "adguard.restore_pending"
)

// ChangeError is a failed request with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

// Helper is what this package asks the root helper to do.
type Helper interface {
	AdguardStatus(ctx context.Context) (adguard.Status, error)
	AdguardInstall(ctx context.Context) error
	AdguardSetEnabled(ctx context.Context, enabled bool) error
	AdguardApplySettings(ctx context.Context) error
	AdguardSettings(ctx context.Context) (string, error)
}

type Config struct {
	DB        *sql.DB
	Helper    Helper
	Audit     *audit.Log
	Paths     adguard.Paths
	Component components.Component
	Arch      string
	// HTTP fetches the release. Its timeout bounds the whole download.
	HTTP *http.Client
	Log  *slog.Logger
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
	// Installed: the program is on this device. Enabled: it is switched on,
	// which is what the switch in the page shows. Running: it runs right now.
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Version   string `json:"version"`
	Running   bool   `json:"running"`
	// Pinned is the version this SGC installs. A different installed
	// version means: this SGC brings a newer AdGuard Home.
	Pinned          string `json:"pinned"`
	UpdateAvailable bool   `json:"updateAvailable"`
	// RestorePending: this SGC was restored from an export, and the DNS part
	// of that export is not in place on this device yet.
	RestorePending bool `json:"restorePending"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	status := Status{Pinned: s.cfg.Component.Version}
	pending, _, err := store.Setting(ctx, s.cfg.DB, SettingRestorePending)
	if err != nil {
		return status, err
	}
	status.RestorePending = pending == "true"
	device, err := s.cfg.Helper.AdguardStatus(ctx)
	if err != nil {
		s.cfg.Log.Warn("ask the helper about AdGuard Home", "error", err)
		return status, nil
	}
	status.Available = true
	status.Installed, status.Version, status.Running = device.Installed, device.Version, device.Running
	status.Enabled = device.Installed && device.Enabled
	status.UpdateAvailable = device.Installed && device.Version != status.Pinned
	return status, nil
}

// choice returns what the owner chose for DNS, and whether anything was
// chosen at all.
func (s *Service) choice(ctx context.Context) (enabled, known bool, err error) {
	for _, key := range []string{SettingEnabled, SettingInstalled} {
		value, found, err := store.Setting(ctx, s.cfg.DB, key)
		if err != nil {
			return false, false, err
		}
		if found && value != "" {
			return value == "true", true, nil
		}
	}
	return false, false, nil
}

// FirstInstallDue says whether this is a device on which nobody has decided
// about DNS yet and nobody could have: no choice is recorded and there is no
// admin account. That is a device the installer has just run on, and the
// installer then switches DNS on. A device updated from a version without
// AdGuard Home has an admin, and gets nothing installed unasked.
func (s *Service) FirstInstallDue(ctx context.Context, setupRequired bool) (bool, error) {
	_, known, err := s.choice(ctx)
	return setupRequired && !known, err
}

// SetEnabled switches DNS on or off. Switching on installs AdGuard Home
// first if it is not on this device: on one that was updated from a version
// that did not install it, or where the installer could not download it.
// An error means the device is as it was.
func (s *Service) SetEnabled(ctx context.Context, actor, remote string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, err := s.cfg.Helper.AdguardStatus(ctx)
	if err != nil {
		s.cfg.Log.Error("ask the helper about AdGuard Home", "error", err)
		return &ChangeError{"The device could not be asked about AdGuard Home. Nothing was changed."}
	}
	switch {
	case enabled && !device.Installed:
		if err := s.install(ctx); err != nil {
			return err
		}
		s.record(ctx, actor, audit.ActionDNSInstalled, "AdGuard Home "+s.cfg.Component.Version, remote)
	case enabled:
		if err := s.cfg.Helper.AdguardSetEnabled(ctx, true); err != nil {
			s.cfg.Log.Error("switch AdGuard Home on", "error", err)
			return &ChangeError{"DNS could not be switched on: " + err.Error() + "."}
		}
	case device.Installed:
		if err := s.cfg.Helper.AdguardSetEnabled(ctx, false); err != nil {
			s.cfg.Log.Error("switch AdGuard Home off", "error", err)
			return &ChangeError{"DNS could not be switched off: " + err.Error() + "."}
		}
	}
	if err := s.remember(ctx, enabled); err != nil {
		return err
	}
	action := audit.ActionDNSSwitchedOff
	if enabled {
		action = audit.ActionDNSSwitchedOn
	}
	s.record(ctx, actor, action, "", remote)
	return nil
}

// Install replaces the installed AdGuard Home with the release this SGC
// pins, when that is a newer one. An error means the device is as it was.
func (s *Service) Install(ctx context.Context, actor, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.install(ctx); err != nil {
		return err
	}
	// The root side starts what it installs.
	if err := s.remember(ctx, true); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDNSInstalled, "AdGuard Home "+s.cfg.Component.Version, remote)
	return nil
}

// install downloads the pinned release, checks it and has it installed and
// started.
func (s *Service) install(ctx context.Context) error {
	file, err := s.cfg.Component.File(s.cfg.Arch)
	if err != nil {
		return &ChangeError{"SGC has no AdGuard Home for this device's processor type."}
	}
	spooled := filepath.Join(s.cfg.Paths.SpoolDir, s.cfg.Component.SpoolName(s.cfg.Arch))
	defer os.Remove(spooled)
	if err := s.download(ctx, file, spooled); err != nil {
		s.cfg.Log.Error("download AdGuard Home", "error", err)
		if errors.Is(err, components.ErrWrongFile) {
			return &ChangeError{"The download of AdGuard Home was not the file SGC expects, and was thrown away. Nothing was changed."}
		}
		return &ChangeError{"AdGuard Home could not be downloaded. Check that this device can reach the internet, then try again. Nothing was changed."}
	}

	// On a device restored from an export, AdGuard Home starts from the
	// settings in that export. The root side uses them only if AdGuard Home
	// has no settings here yet.
	handed, err := s.handOverSettings(ctx)
	if err != nil {
		return err
	}
	if handed {
		defer os.Remove(s.cfg.Paths.RestoredSettings())
	}

	if err := s.cfg.Helper.AdguardInstall(ctx); err != nil {
		s.cfg.Log.Error("install AdGuard Home", "error", err)
		return &ChangeError{"AdGuard Home could not be installed: " + err.Error() + ". Nothing was changed."}
	}
	return nil
}

// handOverSettings puts the settings file an export brought along where the
// root side looks for it. It says whether there was one.
func (s *Service) handOverSettings(ctx context.Context) (bool, error) {
	kept, _, err := store.Setting(ctx, s.cfg.DB, SettingSettingsFile)
	if err != nil || kept == "" {
		return false, err
	}
	if err := os.MkdirAll(s.cfg.Paths.SpoolDir, 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(s.cfg.Paths.RestoredSettings(), []byte(kept), 0o600); err != nil {
		return false, fmt.Errorf("hand over the restored settings: %w", err)
	}
	return true, nil
}

func (s *Service) remember(ctx context.Context, enabled bool) error {
	return store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingEnabled, strconv.FormatBool(enabled))
}

// MarkRestored notes that an export has just been put in place, so that
// FinishRestore has work to do. It is called once, before anything else
// looks at the restored database.
func (s *Service) MarkRestored(ctx context.Context) error {
	return store.SetSetting(ctx, s.cfg.DB, SettingRestorePending, "true")
}

// FinishRestore makes AdGuard Home on this device what the restored export
// says: its settings are the ones from the export, and it is on or off as it
// was. It does nothing unless a restore is waiting for that, so it is called
// at every start: what failed once is tried again, and the page offers it
// too.
//
// The device a restore lands on normally has AdGuard Home already, installed
// with SGC and running on SGC's first settings.
func (s *Service) FinishRestore(ctx context.Context, actor, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pending, _, err := store.Setting(ctx, s.cfg.DB, SettingRestorePending); err != nil || pending != "true" {
		return err
	}
	enabled, known, err := s.choice(ctx)
	if err != nil {
		return err
	}
	device, err := s.cfg.Helper.AdguardStatus(ctx)
	if err != nil {
		s.cfg.Log.Error("ask the helper about AdGuard Home", "error", err)
		return &ChangeError{"The device could not be asked about AdGuard Home."}
	}

	detail := "AdGuard Home runs on the settings from the export"
	switch {
	case !known:
		// The export is from a device where nobody had chosen about DNS: it
		// says nothing. This device stays as the installer left it.
		if !device.Installed {
			return s.restoreDone(ctx)
		}
		enabled = device.Enabled
		detail = "the export says nothing about DNS; AdGuard Home stays as it is on this device"
	case !device.Installed && !enabled:
		detail = "DNS was switched off in the export and AdGuard Home is not on this device"
	case !device.Installed:
		// install hands the export's settings over itself.
		if err := s.install(ctx); err != nil {
			return err
		}
	default:
		handed, err := s.handOverSettings(ctx)
		if err != nil {
			return err
		}
		if handed {
			defer os.Remove(s.cfg.Paths.RestoredSettings())
			if err := s.cfg.Helper.AdguardApplySettings(ctx); err != nil {
				s.cfg.Log.Error("put the restored settings into AdGuard Home", "error", err)
				return &ChangeError{"The DNS settings from the export could not be put in place: " + err.Error() + "."}
			}
		} else {
			detail = "the export holds no settings for AdGuard Home; it keeps the ones on this device"
		}
		if device.Enabled != enabled {
			if err := s.cfg.Helper.AdguardSetEnabled(ctx, enabled); err != nil {
				s.cfg.Log.Error("switch AdGuard Home as in the export", "error", err)
				return &ChangeError{"DNS could not be switched as it was in the export: " + err.Error() + "."}
			}
		}
		if !enabled {
			detail += ", switched off as it was"
		}
	}
	if err := s.remember(ctx, enabled); err != nil {
		return err
	}
	if err := s.restoreDone(ctx); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDNSRestored, detail, remote)
	return nil
}

func (s *Service) restoreDone(ctx context.Context) error {
	return store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingRestorePending, "false")
}

// SaveForExport copies AdGuard Home's settings file into the database, so
// that the export about to be made carries the owner's DNS settings as they
// are now. Without AdGuard Home on this device there is nothing to copy, and
// what an earlier restore brought along stays.
func (s *Service) SaveForExport(ctx context.Context) error {
	// On a device where AdGuard Home was never installed there is nothing to
	// ask the root side about, and an export must not depend on it.
	if _, known, err := s.choice(ctx); err != nil || !known {
		return err
	}
	device, err := s.cfg.Helper.AdguardStatus(ctx)
	if err != nil {
		return fmt.Errorf("ask about AdGuard Home: %w", err)
	}
	if !device.Installed {
		return nil
	}
	settings, err := s.cfg.Helper.AdguardSettings(ctx)
	if err != nil {
		return fmt.Errorf("read AdGuard Home's settings: %w", err)
	}
	return store.SetSetting(ctx, s.cfg.DB, SettingSettingsFile, settings)
}

// download fetches the file and keeps it only if it is the pinned one.
func (s *Service) download(ctx context.Context, file components.File, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, file.URL, nil)
	if err != nil {
		return err
	}
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the download answered with status %d", resp.StatusCode)
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// One byte more than expected is enough to know that it is not the file.
	_, copyErr := io.Copy(out, io.LimitReader(resp.Body, file.Size+1))
	if err := out.Close(); copyErr == nil {
		copyErr = err
	}
	if copyErr != nil {
		os.Remove(dest)
		return copyErr
	}
	if err := components.Verify(dest, file); err != nil {
		os.Remove(dest)
		return err
	}
	return nil
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}
