// Package dnscontrol is the web process's side of AdGuard Home.
//
// The web process downloads the pinned release and checks it, asks the root
// helper to install or remove it, and remembers that the owner wanted it
// (which is what an export carries, together with a copy of AdGuard Home's
// settings file). It does not configure AdGuard Home: after the first start
// its settings are the owner's, made in AdGuard Home's own page, which SGC
// serves behind its login (internal/web).
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
	"sync"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/components"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// SettingInstalled is "true" once the owner has installed AdGuard Home,
	// here or on the device an export came from. On a restored device it is
	// shown and not acted on: installing is the owner's step there too.
	SettingInstalled = "adguard.installed"
	// SettingSettingsFile holds AdGuard Home's settings file as it was at
	// the last export. It is how the owner's DNS settings travel: a device
	// restored from the export starts its AdGuard Home from them.
	SettingSettingsFile = "adguard.settings_file"
)

// ChangeError is a failed request with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

// Helper is what this package asks the root helper to do.
type Helper interface {
	AdguardStatus(ctx context.Context) (adguard.Status, error)
	AdguardInstall(ctx context.Context) error
	AdguardRemove(ctx context.Context) error
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
	// One installation or removal at a time.
	mu sync.Mutex
}

func New(cfg Config) *Service { return &Service{cfg: cfg} }

type Status struct {
	// Available is false when the root helper could not be asked.
	Available bool   `json:"available"`
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	Running   bool   `json:"running"`
	// Pinned is the version this SGC installs. A different installed
	// version means: this SGC brings a newer AdGuard Home.
	Pinned          string `json:"pinned"`
	UpdateAvailable bool   `json:"updateAvailable"`
	// Wanted: installed on the device an export came from, not here yet.
	Wanted bool `json:"wanted"`
	// RestoredSettings: settings from that export are kept and will be what
	// AdGuard Home starts with here.
	RestoredSettings bool `json:"restoredSettings"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	status := Status{Pinned: s.cfg.Component.Version}
	wanted, _, err := store.Setting(ctx, s.cfg.DB, SettingInstalled)
	if err != nil {
		return status, err
	}
	kept, _, err := store.Setting(ctx, s.cfg.DB, SettingSettingsFile)
	if err != nil {
		return status, err
	}
	device, err := s.cfg.Helper.AdguardStatus(ctx)
	if err != nil {
		s.cfg.Log.Warn("ask the helper about AdGuard Home", "error", err)
		return status, nil
	}
	status.Available = true
	status.Installed, status.Version, status.Running = device.Installed, device.Version, device.Running
	status.UpdateAvailable = device.Installed && device.Version != status.Pinned
	status.Wanted = wanted == "true" && !device.Installed
	status.RestoredSettings = kept != "" && !device.Installed
	return status, nil
}

// Install downloads the pinned release, checks it and has it installed and
// started. With a newer release pinned than the one installed, it replaces
// the installed one. An error means the device is as it was.
func (s *Service) Install(ctx context.Context, actor, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	if kept, _, err := store.Setting(ctx, s.cfg.DB, SettingSettingsFile); err == nil && kept != "" {
		if err := os.WriteFile(s.cfg.Paths.RestoredSettings(), []byte(kept), 0o600); err != nil {
			return fmt.Errorf("hand over the restored settings: %w", err)
		}
		defer os.Remove(s.cfg.Paths.RestoredSettings())
	}

	if err := s.cfg.Helper.AdguardInstall(ctx); err != nil {
		s.cfg.Log.Error("install AdGuard Home", "error", err)
		return &ChangeError{"AdGuard Home could not be installed: " + err.Error() + ". Nothing was changed."}
	}
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingInstalled, "true"); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDNSInstalled, "AdGuard Home "+s.cfg.Component.Version, remote)
	return nil
}

// Remove stops AdGuard Home and takes the program away. Its settings stay
// on the device.
func (s *Service) Remove(ctx context.Context, actor, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cfg.Helper.AdguardRemove(ctx); err != nil {
		s.cfg.Log.Error("remove AdGuard Home", "error", err)
		return &ChangeError{"AdGuard Home could not be removed: " + err.Error() + "."}
	}
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingInstalled, "false"); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDNSRemoved, "AdGuard Home", remote)
	return nil
}

// SaveForExport copies AdGuard Home's settings file into the database, so
// that the export about to be made carries the owner's DNS settings as they
// are now. Without AdGuard Home on this device there is nothing to copy, and
// what an earlier restore brought along stays.
func (s *Service) SaveForExport(ctx context.Context) error {
	// On a device where AdGuard Home was never installed there is nothing to
	// ask the root side about, and an export must not depend on it.
	if wanted, _, err := store.Setting(ctx, s.cfg.DB, SettingInstalled); err != nil {
		return err
	} else if wanted != "true" {
		return nil
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
