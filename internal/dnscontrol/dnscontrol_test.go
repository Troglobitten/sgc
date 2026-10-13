package dnscontrol

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/components"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

// rootSide stands in for the root helper. At the moment it is asked to
// install, it looks at what the web process has put in the spool folder.
type rootSide struct {
	t        *testing.T
	paths    adguard.Paths
	status   adguard.Status
	calls    []string
	refuse   string
	settings string
	// What was in the spool folder when the installation was asked for.
	spooled  []string
	restored string
	// The settings from an export that were put into AdGuard Home.
	applied string
}

func (r *rootSide) AdguardStatus(context.Context) (adguard.Status, error) { return r.status, nil }

func (r *rootSide) AdguardInstall(context.Context) error {
	r.calls = append(r.calls, "install")
	entries, _ := os.ReadDir(r.paths.SpoolDir)
	r.spooled = nil
	for _, entry := range entries {
		r.spooled = append(r.spooled, entry.Name())
	}
	data, _ := os.ReadFile(r.paths.RestoredSettings())
	r.restored = string(data)
	if r.refuse != "" {
		return errors.New(r.refuse)
	}
	r.status = adguard.Status{Installed: true, Version: "0.107.79", Running: true, Enabled: true}
	return nil
}

func (r *rootSide) AdguardSetEnabled(_ context.Context, enabled bool) error {
	r.calls = append(r.calls, "enabled "+strconv.FormatBool(enabled))
	if r.refuse != "" {
		return errors.New(r.refuse)
	}
	r.status.Enabled, r.status.Running = enabled, enabled
	return nil
}

func (r *rootSide) AdguardApplySettings(context.Context) error {
	r.calls = append(r.calls, "apply-settings")
	if r.refuse != "" {
		return errors.New(r.refuse)
	}
	data, _ := os.ReadFile(r.paths.RestoredSettings())
	r.applied = string(data)
	return nil
}

func (r *rootSide) AdguardSettings(context.Context) (string, error) { return r.settings, nil }

type env struct {
	t       *testing.T
	db      *sql.DB
	root    *rootSide
	service *Service
	// What the download address serves.
	served []byte
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{t: t, db: db, served: []byte("the release of AdGuard Home")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(e.served) }))
	t.Cleanup(server.Close)
	sum := sha256.Sum256(e.served)
	paths := adguard.Paths{SpoolDir: filepath.Join(dir, "components")}
	e.root = &rootSide{t: t, paths: paths}
	e.service = New(Config{
		DB: db, Helper: e.root, Audit: audit.New(db), Paths: paths,
		Component: components.Component{Name: "adguardhome", Version: "0.107.79", Files: map[string]components.File{
			"arm64": {URL: server.URL + "/release.tar.gz", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(e.served))},
		}},
		Arch: "arm64",
		HTTP: server.Client(),
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
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

func (e *env) lastHistory() string {
	e.t.Helper()
	entries, err := audit.New(e.db).Recent(context.Background(), 1)
	if err != nil || len(entries) == 0 {
		return ""
	}
	return strings.TrimSpace(entries[0].Actor + " " + entries[0].Action + " " + entries[0].Detail)
}

func (e *env) setting(key string) string {
	e.t.Helper()
	value, _, err := store.Setting(context.Background(), e.db, key)
	if err != nil {
		e.t.Fatal(err)
	}
	return value
}

// hasAdguard makes this a device the installer has run on: AdGuard Home is
// there and switched on.
func (e *env) hasAdguard() {
	e.root.status = adguard.Status{Installed: true, Version: "0.107.79", Running: true, Enabled: true}
}

func TestSwitchingOnAndOff(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if s := e.status(); !s.Available || s.Installed || s.Enabled || s.Pinned != "0.107.79" {
		t.Fatalf("to begin with: %+v", s)
	}
	// A device the installer has just run on: nothing chosen, no admin yet.
	if due, err := e.service.FirstInstallDue(ctx, true); err != nil || !due {
		t.Errorf("on a new device: due %v, %v", due, err)
	}
	// A device that was updated from a version without AdGuard Home has an admin.
	if due, _ := e.service.FirstInstallDue(ctx, false); due {
		t.Error("due on a device that has an admin")
	}

	// Switched on where AdGuard Home is not yet: downloaded and installed.
	if err := e.service.SetEnabled(ctx, "alex", "192.168.1.10", true); err != nil {
		t.Fatal(err)
	}
	// The root side found the downloaded release, and nothing else.
	if got := strings.Join(e.root.spooled, " "); got != "adguardhome-0.107.79-arm64.tar.gz" {
		t.Errorf("in the spool at installation: %s", got)
	}
	if entries, _ := os.ReadDir(e.root.paths.SpoolDir); len(entries) != 0 {
		t.Errorf("left in the spool afterwards: %v", entries)
	}
	if s := e.status(); !s.Installed || !s.Enabled || !s.Running || s.UpdateAvailable {
		t.Errorf("after switching on: %+v", s)
	}
	if e.lastHistory() != "alex dns.switched_on" || e.setting(SettingEnabled) != "true" {
		t.Errorf("history: %s; setting: %s", e.lastHistory(), e.setting(SettingEnabled))
	}
	if due, _ := e.service.FirstInstallDue(ctx, true); due {
		t.Error("due again after the choice was made")
	}

	// This SGC brings a newer release than the one installed.
	e.root.status.Version = "0.107.70"
	if s := e.status(); !s.UpdateAvailable {
		t.Errorf("with an older version installed: %+v", s)
	}
	if err := e.service.Install(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.UpdateAvailable || e.lastHistory() != "alex dns.installed AdGuard Home 0.107.79" {
		t.Errorf("after replacing it: %+v, history: %s", s, e.lastHistory())
	}

	// Off: the program stays, nothing is downloaded or installed.
	e.served = []byte("a download now would be refused")
	installs := len(e.root.calls)
	if err := e.service.SetEnabled(ctx, "alex", "", false); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); !s.Installed || s.Enabled || s.Running {
		t.Errorf("switched off: %+v", s)
	}
	if e.lastHistory() != "alex dns.switched_off" || e.setting(SettingEnabled) != "false" {
		t.Errorf("history: %s; setting: %s", e.lastHistory(), e.setting(SettingEnabled))
	}
	// And on again.
	if err := e.service.SetEnabled(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); !s.Enabled || !s.Running {
		t.Errorf("switched on again: %+v", s)
	}
	if got := strings.Join(e.root.calls[installs:], ", "); got != "enabled false, enabled true" {
		t.Errorf("asked of the root side: %s", got)
	}

	// The root side cannot do it: said in words, and the choice stays as it was.
	e.root.refuse = "AdGuard Home could not be stopped: Unit is masked"
	var failure *ChangeError
	if err := e.service.SetEnabled(ctx, "alex", "", false); !errors.As(err, &failure) || !strings.Contains(failure.Message, "Unit is masked") {
		t.Errorf("a refusal: %v", err)
	}
	if e.setting(SettingEnabled) != "true" {
		t.Error("the choice was changed although the device was not")
	}
}

func TestADownloadThatIsNotThePinnedFileIsThrownAway(t *testing.T) {
	e := newEnv(t)
	e.served = []byte("the release of AdGuard Home, altered on the way")
	var failure *ChangeError
	err := e.service.Install(context.Background(), "alex", "")
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, "not the file SGC expects") {
		t.Fatalf("an altered download: %v", err)
	}
	// One byte short as well.
	e.served = []byte("the release of AdGuard Hom")
	if err := e.service.Install(context.Background(), "alex", ""); !errors.As(err, &failure) {
		t.Fatalf("a short download: %v", err)
	}
	if len(e.root.calls) != 0 {
		t.Errorf("the root side was asked: %v", e.root.calls)
	}
	if entries, _ := os.ReadDir(e.root.paths.SpoolDir); len(entries) != 0 {
		t.Errorf("the refused download was kept: %v", entries)
	}
	if e.status().Installed || e.lastHistory() != "" {
		t.Error("something was recorded as installed")
	}
}

func TestAnInstallationTheRootSideRefuses(t *testing.T) {
	e := newEnv(t)
	e.root.refuse = "another program on this device already answers DNS (port 53): systemd-resolve. It has to be switched off first"
	var failure *ChangeError
	err := e.service.Install(context.Background(), "alex", "")
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, "systemd-resolve") || !strings.Contains(failure.Message, "Nothing was changed") {
		t.Fatalf("a refusal: %v", err)
	}
	if wanted, _, _ := store.Setting(context.Background(), e.db, SettingInstalled); wanted != "" {
		t.Errorf("recorded as wanted: %q", wanted)
	}
}

// The owner's DNS settings travel in the database: copied in before an
// export, and put into the AdGuard Home of the device the export is restored
// to, without anybody asking.
func TestSettingsTravelWithAnExport(t *testing.T) {
	ctx := context.Background()
	old := newEnv(t)
	// Nothing chosen, nothing installed: nothing to copy, and nothing is invented.
	if err := old.service.SaveForExport(ctx); err != nil {
		t.Fatal(err)
	}
	if kept := old.setting(SettingSettingsFile); kept != "" {
		t.Fatalf("settings kept without AdGuard Home: %q", kept)
	}
	if err := old.service.SetEnabled(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	old.root.settings = "user_rules:\n  - '||ads.domain.tld^'\n"
	if err := old.service.SaveForExport(ctx); err != nil {
		t.Fatal(err)
	}
	// restoredTo makes a device on which the export has just been put in
	// place: what an export carries came with the database.
	restoredTo := func(settings map[string]string) *env {
		t.Helper()
		fresh := newEnv(t)
		for key, value := range settings {
			if err := store.SetSetting(ctx, fresh.db, key, value); err != nil {
				t.Fatal(err)
			}
		}
		return fresh
	}
	exported := map[string]string{SettingEnabled: old.setting(SettingEnabled), SettingSettingsFile: old.setting(SettingSettingsFile)}
	if exported[SettingEnabled] != "true" || exported[SettingSettingsFile] != old.root.settings {
		t.Fatalf("what the export carries: %v", exported)
	}

	// The usual case: the installer has put AdGuard Home on the new device,
	// running on SGC's first settings.
	fresh := restoredTo(exported)
	fresh.hasAdguard()
	// Without a restore there is nothing to finish.
	if err := fresh.service.FinishRestore(ctx, audit.ActorSystem, ""); err != nil || len(fresh.root.calls) != 0 {
		t.Fatalf("without a restore: %v, %v", err, fresh.root.calls)
	}
	if err := fresh.service.MarkRestored(ctx); err != nil {
		t.Fatal(err)
	}
	if !fresh.status().RestorePending {
		t.Error("the page is not told that the DNS part of the restore is still to do")
	}
	// The root side cannot do it now: it stays to do.
	fresh.root.refuse = "AdGuard Home could not be stopped"
	var failure *ChangeError
	if err := fresh.service.FinishRestore(ctx, audit.ActorSystem, ""); !errors.As(err, &failure) || !strings.Contains(failure.Message, "could not be put in place") {
		t.Errorf("a refusal: %v", err)
	}
	if !fresh.status().RestorePending {
		t.Error("a restore that failed is no longer waiting")
	}
	fresh.root.refuse = ""
	if err := fresh.service.FinishRestore(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	if fresh.root.applied != old.root.settings {
		t.Errorf("put into AdGuard Home: %q", fresh.root.applied)
	}
	if _, err := os.Stat(fresh.root.paths.RestoredSettings()); !errors.Is(err, os.ErrNotExist) {
		t.Error("the handed-over settings were left in the spool")
	}
	if s := fresh.status(); s.RestorePending || !s.Enabled {
		t.Errorf("after the restore: %+v", s)
	}
	if fresh.lastHistory() != "alex dns.restored AdGuard Home runs on the settings from the export" {
		t.Errorf("history: %s", fresh.lastHistory())
	}
	// Done is done.
	calls := len(fresh.root.calls)
	if err := fresh.service.FinishRestore(ctx, audit.ActorSystem, ""); err != nil || len(fresh.root.calls) != calls {
		t.Errorf("a second time: %v, %v", err, fresh.root.calls[calls:])
	}

	// Switched off in the export: its settings are put in place, and it is
	// off on the new device too.
	off := restoredTo(map[string]string{SettingEnabled: "false", SettingSettingsFile: old.root.settings})
	off.hasAdguard()
	off.service.MarkRestored(ctx)
	if err := off.service.FinishRestore(ctx, audit.ActorSystem, ""); err != nil {
		t.Fatal(err)
	}
	if s := off.status(); off.root.applied != old.root.settings || s.Enabled || s.RestorePending {
		t.Errorf("switched off in the export: applied %q, %+v", off.root.applied, s)
	}

	// An export of SGC 0.11.0, which noted "installed", on a device where the
	// installer could not download AdGuard Home: installed now, starting
	// from the export's settings.
	legacy := restoredTo(map[string]string{SettingInstalled: "true", SettingSettingsFile: old.root.settings})
	legacy.service.MarkRestored(ctx)
	if err := legacy.service.FinishRestore(ctx, audit.ActorSystem, ""); err != nil {
		t.Fatal(err)
	}
	if s := legacy.status(); legacy.root.restored != old.root.settings || !s.Enabled || s.RestorePending || legacy.setting(SettingEnabled) != "true" {
		t.Errorf("an export of 0.11.0: handed over %q, %+v", legacy.root.restored, s)
	}

	// An export that says nothing about DNS: the device stays as the
	// installer left it, and that becomes the choice, so that the next
	// export carries its settings.
	silent := restoredTo(nil)
	silent.hasAdguard()
	silent.service.MarkRestored(ctx)
	if err := silent.service.FinishRestore(ctx, audit.ActorSystem, ""); err != nil {
		t.Fatal(err)
	}
	if s := silent.status(); len(silent.root.calls) != 0 || !s.Enabled || s.RestorePending || silent.setting(SettingEnabled) != "true" {
		t.Errorf("an export without DNS: %v, %+v", silent.root.calls, s)
	}
	silent.root.settings = "settings made on the new device\n"
	if err := silent.service.SaveForExport(ctx); err != nil || silent.setting(SettingSettingsFile) != silent.root.settings {
		t.Errorf("the next export: %v, %q", err, silent.setting(SettingSettingsFile))
	}
}
