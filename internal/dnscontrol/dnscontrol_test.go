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
	r.status = adguard.Status{Installed: true, Version: "0.107.79", Running: true}
	return nil
}

func (r *rootSide) AdguardRemove(context.Context) error {
	r.calls = append(r.calls, "remove")
	r.status = adguard.Status{}
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
	return entries[0].Actor + " " + entries[0].Action + " " + entries[0].Detail
}

func TestInstallAndRemove(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if s := e.status(); !s.Available || s.Installed || s.Wanted || s.Pinned != "0.107.79" {
		t.Fatalf("to begin with: %+v", s)
	}
	if err := e.service.Install(ctx, "alex", "192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	// The root side found the downloaded release, and nothing else.
	if got := strings.Join(e.root.spooled, " "); got != "adguardhome-0.107.79-arm64.tar.gz" {
		t.Errorf("in the spool at installation: %s", got)
	}
	if entries, _ := os.ReadDir(e.root.paths.SpoolDir); len(entries) != 0 {
		t.Errorf("left in the spool afterwards: %v", entries)
	}
	if s := e.status(); !s.Installed || !s.Running || s.UpdateAvailable || s.Wanted {
		t.Errorf("after installing: %+v", s)
	}
	if e.lastHistory() != "alex dns.installed AdGuard Home 0.107.79" {
		t.Errorf("history: %s", e.lastHistory())
	}
	// This SGC brings a newer release than the one installed.
	e.root.status.Version = "0.107.70"
	if s := e.status(); !s.UpdateAvailable {
		t.Errorf("with an older version installed: %+v", s)
	}

	if err := e.service.Remove(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Installed || s.Wanted {
		t.Errorf("after removing: %+v", s)
	}
	if e.lastHistory() != "alex dns.removed AdGuard Home" {
		t.Errorf("history: %s", e.lastHistory())
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
// export, handed to the root side when AdGuard Home is installed on the
// device the export was restored to.
func TestSettingsTravelWithAnExport(t *testing.T) {
	ctx := context.Background()
	old := newEnv(t)
	// Nothing installed: nothing to copy, and nothing is invented.
	if err := old.service.SaveForExport(ctx); err != nil {
		t.Fatal(err)
	}
	if kept, _, _ := store.Setting(ctx, old.db, SettingSettingsFile); kept != "" {
		t.Fatalf("settings kept without AdGuard Home: %q", kept)
	}
	if err := old.service.Install(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	old.root.settings = "user_rules:\n  - '||ads.domain.tld^'\n"
	if err := old.service.SaveForExport(ctx); err != nil {
		t.Fatal(err)
	}

	// The restored device: the two settings came with the database.
	fresh := newEnv(t)
	for _, key := range []string{SettingInstalled, SettingSettingsFile} {
		value, _, _ := store.Setting(ctx, old.db, key)
		store.SetSetting(ctx, fresh.db, key, value)
	}
	if s := fresh.status(); s.Installed || !s.Wanted || !s.RestoredSettings {
		t.Fatalf("on the restored device: %+v", s)
	}
	// Exporting again from there, before installing, keeps what came along.
	if err := fresh.service.SaveForExport(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fresh.service.Install(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	if fresh.root.restored != old.root.settings {
		t.Errorf("handed to the root side: %q", fresh.root.restored)
	}
	if _, err := os.Stat(fresh.root.paths.RestoredSettings()); !errors.Is(err, os.ErrNotExist) {
		t.Error("the handed-over settings were left in the spool")
	}
	if s := fresh.status(); !s.Installed || s.Wanted || s.RestoredSettings {
		t.Errorf("after installing there: %+v", s)
	}
}
