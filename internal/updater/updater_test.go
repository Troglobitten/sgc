package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/Troglobitten/sgc/internal/layout"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/release"
)

// fakeServices records what the updater asked systemd to do.
type fakeServices struct {
	calls []string
	fail  map[string]error // call (e.g. "start sgc.service") -> error to return
}

func (f *fakeServices) do(call string) error {
	f.calls = append(f.calls, call)
	return f.fail[call]
}
func (f *fakeServices) Stop(unit string) error    { return f.do("stop " + unit) }
func (f *fakeServices) Start(unit string) error   { return f.do("start " + unit) }
func (f *fakeServices) Restart(unit string) error { return f.do("restart " + unit) }
func (f *fakeServices) DaemonReload() error       { return f.do("daemon-reload") }

// env is a pretend installation in a temporary folder, at version 1.0.0.
type env struct {
	t        *testing.T
	cfg      Config
	services *fakeServices
	private  ed25519.PrivateKey
	// healthy decides whether a version "comes up"; by default all do.
	healthy func(version string) error
}

const (
	oldVersion = "1.0.0"
	newVersion = "1.1.0"
	testArch   = "arm64"
)

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, services: &fakeServices{fail: map[string]error{}}, private: private}
	e.healthy = func(string) error { return nil }
	e.cfg = Config{
		CurrentVersion: oldVersion,
		Arch:           testArch,
		TrustedKeys:    []ed25519.PublicKey{public},
		InstallRoot:    filepath.Join(root, "opt"),
		UnitDir:        filepath.Join(root, "units"),
		WorkDir:        filepath.Join(root, "work"),
		StateDir:       filepath.Join(root, "state"),
		SpoolDir:       filepath.Join(root, "state", "updates"),
		OwnerUID:       os.Getuid(),
		OwnerGID:       os.Getgid(),
		Services:       e.services,
		Healthy:        func(_ context.Context, version string) error { return e.healthy(version) },
		Now:            time.Now,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// The installed 1.0.0.
	e.write(filepath.Join(e.cfg.InstallRoot, "releases", oldVersion, "sgc"), "old sgc", 0o755)
	e.write(filepath.Join(e.cfg.InstallRoot, "releases", oldVersion, "sgc-helper"), "old helper", 0o755)
	if err := os.Symlink(filepath.Join("releases", oldVersion), filepath.Join(e.cfg.InstallRoot, "current")); err != nil {
		t.Fatal(err)
	}
	e.write(filepath.Join(e.cfg.UnitDir, "sgc.service"), "old unit", 0o644)
	e.write(filepath.Join(e.cfg.StateDir, layout.DatabaseFile), "old database", 0o600)
	return e
}

func (e *env) write(path, content string, mode os.FileMode) {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(path string) string {
	e.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(data)
}

func (e *env) current() string {
	e.t.Helper()
	target, err := os.Readlink(filepath.Join(e.cfg.InstallRoot, "current"))
	if err != nil {
		e.t.Fatal(err)
	}
	return target
}

type tarEntry struct {
	name     string
	content  string
	typeflag byte
}

func makeArchive(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Mode: 0o644, Size: int64(len(entry.content)), Typeflag: typeflag}
		if typeflag != tar.TypeReg {
			header.Size = 0
			header.Linkname = entry.content
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if typeflag == tar.TypeReg {
			tw.Write([]byte(entry.content))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func goodRelease() []tarEntry {
	return []tarEntry{
		{name: "sgc", content: "new sgc"},
		{name: "sgc-helper", content: "new helper"},
		{name: "sgc.service", content: "new unit"},
		{name: "sgc-update@.service", content: "a unit the old version did not have"},
	}
}

// publish puts a signed release for version into the spool folder, the way
// the web process would after downloading it.
func (e *env) publish(version string, entries []tarEntry, signer ed25519.PrivateKey) {
	e.t.Helper()
	archive := makeArchive(e.t, entries)
	name := release.ArchiveName(version, testArch)
	sum := sha256.Sum256(archive)
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	spool := filepath.Join(e.cfg.SpoolDir, version)
	e.write(filepath.Join(spool, name), string(archive), 0o600)
	e.write(filepath.Join(spool, release.ChecksumsFile), string(checksums), 0o600)
	e.write(filepath.Join(spool, release.SignatureFile), string(ed25519.Sign(signer, checksums)), 0o600)
}

// expectUntouched checks that the installation is exactly as newEnv left it.
func (e *env) expectUntouched() {
	e.t.Helper()
	if got := e.current(); got != filepath.Join("releases", oldVersion) {
		e.t.Errorf("current -> %s, want the old release", got)
	}
	if got := e.read(filepath.Join(e.cfg.UnitDir, "sgc.service")); got != "old unit" {
		e.t.Errorf("unit file = %q, want the old one", got)
	}
	if got := e.read(filepath.Join(e.cfg.StateDir, layout.DatabaseFile)); got != "old database" {
		e.t.Errorf("database = %q, want the old one", got)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.UnitDir, "sgc-update@.service")); !errors.Is(err, os.ErrNotExist) {
		e.t.Error("a unit introduced by the failed update was left behind")
	}
}

func TestSuccessfulUpdate(t *testing.T) {
	e := newEnv(t)
	e.publish(newVersion, goodRelease(), e.private)

	status := Run(context.Background(), e.cfg, newVersion)

	if status.State != StateSucceeded || !status.Changed {
		t.Fatalf("status = %+v", status)
	}
	if got := e.current(); got != filepath.Join("releases", newVersion) {
		t.Errorf("current -> %s, want the new release", got)
	}
	newDir := filepath.Join(e.cfg.InstallRoot, "releases", newVersion)
	if got := e.read(filepath.Join(newDir, "sgc")); got != "new sgc" {
		t.Errorf("installed program = %q", got)
	}
	for name, want := range map[string]os.FileMode{"sgc": 0o755, "sgc-helper": 0o755, "sgc.service": 0o644} {
		info, err := os.Stat(filepath.Join(newDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s has mode %o, want %o", name, info.Mode().Perm(), want)
		}
	}
	if got := e.read(filepath.Join(e.cfg.UnitDir, "sgc.service")); got != "new unit" {
		t.Errorf("unit file = %q, want the new one", got)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.UnitDir, "sgc-update@.service")); err != nil {
		t.Errorf("new unit was not installed: %v", err)
	}
	// The previous release stays for a manual rollback.
	if _, err := os.Stat(filepath.Join(e.cfg.InstallRoot, "releases", oldVersion, "sgc")); err != nil {
		t.Errorf("the previous release was removed: %v", err)
	}

	// SGC must be stopped before its database is copied and its programs
	// are swapped, and started only after systemd has re-read the units.
	want := []string{
		"stop sgc.service", "daemon-reload", "stop sgc-helper.service",
		"restart sgc-helper.socket", "start sgc.service",
	}
	if strings.Join(e.services.calls, ", ") != strings.Join(want, ", ") {
		t.Errorf("systemd calls = %v\nwant %v", e.services.calls, want)
	}

	recorded, err := ReadStatus(e.cfg.WorkDir)
	if err != nil || recorded == nil || recorded.State != StateSucceeded || recorded.ID != status.ID {
		t.Errorf("recorded status = %+v, err %v", recorded, err)
	}
}

func TestOlderReleasesAreCleanedUp(t *testing.T) {
	e := newEnv(t)
	e.write(filepath.Join(e.cfg.InstallRoot, "releases", "0.9.0", "sgc"), "ancient", 0o755)
	e.publish(newVersion, goodRelease(), e.private)

	Run(context.Background(), e.cfg, newVersion)

	if _, err := os.Stat(filepath.Join(e.cfg.InstallRoot, "releases", "0.9.0")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a release older than the previous one was kept")
	}
}

func TestNewVersionThatDoesNotStartIsRolledBack(t *testing.T) {
	e := newEnv(t)
	e.publish(newVersion, goodRelease(), e.private)
	e.healthy = func(version string) error {
		if version == newVersion {
			// The broken version got as far as changing the database.
			e.write(filepath.Join(e.cfg.StateDir, layout.DatabaseFile), "database changed by the broken version", 0o600)
			e.write(filepath.Join(e.cfg.StateDir, layout.DatabaseFile+"-wal"), "leftover", 0o600)
			return errors.New("no answer within 60 seconds")
		}
		return nil
	}

	status := Run(context.Background(), e.cfg, newVersion)

	if status.State != StateRolledBack {
		t.Fatalf("state = %q (%s), want %q", status.State, status.Message, StateRolledBack)
	}
	if !strings.Contains(status.Message, "went back to "+oldVersion) || !strings.Contains(status.Message, "no answer within 60 seconds") {
		t.Errorf("message does not explain what happened: %q", status.Message)
	}
	e.expectUntouched()
	if _, err := os.Stat(filepath.Join(e.cfg.StateDir, layout.DatabaseFile+"-wal")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a side file left by the broken version survived the rollback; it would corrupt the restored database")
	}
	if last := e.services.calls[len(e.services.calls)-1]; last != "start sgc.service" {
		t.Errorf("last systemd call = %q; SGC must be running again after a rollback", last)
	}
}

func TestNewVersionThatFailsToStartAtAllIsRolledBack(t *testing.T) {
	e := newEnv(t)
	e.publish(newVersion, goodRelease(), e.private)
	// Only the first start (of the new version) fails.
	starts := 0
	e.cfg.Services = startFailsOnce{Services: e.cfg.Services, count: &starts}

	status := Run(context.Background(), e.cfg, newVersion)

	if status.State != StateRolledBack {
		t.Fatalf("state = %q (%s), want %q", status.State, status.Message, StateRolledBack)
	}
	e.expectUntouched()
}

type startFailsOnce struct {
	Services
	count *int
}

func (s startFailsOnce) Start(unit string) error {
	*s.count++
	if *s.count == 1 {
		return errors.New("exit status 1")
	}
	return nil
}

func TestFailedRollbackIsReportedAsNeedingAttention(t *testing.T) {
	e := newEnv(t)
	e.publish(newVersion, goodRelease(), e.private)
	e.healthy = func(string) error { return errors.New("no answer") } // neither version comes up

	status := Run(context.Background(), e.cfg, newVersion)

	if status.State != StateFailed || !status.Changed {
		t.Fatalf("status = %+v, want failed with Changed set", status)
	}
	if !strings.Contains(status.Message, "needs attention") {
		t.Errorf("message = %q", status.Message)
	}
}

func TestRefusedWithoutTouchingAnything(t *testing.T) {
	_, attackerKey, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name    string
		version string
		prepare func(e *env)
		wantMsg string
	}{
		{
			name:    "signed by another key",
			version: newVersion,
			prepare: func(e *env) { e.publish(newVersion, goodRelease(), attackerKey) },
			wantMsg: "not signed by the SGC release key",
		},
		{
			name:    "archive altered after signing",
			version: newVersion,
			prepare: func(e *env) {
				e.publish(newVersion, goodRelease(), e.private)
				path := filepath.Join(e.cfg.SpoolDir, newVersion, release.ArchiveName(newVersion, testArch))
				e.write(path, e.read(path)+"x", 0o600)
			},
			wantMsg: "does not match its signed checksum",
		},
		{
			name:    "an older release offered as an update",
			version: "0.9.0",
			prepare: func(e *env) { e.publish("0.9.0", goodRelease(), e.private) },
			wantMsg: "not newer than the installed",
		},
		{
			name:    "the installed version offered again",
			version: oldVersion,
			prepare: func(e *env) { e.publish(oldVersion, goodRelease(), e.private) },
			wantMsg: "not newer than the installed",
		},
		{
			name:    "a genuine archive presented under a newer version",
			version: "1.2.0",
			prepare: func(e *env) {
				e.publish(newVersion, goodRelease(), e.private)
				os.Rename(filepath.Join(e.cfg.SpoolDir, newVersion), filepath.Join(e.cfg.SpoolDir, "1.2.0"))
			},
			wantMsg: "no such file", // the archive name contains the version
		},
		{
			name:    "version that is not a version",
			version: "1.1.0; reboot",
			prepare: func(e *env) {},
			wantMsg: "not a version",
		},
		{
			name:    "nothing downloaded",
			version: newVersion,
			prepare: func(e *env) {},
			wantMsg: "read the downloaded checksum list",
		},
		{
			name:    "release without the main program",
			version: newVersion,
			prepare: func(e *env) {
				e.publish(newVersion, []tarEntry{{name: "sgc-helper", content: "x"}}, e.private)
			},
			wantMsg: "does not contain sgc",
		},
		{
			name:    "archive with a path that leaves the release folder",
			version: newVersion,
			prepare: func(e *env) {
				entries := append(goodRelease(), tarEntry{name: "../../etc/cron.d/evil", content: "x"})
				e.publish(newVersion, entries, e.private)
			},
			wantMsg: "unexpected file name",
		},
		{
			name:    "archive with a symbolic link",
			version: newVersion,
			prepare: func(e *env) {
				entries := append(goodRelease(), tarEntry{name: "link", content: "/etc/shadow", typeflag: tar.TypeSymlink})
				e.publish(newVersion, entries, e.private)
			},
			wantMsg: "only plain files are allowed",
		},
		{
			name:    "checksum list replaced by a link to another file",
			version: newVersion,
			prepare: func(e *env) {
				e.publish(newVersion, goodRelease(), e.private)
				path := filepath.Join(e.cfg.SpoolDir, newVersion, release.ChecksumsFile)
				secret := filepath.Join(e.cfg.WorkDir, "root-only-secret")
				e.write(secret, "secret", 0o600)
				os.Remove(path)
				os.Symlink(secret, path)
			},
			wantMsg: "read the downloaded checksum list",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.prepare(e)

			status := Run(context.Background(), e.cfg, tc.version)

			if status.State != StateFailed || status.Changed {
				t.Errorf("status = %+v, want failed without changes", status)
			}
			if !strings.Contains(status.Message, tc.wantMsg) {
				t.Errorf("message = %q, want it to mention %q", status.Message, tc.wantMsg)
			}
			e.expectUntouched()
			if len(e.services.calls) != 0 {
				t.Errorf("systemd was touched: %v", e.services.calls)
			}
		})
	}
}

func TestOnlyOneUpdateAtATime(t *testing.T) {
	e := newEnv(t)
	e.publish(newVersion, goodRelease(), e.private)

	inside := make(chan struct{})
	proceed := make(chan struct{})
	e.healthy = func(string) error {
		close(inside)
		<-proceed
		return nil
	}
	first := make(chan Status, 1)
	go func() { first <- Run(context.Background(), e.cfg, newVersion) }()
	<-inside

	second := Run(context.Background(), e.cfg, newVersion)
	if second.State != StateFailed || !strings.Contains(second.Message, "already running") {
		t.Errorf("second update: %+v, want a refusal", second)
	}

	close(proceed)
	if status := <-first; status.State != StateSucceeded {
		t.Errorf("first update: %+v", status)
	}
	// The refused attempt must not have overwritten the real outcome.
	if recorded, _ := ReadStatus(e.cfg.WorkDir); recorded == nil || recorded.State != StateSucceeded {
		t.Errorf("recorded status = %+v, want the first update's success", recorded)
	}
}

func TestReadStatusWithoutAnyUpdate(t *testing.T) {
	status, err := ReadStatus(t.TempDir())
	if status != nil || err != nil {
		t.Errorf("got %+v, %v; want nil, nil", status, err)
	}
}
