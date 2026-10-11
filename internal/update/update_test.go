package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Troglobitten/sgc/internal/layout"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/release"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	installed = "1.0.0"
	arch      = "arm64"
)

// mirror is a pretend release server.
type mirror struct {
	t       *testing.T
	server  *httptest.Server
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	// What it serves; tests change these.
	latest map[string]any
	files  map[string][]byte // "v1.1.0/SHA256SUMS" -> content
	down   bool
	hits   int
}

func newMirror(t *testing.T) *mirror {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &mirror{t: t, private: private, public: public, files: map[string][]byte{}}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits++
		if m.down {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/latest.json" {
			json.NewEncoder(w).Encode(m.latest)
			return
		}
		data, ok := m.files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(m.server.Close)
	return m
}

// publish makes version the newest release, signed with signer.
func (m *mirror) publish(version string, archive []byte, signer ed25519.PrivateKey) {
	name := release.ArchiveName(version, arch)
	sum := sha256.Sum256(archive)
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	m.files["v"+version+"/"+name] = archive
	m.files["v"+version+"/"+release.ChecksumsFile] = checksums
	m.files["v"+version+"/"+release.SignatureFile] = ed25519.Sign(signer, checksums)
	m.latest = map[string]any{
		"version":     version,
		"notes":       "What is new in " + version,
		"publishedAt": time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}
}

type clock struct{ t time.Time }

func newChecker(t *testing.T, m *mirror) (*Checker, *clock, string) {
	t.Helper()
	ctx := context.Background()
	stateDir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(stateDir, layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	source, err := MirrorSource(m.server.URL, "sgc-test")
	if err != nil {
		t.Fatal(err)
	}
	checker, err := NewChecker(Config{
		DB:             db,
		Source:         source,
		CurrentVersion: installed,
		Arch:           arch,
		TrustedKeys:    []ed25519.PublicKey{m.public},
		StateDir:       stateDir,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)}
	checker.now = func() time.Time { return c.t }
	return checker, c, stateDir
}

func TestBeforeAnyCheck(t *testing.T) {
	checker, _, _ := newChecker(t, newMirror(t))

	status, err := checker.Status(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	if status.Current != installed || status.Latest != "" || status.UpdateAvailable || status.CheckedAt != nil {
		t.Errorf("status = %+v", status)
	}
	if !status.AutoCheck {
		t.Error("the daily check should be on unless switched off")
	}
}

func TestCheckFindsANewerRelease(t *testing.T) {
	m := newMirror(t)
	m.publish("1.1.0", []byte("archive"), m.private)
	checker, c, _ := newChecker(t, m)

	status, err := checker.Check(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	if !status.UpdateAvailable || status.Latest != "1.1.0" || status.Notes != "What is new in 1.1.0" {
		t.Errorf("status = %+v", status)
	}
	if status.CheckedAt == nil || !status.CheckedAt.Equal(c.t) || status.CheckError != "" {
		t.Errorf("check time or error wrong: %+v", status)
	}
	if status.PublishedAt == nil || status.PublishedAt.Year() != 2026 {
		t.Errorf("published = %v", status.PublishedAt)
	}
}

func TestNoUpdateWhenTheNewestIsInstalledOrOlder(t *testing.T) {
	for _, version := range []string{installed, "0.9.0"} {
		m := newMirror(t)
		m.publish(version, []byte("archive"), m.private)
		checker, _, _ := newChecker(t, m)

		status, err := checker.Check(context.Background())

		if err != nil {
			t.Fatal(err)
		}
		if status.UpdateAvailable || status.Notes != "" {
			t.Errorf("newest is %s, installed is %s: status = %+v", version, installed, status)
		}
	}
}

func TestAFailingCheckIsRememberedAndVisible(t *testing.T) {
	m := newMirror(t)
	m.publish("1.1.0", []byte("archive"), m.private)
	checker, c, _ := newChecker(t, m)
	ctx := context.Background()
	if _, err := checker.Check(ctx); err != nil {
		t.Fatal(err)
	}

	m.down = true
	c.t = c.t.Add(24 * time.Hour)
	status, err := checker.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.CheckError == "" || status.CheckFailedAt == nil || !status.CheckFailedAt.Equal(c.t) {
		t.Errorf("a failed check left no trace: %+v", status)
	}
	// What was known before stays known.
	if status.Latest != "1.1.0" || !status.UpdateAvailable {
		t.Errorf("earlier knowledge was lost: %+v", status)
	}

	m.down = false
	status, _ = checker.Check(ctx)
	if status.CheckError != "" || status.CheckFailedAt != nil {
		t.Errorf("a successful check did not clear the error: %+v", status)
	}
}

func TestAStrangeVersionFromTheNetworkIsRefused(t *testing.T) {
	m := newMirror(t)
	checker, _, _ := newChecker(t, m)
	for _, version := range []string{"", "latest", "1.1.0-beta", "1.1.0/../../etc", "v1.1.0"} {
		m.latest = map[string]any{"version": version}

		status, err := checker.Check(context.Background())

		if err != nil {
			t.Fatal(err)
		}
		if status.CheckError == "" || status.Latest != "" || status.UpdateAvailable {
			t.Errorf("version %q was accepted: %+v", version, status)
		}
	}
}

func TestFetchStoresAVerifiedDownload(t *testing.T) {
	m := newMirror(t)
	m.publish("1.1.0", []byte("the archive"), m.private)
	checker, _, stateDir := newChecker(t, m)
	ctx := context.Background()
	checker.Check(ctx)

	if err := checker.Fetch(ctx, "1.1.0"); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(stateDir, layout.SpoolFolder, "1.1.0")
	archive, err := os.ReadFile(filepath.Join(dir, release.ArchiveName("1.1.0", arch)))
	if err != nil || string(archive) != "the archive" {
		t.Errorf("archive in spool = %q, %v", archive, err)
	}
	for _, name := range []string{release.ChecksumsFile, release.SignatureFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s missing from the spool: %v", name, err)
		} else if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %o, want 600", name, info.Mode().Perm())
		}
	}
}

func TestFetchRefusals(t *testing.T) {
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name    string
		prepare func(m *mirror)
		version string
		want    error
	}{
		{
			name:    "signed by another key",
			prepare: func(m *mirror) { m.publish("1.1.0", []byte("archive"), attacker) },
			version: "1.1.0",
			want:    release.ErrBadSignature,
		},
		{
			name: "archive altered after signing",
			prepare: func(m *mirror) {
				m.publish("1.1.0", []byte("archive"), m.private)
				m.files["v1.1.0/"+release.ArchiveName("1.1.0", arch)] = []byte("something else")
			},
			version: "1.1.0",
			want:    release.ErrBadChecksum,
		},
		{
			name: "an older signed archive under the new version's address",
			prepare: func(m *mirror) {
				m.publish("1.0.5", []byte("old archive"), m.private)
				oldSums := m.files["v1.0.5/"+release.ChecksumsFile]
				oldSig := m.files["v1.0.5/"+release.SignatureFile]
				m.publish("1.1.0", []byte("new archive"), m.private)
				m.files["v1.1.0/"+release.ChecksumsFile] = oldSums
				m.files["v1.1.0/"+release.SignatureFile] = oldSig
				m.files["v1.1.0/"+release.ArchiveName("1.1.0", arch)] = []byte("old archive")
			},
			version: "1.1.0",
			want:    release.ErrNotListed,
		},
		{
			name:    "a version other than the newest",
			prepare: func(m *mirror) { m.publish("1.1.0", []byte("archive"), m.private) },
			version: "1.0.5",
			want:    ErrNotLatest,
		},
		{
			name:    "nothing newer exists",
			prepare: func(m *mirror) { m.publish(installed, []byte("archive"), m.private) },
			version: installed,
			want:    ErrNoUpdate,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMirror(t)
			tc.prepare(m)
			checker, _, stateDir := newChecker(t, m)
			ctx := context.Background()
			checker.Check(ctx)

			err := checker.Fetch(ctx, tc.version)

			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if entries, _ := os.ReadDir(filepath.Join(stateDir, layout.SpoolFolder)); len(entries) != 0 {
				t.Errorf("a refused download was left in the spool: %v", entries)
			}
		})
	}
}

func TestDailyCheckSchedule(t *testing.T) {
	m := newMirror(t)
	m.publish("1.1.0", []byte("archive"), m.private)
	checker, c, _ := newChecker(t, m)
	ctx := context.Background()

	due := func() bool {
		t.Helper()
		d, err := checker.checkDue(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	if !due() {
		t.Error("a check should be due when none was ever made")
	}
	checker.Check(ctx)
	if due() {
		t.Error("a check is due again right after one succeeded")
	}
	c.t = c.t.Add(23 * time.Hour)
	if due() {
		t.Error("a check is due after only 23 hours")
	}
	c.t = c.t.Add(2 * time.Hour)
	if !due() {
		t.Error("a check should be due after a day")
	}

	// A failed attempt also counts: a source that is down is asked once a
	// day, not once an hour.
	m.down = true
	checker.Check(ctx)
	if due() {
		t.Error("a check is due again right after one failed")
	}

	// Switched off means never due.
	c.t = c.t.Add(48 * time.Hour)
	if err := checker.SetAutoCheck(ctx, false); err != nil {
		t.Fatal(err)
	}
	if due() {
		t.Error("a check is due although the daily check is switched off")
	}
	if status, _ := checker.Status(ctx); status.AutoCheck {
		t.Error("status still reports the daily check as on")
	}
	checker.SetAutoCheck(ctx, true)
	if !due() {
		t.Error("switching the daily check back on did not make it due")
	}
}

func TestUpdateSourceAddressRules(t *testing.T) {
	for _, address := range []string{"https://updates.example.org/sgc", "http://127.0.0.1:9000", "http://localhost:9000", "http://[::1]:9000"} {
		if _, err := MirrorSource(address, "t"); err != nil {
			t.Errorf("%s was refused: %v", address, err)
		}
	}
	for _, address := range []string{"http://updates.example.org", "http://192.168.1.5:9000", "ftp://example.org", "not an address", ""} {
		if _, err := MirrorSource(address, "t"); err == nil {
			t.Errorf("%s was accepted; plain http to another machine must be refused", address)
		}
	}
}

func TestGitHubAnswerIsUnderstood(t *testing.T) {
	// The fields SGC relies on, as GitHub returns them.
	answer := `{"tag_name":"v0.5.1","name":"SGC 0.5.1","draft":false,"prerelease":false,
		"published_at":"2026-10-11T00:06:32Z","body":"Fixes a thing."}`
	source := GitHubSource("owner/repo", "t")

	parsed, err := source.parseLatest([]byte(answer))

	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != "0.5.1" || parsed.Notes != "Fixes a thing." || parsed.PublishedAt.Year() != 2026 {
		t.Errorf("parsed = %+v", parsed)
	}
	if got := source.fileURL("0.5.1", "SHA256SUMS"); got != "https://github.com/owner/repo/releases/download/v0.5.1/SHA256SUMS" {
		t.Errorf("download address = %s", got)
	}
}
