package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

// The files in testdata are exports written by earlier versions of SGC, one
// for each layout the database has had:
//
//	export-schema2.age   SGC 0.6.0: admin, history, settings
//	export-schema3.age   SGC 0.8.0: adds SSH keys, and the settings for the
//	                     firewall and for "keys only"
//
// They are kept forever: every later SGC must still be able to restore them,
// which is the promise "a newer SGC can import an older export". When the
// layout changes, the tests below prove the old files are brought up to
// date; add a new file alongside them, never replace one.
//
// Writing the file for the current layout (once, when the layout changes;
// it refuses to overwrite):
//
//	SGC_WRITE_FIXTURE=<version> go test ./internal/backup -run WriteFixture
const (
	fixtureFile       = "testdata/export-schema2.age"
	fixtureSchema3    = "testdata/export-schema3.age"
	fixtureSchema7    = "testdata/export-schema7.age"
	fixturePassphrase = "fixture passphrase, not a secret"
)

func TestWriteFixture(t *testing.T) {
	version := os.Getenv("SGC_WRITE_FIXTURE")
	if version == "" {
		t.Skip("only run on purpose, to create the fixture")
	}
	fixtureFile := fmt.Sprintf("testdata/export-schema%d.age", store.SchemaVersion())
	if _, err := os.Stat(fixtureFile); err == nil {
		t.Fatalf("%s already exists; fixtures are never replaced", fixtureFile)
	}
	db, stateDir := newSourceDB(t)
	var file bytes.Buffer
	if _, err := Export(context.Background(), db, &file, fixturePassphrase, Source{SGCVersion: version, Hostname: "old-gateway"}, filepath.Join(stateDir, "tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixtureFile, file.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRestoresAnExportMadeBySGC060(t *testing.T) {
	ctx := context.Background()
	file, err := os.ReadFile(fixtureFile)
	if err != nil {
		t.Fatalf("the fixture is missing: %v", err)
	}
	targetDir := t.TempDir()

	manifest, err := Stage(ctx, bytes.NewReader(file), fixturePassphrase, targetDir)
	if err != nil {
		t.Fatalf("an export made by SGC 0.6.0 can no longer be restored: %v", err)
	}
	if manifest.SGCVersion != "0.6.0" || manifest.SchemaVersion != 2 || manifest.AdminUsername != "alex" || manifest.Hostname != "old-gateway" {
		t.Errorf("manifest = %+v", manifest)
	}
	if err := Confirm(targetDir, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyStaged(targetDir); err != nil {
		t.Fatal(err)
	}

	db, err := store.Open(ctx, filepath.Join(targetDir, layout.DatabaseFile))
	if err != nil {
		t.Fatalf("open the restored database: %v", err)
	}
	defer db.Close()

	// What was in the old export is intact...
	var hash, autoCheck string
	var history int
	if err := db.QueryRowContext(ctx, "SELECT password_hash FROM admin").Scan(&hash); err != nil || hash != "the-password-hash" {
		t.Errorf("admin = %q, %v", hash, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log").Scan(&history); err != nil || history != 2 {
		t.Errorf("history entries = %d, %v", history, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT value FROM setting WHERE key = 'update.auto_check'").Scan(&autoCheck); err != nil || autoCheck != "0" {
		t.Errorf("setting = %q, %v", autoCheck, err)
	}
	// ...and the database has today's layout.
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != store.SchemaVersion() {
		t.Errorf("layout version = %d, want %d", version, store.SchemaVersion())
	}
	// What that version did not have yet is simply empty.
	var keys int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ssh_key").Scan(&keys); err != nil || keys != 0 {
		t.Errorf("SSH keys = %d, %v", keys, err)
	}
}

func TestRestoresAnExportMadeBySGC0160(t *testing.T) {
	ctx := context.Background()
	file, err := os.ReadFile(fixtureSchema7)
	if err != nil {
		t.Fatalf("the fixture is missing: %v", err)
	}
	targetDir := t.TempDir()
	manifest, err := Stage(ctx, bytes.NewReader(file), fixturePassphrase, targetDir)
	if err != nil {
		t.Fatalf("an export made by SGC 0.16.0 can no longer be restored: %v", err)
	}
	if manifest.SGCVersion != "0.16.0" || manifest.SchemaVersion != 7 {
		t.Errorf("manifest = %+v", manifest)
	}
	if err := Confirm(targetDir, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyStaged(targetDir); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(targetDir, layout.DatabaseFile))
	if err != nil {
		t.Fatalf("open the restored database: %v", err)
	}
	defer db.Close()
	for query, want := range map[string]string{
		// What travels: every phone keeps working, servers keep their
		// registrations, the dashboard its icons.
		"SELECT value FROM setting WHERE key = 'gateway.name'":                         "gw",
		"SELECT value FROM setting WHERE key = 'vpn.server_key'":                       "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		"SELECT label || '|' || pinned_ip FROM announce_token":                         "media server|192.168.1.30",
		"SELECT COUNT(*) FROM service":                                                 "2",
		"SELECT name || '|' || token_id || '|' || protected FROM service WHERE id = 1": "media|1|1",
		"SELECT COUNT(*) FROM service_icon":                                            "1",
		"SELECT name || '|' || username || '|' || password_hash FROM person":           "Kim|kim|a-person-hash",
		"SELECT COUNT(*) FROM person_service":                                          "1",
		"SELECT name || '|' || address || '|' || private_key FROM vpn_device":          "phone|10.86.0.2|AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		"SELECT COUNT(*) FROM setting WHERE key = 'notify.channels'":                   "1",
		"SELECT COUNT(*) FROM setting WHERE key = 'backups.settings'":                  "1",
		// What does not: this device's own bookkeeping.
		"SELECT COUNT(*) FROM service_health": "0",
		"SELECT COUNT(*) FROM vpn_usage":      "0",
		"SELECT COUNT(*) FROM vpn_peer_state": "0",
		"SELECT COUNT(*) FROM notification":   "0",
		"SELECT COUNT(*) FROM person_session": "0",
		"SELECT COUNT(*) FROM gate_pass":      "0",
		"SELECT COUNT(*) FROM setting WHERE key IN ('proxy.last_apply', 'vpn.last_apply', 'backups.last', 'eol.state', 'vpn.endpoint_state')": "0",
	} {
		var got string
		if err := db.QueryRowContext(ctx, query).Scan(&got); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", query, got, err, want)
		}
	}
}

func TestRestoresAnExportMadeBySGC080(t *testing.T) {
	ctx := context.Background()
	file, err := os.ReadFile(fixtureSchema3)
	if err != nil {
		t.Fatalf("the fixture is missing: %v", err)
	}
	targetDir := t.TempDir()

	manifest, err := Stage(ctx, bytes.NewReader(file), fixturePassphrase, targetDir)
	if err != nil {
		t.Fatalf("an export made by SGC 0.8.0 can no longer be restored: %v", err)
	}
	if manifest.SGCVersion != "0.8.0" || manifest.SchemaVersion != 3 || manifest.AdminUsername != "alex" || manifest.Hostname != "old-gateway" {
		t.Errorf("manifest = %+v", manifest)
	}
	if err := Confirm(targetDir, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyStaged(targetDir); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(targetDir, layout.DatabaseFile))
	if err != nil {
		t.Fatalf("open the restored database: %v", err)
	}
	defer db.Close()

	for query, want := range map[string]string{
		"SELECT password_hash FROM admin":                                 "the-password-hash",
		"SELECT COUNT(*) FROM audit_log":                                  "2",
		"SELECT value FROM setting WHERE key = 'update.auto_check'":       "0",
		"SELECT value FROM setting WHERE key = 'firewall.enabled'":        "true",
		"SELECT value FROM setting WHERE key = 'ssh.account'":             "alex",
		"SELECT value FROM setting WHERE key = 'ssh.keys_only'":           "true",
		"SELECT label || '|' || key_type || '|' || added_by FROM ssh_key": "laptop|ssh-ed25519|alex",
		"SELECT fingerprint FROM ssh_key":                                 "SHA256:ZcQJrTJFZ1DO2xgEpCKluYro6G3ehPZvDrs/oGfuJG4",
		// Bookkeeping of the old installation did not travel.
		"SELECT COUNT(*) FROM setting WHERE key LIKE '%open_change'": "0",
		"SELECT COUNT(*) FROM session":                               "0",
	} {
		var got string
		if err := db.QueryRowContext(ctx, query).Scan(&got); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", query, got, err, want)
		}
	}
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != store.SchemaVersion() {
		t.Errorf("layout version = %d, want %d", version, store.SchemaVersion())
	}
}
