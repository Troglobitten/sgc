package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

// testdata/export-schema2.age is an export written by SGC 0.6.0, when the
// database layout was at version 2. It is kept forever: every later SGC must
// still be able to restore it, which is the promise "a newer SGC can import
// an older export". When the layout changes, this test proves the old file
// is brought up to date; add a new fixture alongside it, never replace it.
//
// Regenerating (only ever needed if the fixture is lost):
//
//	SGC_WRITE_FIXTURE=1 go test ./internal/backup -run WriteFixture
const (
	fixtureFile       = "testdata/export-schema2.age"
	fixturePassphrase = "fixture passphrase, not a secret"
)

func TestWriteFixture(t *testing.T) {
	if os.Getenv("SGC_WRITE_FIXTURE") != "1" {
		t.Skip("only run on purpose, to create the fixture")
	}
	if _, err := os.Stat(fixtureFile); err == nil {
		t.Fatalf("%s already exists; fixtures are never replaced", fixtureFile)
	}
	db, stateDir := newSourceDB(t)
	var file bytes.Buffer
	if _, err := Export(context.Background(), db, &file, fixturePassphrase, Source{SGCVersion: "0.6.0", Hostname: "old-gateway"}, filepath.Join(stateDir, "tmp")); err != nil {
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
}
