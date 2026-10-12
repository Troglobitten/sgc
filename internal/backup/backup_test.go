package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

const testPassphrase = "a passphrase for tests"

var testSource = Source{SGCVersion: "1.2.3", Hostname: "old-gateway"}

// A marker that must never appear in an export: the stored form of a session.
var sessionHash = []byte("SESSION-TOKEN-HASH-MUST-NOT-TRAVEL")

// newSourceDB makes a database the way a used SGC has it: an admin, history,
// settings, a signed-in browser, a cached update check.
func newSourceDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	ctx := context.Background()
	stateDir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(stateDir, layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	statements := []string{
		`INSERT INTO admin (id, username, password_hash, created_at) VALUES (1, 'alex', 'the-password-hash', 100)`,
		`INSERT INTO audit_log (at, actor, action, detail, remote_addr) VALUES (101, 'alex', 'setup.completed', 'admin account created', '192.168.1.10')`,
		`INSERT INTO audit_log (at, actor, action, detail, remote_addr) VALUES (102, 'alex', 'login.success', '', '192.168.1.10')`,
		`INSERT INTO setting (key, value) VALUES ('update.auto_check', '0')`,
		`INSERT INTO setting (key, value) VALUES ('update.last_reported_id', '12345')`,
		`INSERT INTO setting (key, value) VALUES ('firewall.enabled', 'true')`,
		`INSERT INTO setting (key, value) VALUES ('firewall.open_change', '{"id":77,"enabled":false,"actor":"alex"}')`,
		`INSERT INTO setting (key, value) VALUES ('ssh.account', 'alex')`,
		`INSERT INTO setting (key, value) VALUES ('ssh.keys_only', 'true')`,
		`INSERT INTO setting (key, value) VALUES ('ssh.open_change', '{"id":78,"actor":"alex","what":"switching to keys only"}')`,
		`INSERT INTO setting (key, value) VALUES ('os_updates.mode', 'automatic')`,
		`INSERT INTO setting (key, value) VALUES ('os_updates.open_install', '{"id":79,"actor":"alex","remote":"192.168.1.10"}')`,
		`INSERT INTO ssh_key (label, key_type, key_blob, fingerprint, added_at, added_by) VALUES ('laptop', 'ssh-ed25519', 'AAAAC3NzaC1lZDI1NTE5AAAAID25i1+d/VGOmeRQ2ZPpnryBGMe/B28pdc623ONJVCV1', 'SHA256:ZcQJrTJFZ1DO2xgEpCKluYro6G3ehPZvDrs/oGfuJG4', 103, 'alex')`,
		`INSERT INTO setup_token (id, token_hash, expires_at) VALUES (1, x'00', 999)`,
		`UPDATE update_check SET latest_version = '9.9.9', notes = 'cached notes', checked_at = 500`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO session (token_hash, username, created_at, last_seen_at, expires_at, remote_addr, user_agent)
		 VALUES (?, 'alex', 1, 1, 9999999999, '192.168.1.10', 'browser')`, sessionHash); err != nil {
		t.Fatal(err)
	}
	return db, stateDir
}

func export(t *testing.T, db *sql.DB, stateDir string) []byte {
	t.Helper()
	var file bytes.Buffer
	if _, err := Export(context.Background(), db, &file, testPassphrase, testSource, filepath.Join(stateDir, "tmp")); err != nil {
		t.Fatalf("Export: %v", err)
	}
	return file.Bytes()
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	source, sourceDir := newSourceDB(t)
	file := export(t, source, sourceDir)

	// A fresh installation: its own, different, database is in place.
	targetDir := t.TempDir()
	fresh, err := store.Open(ctx, filepath.Join(targetDir, layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	fresh.ExecContext(ctx, `INSERT INTO setup_token (id, token_hash, expires_at) VALUES (1, x'ff', 999)`)
	fresh.Close()

	manifest, err := Stage(ctx, bytes.NewReader(file), testPassphrase, targetDir)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if manifest.AdminUsername != "alex" || manifest.SGCVersion != "1.2.3" || manifest.Hostname != "old-gateway" || manifest.FormatVersion != FormatVersion {
		t.Errorf("manifest = %+v", manifest)
	}
	if manifest.SchemaVersion != store.SchemaVersion() || manifest.CreatedAt.IsZero() {
		t.Errorf("manifest = %+v", manifest)
	}

	if err := Confirm(targetDir, manifest); err != nil {
		t.Fatal(err)
	}
	applied, err := ApplyStaged(targetDir)
	if err != nil || applied == nil || applied.AdminUsername != "alex" {
		t.Fatalf("ApplyStaged = %+v, %v", applied, err)
	}

	restored, err := store.Open(ctx, filepath.Join(targetDir, layout.DatabaseFile))
	if err != nil {
		t.Fatalf("open restored database: %v", err)
	}
	defer restored.Close()

	// Everything that is configuration or history is identical.
	for _, query := range []string{
		"SELECT group_concat(username || '|' || password_hash || '|' || created_at) FROM admin",
		"SELECT group_concat(at || '|' || actor || '|' || action || '|' || detail || '|' || remote_addr, ';') FROM audit_log",
		"SELECT value FROM setting WHERE key = 'update.auto_check'",
		"SELECT value FROM setting WHERE key = 'firewall.enabled'",
		"SELECT value FROM setting WHERE key = 'ssh.account'",
		"SELECT value FROM setting WHERE key = 'ssh.keys_only'",
		"SELECT value FROM setting WHERE key = 'os_updates.mode'",
		"SELECT group_concat(label || '|' || key_type || '|' || key_blob || '|' || fingerprint || '|' || added_at || '|' || added_by, ';') FROM ssh_key",
	} {
		var want, got sql.NullString
		if err := source.QueryRowContext(ctx, query).Scan(&want); err != nil {
			t.Fatal(err)
		}
		if err := restored.QueryRowContext(ctx, query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want || !want.Valid {
			t.Errorf("%s\n  source:   %q\n  restored: %q", query, want.String, got.String)
		}
	}

	// Everything that belongs to one running installation is gone.
	for query, want := range map[string]int{
		"SELECT COUNT(*) FROM session":                                                   0,
		"SELECT COUNT(*) FROM setup_token":                                               0,
		"SELECT COUNT(*) FROM setting WHERE key = 'update.last_reported_id'":             0,
		"SELECT COUNT(*) FROM setting WHERE key = 'firewall.open_change'":                0,
		"SELECT COUNT(*) FROM setting WHERE key = 'ssh.open_change'":                     0,
		"SELECT COUNT(*) FROM setting WHERE key = 'os_updates.open_install'":             0,
		"SELECT COUNT(*) FROM update_check":                                              1, // the row itself must exist
		"SELECT COUNT(*) FROM update_check WHERE latest_version = '' AND checked_at = 0": 1,
	} {
		var got int
		if err := restored.QueryRowContext(ctx, query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}

	// Nothing is left waiting, so a second start does not restore again.
	if again, err := ApplyStaged(targetDir); again != nil || err != nil {
		t.Errorf("second ApplyStaged = %+v, %v; want nothing to do", again, err)
	}
}

// The export must be openable without SGC: a standard age file holding a
// tar archive with exactly the two documented entries.
func TestExportIsAPlainAgeEncryptedTar(t *testing.T) {
	source, sourceDir := newSourceDB(t)
	file := export(t, source, sourceDir)

	if !bytes.HasPrefix(file, []byte("age-encryption.org/v1\n")) {
		t.Fatalf("the file does not start like an age file: %q", file[:min(len(file), 30)])
	}
	identity, _ := age.NewScryptIdentity(testPassphrase)
	decrypted, err := age.Decrypt(bytes.NewReader(file), identity)
	if err != nil {
		t.Fatalf("plain age cannot decrypt the export: %v", err)
	}
	archive := tar.NewReader(decrypted)
	var names []string
	var database []byte
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		data, _ := io.ReadAll(archive)
		if header.Name == manifestName {
			var manifest Manifest
			if err := json.Unmarshal(data, &manifest); err != nil || manifest.AdminUsername != "alex" {
				t.Errorf("manifest in the archive: %s (%v)", data, err)
			}
		}
		if header.Name == databaseName {
			database = data
		}
	}
	if !slices.Equal(names, []string{manifestName, databaseName}) {
		t.Errorf("archive contains %v", names)
	}

	// Deleted rows must really be gone from the file, not merely unlisted.
	if bytes.Contains(database, sessionHash) {
		t.Error("the stored form of a sign-in session is still inside the exported database")
	}
	if !bytes.Contains(database, []byte("the-password-hash")) {
		t.Error("the admin account is missing from the exported database")
	}
	// And the export itself must not contain anything readable.
	if bytes.Contains(file, []byte("alex")) || bytes.Contains(file, []byte("the-password-hash")) {
		t.Error("the encrypted export contains readable account data")
	}
}

func TestExportLeavesNoTemporaryCopyBehind(t *testing.T) {
	source, sourceDir := newSourceDB(t)
	export(t, source, sourceDir)

	entries, _ := os.ReadDir(filepath.Join(sourceDir, "tmp"))
	if len(entries) != 0 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestPassphraseRules(t *testing.T) {
	source, sourceDir := newSourceDB(t)
	var out bytes.Buffer

	_, err := Export(context.Background(), source, &out, "too short", testSource, filepath.Join(sourceDir, "tmp"))
	if !errors.Is(err, ErrWeakPassphrase) {
		t.Errorf("short passphrase: err = %v", err)
	}
	_, err = Export(context.Background(), source, &out, strings.Repeat("x", maxPassphraseLength+1), testSource, filepath.Join(sourceDir, "tmp"))
	if !errors.Is(err, ErrPassphraseLength) {
		t.Errorf("overlong passphrase: err = %v", err)
	}
	if out.Len() != 0 {
		t.Error("something was written for a refused passphrase")
	}
}

func TestStageRefusals(t *testing.T) {
	ctx := context.Background()
	source, sourceDir := newSourceDB(t)
	good := export(t, source, sourceDir)

	// An export claiming a newer database layout than this SGC knows.
	if _, err := source.ExecContext(ctx, "PRAGMA user_version = 9999"); err != nil {
		t.Fatal(err)
	}
	newer := export(t, source, sourceDir)

	// A file that decrypts fine but is not an SGC export.
	var foreign bytes.Buffer
	recipient, _ := age.NewScryptRecipient(testPassphrase)
	recipient.SetWorkFactor(10)
	w, _ := age.Encrypt(&foreign, recipient)
	w.Write([]byte("just some text, not an archive"))
	w.Close()

	cases := []struct {
		name       string
		file       []byte
		passphrase string
		want       error
		wantText   string
	}{
		{name: "wrong passphrase", file: good, passphrase: "not the passphrase!!", want: ErrWrongPassphrase},
		{name: "not an age file", file: []byte("PK\x03\x04 some other file"), passphrase: testPassphrase, want: ErrNotAnExport},
		{name: "empty file", file: nil, passphrase: testPassphrase, want: ErrNotAnExport},
		{name: "an age file with something else inside", file: foreign.Bytes(), passphrase: testPassphrase, want: ErrNotAnExport},
		{name: "made by a newer SGC", file: newer, passphrase: testPassphrase, want: ErrNewerExport},
		{name: "cut short", file: good[:len(good)-200], passphrase: testPassphrase, wantText: "damaged or incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targetDir := t.TempDir()

			_, err := Stage(ctx, bytes.NewReader(tc.file), tc.passphrase, targetDir)

			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if tc.wantText != "" && (err == nil || !strings.Contains(err.Error(), tc.wantText)) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantText)
			}
			if err == nil {
				t.Fatal("the file was accepted")
			}
			// A refused file must leave nothing that a later start could apply.
			if applied, _ := ApplyStaged(targetDir); applied != nil {
				t.Error("a refused file was applied")
			}
			if _, statErr := os.Stat(stagingDir(targetDir)); !errors.Is(statErr, os.ErrNotExist) {
				t.Error("a refused file left a staging folder behind")
			}
		})
	}
}

func TestAStagedRestoreIsOnlyAppliedWhenConfirmed(t *testing.T) {
	ctx := context.Background()
	source, sourceDir := newSourceDB(t)
	file := export(t, source, sourceDir)

	targetDir := t.TempDir()
	current := filepath.Join(targetDir, layout.DatabaseFile)
	if err := os.WriteFile(current, []byte("the database in use"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Previewed, never confirmed: the next start must not touch the database.
	if _, err := Stage(ctx, bytes.NewReader(file), testPassphrase, targetDir); err != nil {
		t.Fatal(err)
	}
	if applied, err := ApplyStaged(targetDir); applied != nil || err != nil {
		t.Fatalf("ApplyStaged = %+v, %v; an unconfirmed restore was applied", applied, err)
	}
	if data, _ := os.ReadFile(current); string(data) != "the database in use" {
		t.Error("the database in use was changed by an unconfirmed restore")
	}
	if _, err := os.Stat(stagingDir(targetDir)); !errors.Is(err, os.ErrNotExist) {
		t.Error("the unconfirmed restore was not cleaned up")
	}

	// Confirming without anything staged is an error, not a silent no-op.
	if err := Confirm(targetDir, &Manifest{}); err == nil {
		t.Error("Confirm succeeded with nothing staged")
	}
}

// The guard for "every new setting must be covered by export/import": a new
// table cannot be added to the database without deciding here whether it
// travels with an export.
func TestEveryTableIsClassified(t *testing.T) {
	ctx := context.Background()
	db, _ := newSourceDB(t)

	rows, err := db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var classified []string
	classified = append(classified, exportedTables...)
	classified = append(classified, transientTables...)
	for table := range resetStatements {
		classified = append(classified, table)
	}

	var existing []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		existing = append(existing, name)
		if !slices.Contains(classified, name) {
			t.Errorf("table %q is not classified in tables.go: decide whether it is exported or transient", name)
		}
	}
	for _, name := range classified {
		if !slices.Contains(existing, name) {
			t.Errorf("tables.go lists %q, which does not exist in the database", name)
		}
	}
}
