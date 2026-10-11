package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenCreatesSchemaAndIsRepeatable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sgc.db")

	for attempt := 1; attempt <= 2; attempt++ {
		db, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("open %d: %v", attempt, err)
		}

		var version int
		if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version != len(migrations) {
			t.Errorf("open %d: version = %d, want %d", attempt, version, len(migrations))
		}
		for _, table := range []string{"admin", "setup_token", "session", "audit_log", "setting", "update_check"} {
			if _, err := db.ExecContext(ctx, "SELECT 1 FROM "+table+" LIMIT 1"); err != nil {
				t.Errorf("open %d: table %s: %v", attempt, table, err)
			}
		}
		db.Close()
	}
}

// Right after installation the service and `sgc setup-link` both open the
// brand-new database within the same second.
func TestOpeningAFreshDatabaseFromSeveralPlacesAtOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sgc.db")

	const openers = 8
	errs := make(chan error, openers)
	for i := 0; i < openers; i++ {
		go func() {
			db, err := Open(ctx, path)
			if err == nil {
				db.Close()
			}
			errs <- err
		}()
	}
	for i := 0; i < openers; i++ {
		if err := <-errs; err != nil {
			t.Errorf("simultaneous open failed: %v", err)
		}
	}
}

// An installation made with an earlier SGC has an older database. Opening it
// with this version must bring it up to date without losing what is in it.
func TestDatabaseFromAnEarlierVersionIsBroughtUpToDate(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sgc.db")

	// Build the database exactly as SGC 0.4.0 left it: only the first migration.
	all := migrations
	migrations = all[:1]
	db, err := Open(ctx, path)
	migrations = all
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO admin (id, username, password_hash, created_at) VALUES (1, 'alex', 'hash', 5)"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("opening a 0.4.0 database: %v", err)
	}
	defer db.Close()

	var username string
	if err := db.QueryRowContext(ctx, "SELECT username FROM admin").Scan(&username); err != nil || username != "alex" {
		t.Errorf("admin after update = %q, %v; existing data must survive", username, err)
	}
	if _, found, err := Setting(ctx, db, "anything"); err != nil || found {
		t.Errorf("the new settings table is not usable: found=%v err=%v", found, err)
	}
}

func TestSettings(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, found, err := Setting(ctx, db, "color"); err != nil || found {
		t.Errorf("unset setting: found=%v err=%v", found, err)
	}
	for _, value := range []string{"blue", "green"} {
		if err := SetSetting(ctx, db, "color", value); err != nil {
			t.Fatal(err)
		}
		if got, found, _ := Setting(ctx, db, "color"); !found || got != value {
			t.Errorf("after setting %q: got %q, found=%v", value, got, found)
		}
	}
}

func TestOnlyOneAdminRowIsPossible(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	insert := "INSERT INTO admin (id, username, password_hash, created_at) VALUES (?, 'a', 'h', 0)"
	if _, err := db.ExecContext(ctx, insert, 1); err != nil {
		t.Fatalf("first admin: %v", err)
	}
	if _, err := db.ExecContext(ctx, insert, 2); err == nil {
		t.Error("a second admin row was accepted")
	}
}

func TestRefusesDatabaseFromNewerRelease(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sgc.db")
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA user_version = 9999"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = Open(ctx, path)
	if err == nil || !strings.Contains(err.Error(), "newer release") {
		t.Errorf("err = %v, want a refusal mentioning a newer release", err)
	}
}
