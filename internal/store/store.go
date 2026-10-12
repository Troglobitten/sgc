// Package store opens SGC's database and keeps its layout up to date.
//
// Everything SGC knows lives in this one SQLite file. System configuration is
// generated from it, and an export is essentially a copy of it, which is what
// makes export/import reliable (design principle 3).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver: no C compiler needed, static binaries stay simple
)

// migrations are applied in order, each exactly once. The database remembers
// how many have run (PRAGMA user_version).
//
// Never edit or reorder an entry that has shipped in a release; append a new one.
var migrations = []string{
	// 1: admin account, one-time setup token, sessions, audit log.
	`
	CREATE TABLE admin (
		-- SGC has exactly one admin; the CHECK makes a second row impossible.
		id            INTEGER PRIMARY KEY CHECK (id = 1),
		username      TEXT    NOT NULL,
		password_hash TEXT    NOT NULL,
		created_at    INTEGER NOT NULL
	);

	CREATE TABLE setup_token (
		id         INTEGER PRIMARY KEY CHECK (id = 1),
		token_hash BLOB    NOT NULL,
		expires_at INTEGER NOT NULL
	);

	CREATE TABLE session (
		-- Only a hash of the session token is stored, so a copy of the
		-- database cannot be used to take over a login.
		token_hash   BLOB    PRIMARY KEY,
		username     TEXT    NOT NULL,
		created_at   INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL,
		expires_at   INTEGER NOT NULL,
		remote_addr  TEXT    NOT NULL,
		user_agent   TEXT    NOT NULL
	);

	CREATE TABLE audit_log (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		at          INTEGER NOT NULL,
		actor       TEXT    NOT NULL,
		action      TEXT    NOT NULL,
		detail      TEXT    NOT NULL,
		remote_addr TEXT    NOT NULL
	);
	CREATE INDEX audit_log_at ON audit_log (at);
	`,

	// 2: settings, and what the last check for a newer SGC found.
	`
	CREATE TABLE setting (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE update_check (
		id             INTEGER PRIMARY KEY CHECK (id = 1),
		-- The newest release seen at the last successful check.
		latest_version TEXT    NOT NULL DEFAULT '',
		notes          TEXT    NOT NULL DEFAULT '',
		published_at   INTEGER NOT NULL DEFAULT 0,
		checked_at     INTEGER NOT NULL DEFAULT 0,
		-- Set while the most recent check failed; cleared by a successful one.
		error          TEXT    NOT NULL DEFAULT '',
		error_at       INTEGER NOT NULL DEFAULT 0
	);
	INSERT INTO update_check (id) VALUES (1);
	`,

	// 3: SSH keys the owner added in SGC's page.
	`
	CREATE TABLE ssh_key (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		-- What the owner calls the key ("laptop").
		label       TEXT    NOT NULL,
		-- The key itself: its kind and the key in base64, as in a line of an
		-- authorized_keys file. A public key: nothing secret.
		key_type    TEXT    NOT NULL,
		key_blob    TEXT    NOT NULL,
		-- What the SSH server calls the key in its log. Unique, so the same
		-- key is not added twice.
		fingerprint TEXT    NOT NULL UNIQUE,
		added_at    INTEGER NOT NULL,
		added_by    TEXT    NOT NULL
	);
	`,
}

// Setting reads one setting. found is false if it was never set, in which
// case the caller applies its default.
func Setting(ctx context.Context, db *sql.DB, key string) (value string, found bool, err error) {
	err = db.QueryRowContext(ctx, "SELECT value FROM setting WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read setting %s: %w", key, err)
	}
	return value, true, nil
}

// SetSetting stores one setting, replacing any earlier value.
func SetSetting(ctx context.Context, db *sql.DB, key, value string) error {
	if _, err := db.ExecContext(ctx,
		`INSERT INTO setting (key, value) VALUES (?, ?)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
		return fmt.Errorf("store setting %s: %w", key, err)
	}
	return nil
}

// SchemaVersion is the number of migrations this SGC knows: the layout
// version a database has after Open.
func SchemaVersion() int { return len(migrations) }

// OpenSnapshot opens a database file as it is, without updating its layout
// and without the write-ahead log, so that it stays a single self-contained
// file. For working on a copy made for an export.
func OpenSnapshot(path string) (*sql.DB, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database copy: %w", err)
	}
	return db, nil
}

// Open opens (creating if needed) the database at path and applies any
// migrations it has not seen yet.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	// WAL lets the service and the command-line tools use the database at the
	// same time. busy_timeout makes a writer wait for another instead of
	// failing. _txlock=immediate takes the write lock at BEGIN, which avoids
	// the deadlock two upgrading read transactions can run into.
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_txlock=immediate"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// busy_timeout does not cover everything. When several programs open a
	// brand-new database in the same instant (the service and `sgc
	// setup-link` right after installation), each first has to switch it to
	// WAL, and SQLite answers "busy" at once there instead of waiting, because
	// waiting could deadlock. That moment passes in milliseconds, so it is
	// waited out here. Found by this package's own test failing once in a few
	// hundred runs, first on the build machines.
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := migrate(ctx, db)
		if err == nil {
			return db, nil
		}
		if !isBusy(err) || ctx.Err() != nil || time.Now().After(deadline) {
			db.Close()
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// isBusy reports whether an error is SQLite saying that another connection
// holds the database right now (SQLITE_BUSY, in any of its variants).
func isBusy(err error) bool {
	const sqliteBusy = 5
	var coded interface{ Code() int }
	return errors.As(err, &coded) && coded.Code()&0xff == sqliteBusy
}

func migrate(ctx context.Context, db *sql.DB) error {
	// One transaction for everything, and the version is read inside it.
	// The transaction takes the database's write lock at the start, so when
	// two programs open a fresh database at the same moment (the service and
	// `sgc setup-link` right after installation), the second one waits and
	// then sees that there is nothing left to do.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database update: %w", err)
	}
	defer tx.Rollback()

	var applied int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&applied); err != nil {
		return fmt.Errorf("read database version: %w", err)
	}
	if applied > len(migrations) {
		// A newer SGC wrote this database. Running older code against it
		// could corrupt data it does not understand.
		return fmt.Errorf("database is at version %d but this SGC only knows up to %d; it was written by a newer release", applied, len(migrations))
	}
	if applied == len(migrations) {
		return nil
	}

	for i := applied; i < len(migrations); i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("apply migration %d: %w", i+1, err)
		}
	}
	// PRAGMA does not accept bound parameters; the value is our own integer.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", len(migrations))); err != nil {
		return fmt.Errorf("record database version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database update: %w", err)
	}
	return nil
}
