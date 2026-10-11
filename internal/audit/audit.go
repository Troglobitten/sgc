// Package audit records who did what: logins, configuration changes and other
// actions worth being able to look up later ("what changed before it broke?").
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Actions. Stored as text, so never rename one that has shipped.
const (
	ActionSetupLinkCreated = "setup.link_created"
	ActionSetupCompleted   = "setup.completed"
	ActionLogin            = "login.success"
	ActionLoginFailed      = "login.failed"
	ActionLogout           = "logout"
	ActionDeviceRestart    = "device.restart"
	// Written when a requested restart could not be carried out, so the log
	// never claims a restart that did not happen.
	ActionDeviceRestartFailed = "device.restart_failed"
)

// ActorConsole is recorded for actions taken with the command-line tool.
const ActorConsole = "console"

type Entry struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Detail     string    `json:"detail"`
	RemoteAddr string    `json:"remoteAddr"`
}

type Log struct {
	db  *sql.DB
	now func() time.Time
}

func New(db *sql.DB) *Log {
	return &Log{db: db, now: time.Now}
}

// Record appends an entry. remoteAddr is empty for actions not made over the network.
func (l *Log) Record(ctx context.Context, actor, action, detail, remoteAddr string) error {
	if _, err := l.db.ExecContext(ctx,
		"INSERT INTO audit_log (at, actor, action, detail, remote_addr) VALUES (?, ?, ?, ?, ?)",
		l.now().Unix(), actor, action, detail, remoteAddr); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// Recent returns up to limit entries, newest first.
func (l *Log) Recent(ctx context.Context, limit int) ([]Entry, error) {
	rows, err := l.db.QueryContext(ctx,
		"SELECT id, at, actor, action, detail, remote_addr FROM audit_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	defer rows.Close()

	entries := []Entry{}
	for rows.Next() {
		var e Entry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Detail, &e.RemoteAddr); err != nil {
			return nil, fmt.Errorf("read audit log: %w", err)
		}
		e.At = time.Unix(at, 0).UTC()
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
