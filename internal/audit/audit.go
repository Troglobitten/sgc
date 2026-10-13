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

	ActionUpdateStarted    = "update.started"
	ActionUpdateSucceeded  = "update.succeeded"
	ActionUpdateRolledBack = "update.rolled_back"
	ActionUpdateFailed     = "update.failed"
	ActionSettingChanged   = "setting.changed"

	ActionExportCreated    = "export.created"
	ActionRestoreCompleted = "restore.completed"

	// SGC installed Debian packages it needs; the detail names them.
	ActionPackagesInstalled = "system.packages_installed"

	// A firewall change is in effect and waits for confirmation.
	ActionFirewallChangeStarted = "firewall.change_started"
	// The owner confirmed it: it is now what the device starts with.
	ActionFirewallChangeConfirmed = "firewall.change_confirmed"
	// Undone on request, or because the wait was interrupted.
	ActionFirewallChangeUndone = "firewall.change_undone"
	// Undone because nobody confirmed in time.
	ActionFirewallChangeExpired = "firewall.change_expired"
	// It could not be put into effect at all.
	ActionFirewallChangeFailed = "firewall.change_failed"

	// An SSH key was added to, or taken from, the keys that may log in. The
	// detail names the key by its label and fingerprint.
	ActionSSHKeyAdded   = "ssh.key_added"
	ActionSSHKeyRemoved = "ssh.key_removed"
	// The keys known from an export were installed on this device.
	ActionSSHKeysInstalled = "ssh.keys_installed"
	// "Keys only" was confirmed by a login with a key, or switched off.
	ActionSSHKeysOnlyOn  = "ssh.keys_only_on"
	ActionSSHKeysOnlyOff = "ssh.keys_only_off"
	// A change to SSH that takes away a way of logging in is in effect and
	// waits for a login with a key; and the ways it can end without one.
	ActionSSHChangeStarted = "ssh.change_started"
	ActionSSHChangeUndone  = "ssh.change_undone"
	ActionSSHChangeExpired = "ssh.change_expired"
	ActionSSHChangeFailed  = "ssh.change_failed"

	// The owner chose how the device gets Debian's updates: by themselves,
	// or started in SGC's page. Or the choice could not be put into effect.
	ActionOSUpdatesAutomatic    = "os_updates.mode_automatic"
	ActionOSUpdatesByHand       = "os_updates.mode_by_hand"
	ActionOSUpdatesChangeFailed = "os_updates.change_failed"
	// An installation of Debian's updates was started in SGC's page, and how
	// it ended. The detail names what was installed.
	ActionOSUpdatesInstallStarted = "os_updates.install_started"
	ActionOSUpdatesInstalled      = "os_updates.installed"
	ActionOSUpdatesInstallFailed  = "os_updates.install_failed"

	// AdGuard Home was installed (or replaced by a newer release). "removed"
	// is from SGC 0.11.0, which had a button for it; it stays so that the
	// history of a device that used it can still be read.
	ActionDNSInstalled = "dns.installed"
	ActionDNSRemoved   = "dns.removed"
	// DNS was switched on or off. And: the DNS part of a restored export was
	// put in place; the detail says what that meant on this device.
	ActionDNSSwitchedOn  = "dns.switched_on"
	ActionDNSSwitchedOff = "dns.switched_off"
	ActionDNSRestored    = "dns.restored"

	// Logs in memory (log2ram) was switched on or off. Either takes effect
	// when the device restarts.
	ActionLog2ramSwitchedOn  = "log2ram.switched_on"
	ActionLog2ramSwitchedOff = "log2ram.switched_off"

	// The owner's domain and Zone.eu account were saved (the detail names
	// both, never the key), or removed.
	ActionDomainSaved   = "domain.saved"
	ActionDomainRemoved = "domain.removed"
	// Zone.eu stopped accepting the saved account for the domain (the detail
	// says what it answered), and accepted it again.
	ActionZoneCheckFailed    = "zone.check_failed"
	ActionZoneCheckRecovered = "zone.check_recovered"

	// The owner agreed to the certificate authority's terms. A certificate
	// was issued for the first time, or renewed (the detail names what it is
	// for, who issued it and until when it is valid). An attempt at either
	// failed (the detail says why).
	ActionCertificateTermsAgreed = "certificate.terms_agreed"
	ActionCertificateIssued      = "certificate.issued"
	ActionCertificateRenewed     = "certificate.renewed"
	ActionCertificateFailed      = "certificate.failed"
)

// ActorConsole is recorded for actions taken with the command-line tool.
const ActorConsole = "console"

// ActorSystem is recorded for things SGC reports about itself.
const ActorSystem = "system"

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
