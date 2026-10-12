// Package sshcontrol is the web process's side of SSH keys and "keys only".
//
// The web process cannot touch the SSH server. It keeps the keys the owner
// added in the database (which is what an export carries), asks the root
// helper to put them and the "keys only" switch into effect, reads the files
// in which the root side keeps its state, and writes the history.
//
// The database follows what is confirmed on the device, not the other way
// round: a key is recorded once it is installed, and a change that needs a
// key login as proof (internal/sshd) is recorded only when that proof has
// been seen. If the change is undone instead, the database was never wrong.
package sshcontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/sshd"
	"github.com/Troglobitten/sgc/internal/sshkeys"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// SettingAccount is the Linux account SGC installs the keys for.
	SettingAccount = "ssh.account"
	// SettingKeysOnly holds what the owner last had confirmed: "true" or
	// "false". Like the firewall's setting it travels with an export and is
	// not acted on by itself on a restored machine.
	SettingKeysOnly = "ssh.keys_only"
	// SettingOpenChange remembers a change that waits for its proof.
	// Bookkeeping of one installation; left out of exports.
	SettingOpenChange = "ssh.open_change"
)

const (
	maxLabel = 64
	// overdueGrace: see internal/fwcontrol.
	overdueGrace = 15 * time.Second
)

var (
	ErrChangePending = errors.New("another change to SSH is still waiting for a login with a key")
	ErrNoChange      = errors.New("that is already how it is")
	ErrDuplicate     = errors.New("this key has already been added")
	ErrNoSuchKey     = errors.New("there is no such key")
	ErrNeedAccount   = errors.New("choose the account the key is for")
	// ErrNoKeyLogin: switching to keys only is refused until a key has been
	// seen to work, because the outcome would be known in advance.
	ErrNoKeyLogin = errors.New("SGC has not seen anyone log in with a key in the last 15 minutes. Log in over SSH with your key, then switch")
)

// ChangeError is a failed change with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

// InputError is something wrong with what the owner entered.
type InputError struct{ Message string }

func (e *InputError) Error() string { return e.Message }

// Helper is what this package asks the root helper to do.
type Helper interface {
	SSHStatus(ctx context.Context) (sshd.Status, error)
	SSHChange(ctx context.Context, cfg sshd.Config) error
	SSHUndo(ctx context.Context) error
}

type Config struct {
	DB     *sql.DB
	Helper Helper
	Audit  *audit.Log
	Paths  sshd.Paths
	Uptime func() (float64, error)
	Now    func() time.Time
	Log    *slog.Logger
}

type Service struct {
	cfg Config
	// One change at a time.
	mu sync.Mutex
	// Wakes Run up when a change has been started.
	started chan struct{}
}

func New(cfg Config) *Service {
	return &Service{cfg: cfg, started: make(chan struct{}, 1)}
}

// --- State as the interface shows it ----------------------------------------------

type KeyStatus struct {
	ID          int64     `json:"id"`
	Label       string    `json:"label"`
	Kind        string    `json:"kind"`
	Fingerprint string    `json:"fingerprint"`
	AddedAt     time.Time `json:"addedAt"`
	// Installed is false for a key that is known but not on this device:
	// after restoring an export, until the keys are installed here.
	Installed bool `json:"installed"`
	// LastLogin is the most recent login with this key in the last quarter
	// of an hour.
	LastLogin *time.Time `json:"lastLogin"`
}

type LoginStatus struct {
	Account string `json:"account"`
	// Key is the label of the key that was used, or empty if it is not one
	// of SGC's but one the account keeps for itself.
	Key         string    `json:"key"`
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
}

type PendingStatus struct {
	// What is waiting, in words: "switching to keys only", "removing laptop".
	What        string `json:"what"`
	SecondsLeft int    `json:"secondsLeft"`
}

type Status struct {
	// Available is false on a device without an SSH server, and when the
	// root helper could not be asked.
	Available bool `json:"available"`
	Running   bool `json:"running"`

	// Account is the account the keys are for; Accounts are the ones there
	// are to choose from on this device.
	Account  string      `json:"account"`
	Accounts []string    `json:"accounts"`
	Keys     []KeyStatus `json:"keys"`
	// NeedsInstall: keys are known that are not on this device (see KeyStatus).
	NeedsInstall bool `json:"needsInstall"`

	// What the SSH server allows right now.
	PasswordLogins bool   `json:"passwordLogins"`
	RootLogin      string `json:"rootLogin"`
	// KeysOnly is SGC's switch, as confirmed on this device. Wanted is what
	// the owner last had confirmed anywhere: true with KeysOnly false means
	// "it was on in the export this was restored from".
	KeysOnly bool `json:"keysOnly"`
	Wanted   bool `json:"wanted"`
	// LoginsVisible is false if the SSH server does not log logins, in
	// which case SGC cannot see a key work and does not offer the switch.
	LoginsVisible bool `json:"loginsVisible"`
	// RecentLogin is the latest key login in the last quarter of an hour.
	// Switching to keys only is offered once there is one.
	RecentLogin *LoginStatus   `json:"recentLogin"`
	Pending     *PendingStatus `json:"pending"`
	// ProofSeconds is how long a change waits for a key login.
	ProofSeconds int `json:"proofSeconds"`
}

type keyRow struct {
	ID      int64
	Label   string
	Key     sshkeys.Key
	AddedAt time.Time
}

func (s *Service) keys(ctx context.Context) ([]keyRow, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, "SELECT id, label, key_type, key_blob, fingerprint, added_at FROM ssh_key ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("read the SSH keys: %w", err)
	}
	defer rows.Close()
	var keys []keyRow
	for rows.Next() {
		var row keyRow
		var added int64
		if err := rows.Scan(&row.ID, &row.Label, &row.Key.Type, &row.Key.Blob, &row.Key.Fingerprint, &added); err != nil {
			return nil, fmt.Errorf("read the SSH keys: %w", err)
		}
		row.AddedAt = time.Unix(added, 0).UTC()
		keys = append(keys, row)
	}
	return keys, rows.Err()
}

func (s *Service) setting(ctx context.Context, key string) (string, error) {
	value, _, err := store.Setting(ctx, s.cfg.DB, key)
	return value, err
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	// A change that ended on the root side since the last look is acted on
	// first. Without that the answer could be half of it for a moment: the
	// switch confirmed on the device but not yet recorded as what the owner
	// wants, or a removed key still in the list. If a change is being made
	// this very moment the lock is taken, and whoever holds it settles.
	if s.mu.TryLock() {
		s.settle(ctx)
		s.mu.Unlock()
	}

	status := Status{Accounts: []string{}, Keys: []KeyStatus{}, ProofSeconds: int(sshd.ProofWindow.Seconds())}
	rows, err := s.keys(ctx)
	if err != nil {
		return status, err
	}
	if status.Account, err = s.setting(ctx, SettingAccount); err != nil {
		return status, err
	}
	wanted, err := s.setting(ctx, SettingKeysOnly)
	if err != nil {
		return status, err
	}
	status.Wanted = wanted == "true"

	state, err := sshd.ReadState(s.cfg.Paths)
	if err != nil {
		return status, fmt.Errorf("read the SSH state: %w", err)
	}
	status.KeysOnly = state.Confirmed.KeysOnly

	// What only root can find out. Without it the page still shows the keys.
	var logins []sshd.Login
	if system, err := s.cfg.Helper.SSHStatus(ctx); err != nil {
		s.cfg.Log.Warn("ask the helper for the SSH server's state", "error", err)
	} else {
		status.Available = system.Installed
		status.Running = system.Running
		status.Accounts = system.Accounts
		status.PasswordLogins = system.Settings.PasswordLogins
		status.RootLogin = system.Settings.RootLogin
		status.LoginsVisible = system.Settings.LoginsVisible
		logins = system.Logins
	}

	labels := map[string]string{}
	for _, row := range rows {
		labels[row.Key.Fingerprint] = row.Label
		key := KeyStatus{
			ID: row.ID, Label: row.Label, Kind: row.Key.Kind(), Fingerprint: row.Key.Fingerprint, AddedAt: row.AddedAt,
			Installed: state.Confirmed.Account == status.Account &&
				slices.ContainsFunc(state.Confirmed.Keys, func(k sshkeys.Key) bool { return k.Fingerprint == row.Key.Fingerprint }),
		}
		for _, login := range logins {
			if login.Fingerprint == row.Key.Fingerprint {
				at := login.At
				key.LastLogin = &at
			}
		}
		if !key.Installed {
			status.NeedsInstall = true
		}
		status.Keys = append(status.Keys, key)
	}
	if len(logins) > 0 {
		last := logins[len(logins)-1]
		status.RecentLogin = &LoginStatus{Account: last.Account, Key: labels[last.Fingerprint], Fingerprint: last.Fingerprint, At: last.At}
	}

	if state.Pending != nil && state.Pending.NeedsProof {
		uptime, err := s.cfg.Uptime()
		if err != nil {
			return status, err
		}
		status.Pending = &PendingStatus{What: "a change to SSH", SecondsLeft: state.Pending.SecondsLeft(uptime)}
		if open := s.openChange(ctx); open != nil && open.ID == state.Pending.ID {
			status.Pending.What = open.What
		}
	}
	return status, nil
}

// --- Changes ------------------------------------------------------------------

// mutation is what a change does to the database once it is confirmed.
type mutation struct {
	// AddKey: record this key (and the account it is for).
	AddKey   *sshkeys.Key `json:"addKey,omitempty"`
	AddLabel string       `json:"addLabel,omitempty"`
	Account  string       `json:"account,omitempty"`
	// RemoveKey: forget the key with this ID.
	RemoveKey int64 `json:"removeKey,omitempty"`
	// KeysOnly: record the switch.
	KeysOnly *bool `json:"keysOnly,omitempty"`
}

// openChange is what SettingOpenChange holds.
type openChange struct {
	ID     int64  `json:"id"`
	Actor  string `json:"actor"`
	What   string `json:"what"`
	Remote string `json:"remote"`
	// Action is the audit action recorded when the change is confirmed.
	Action   string   `json:"action"`
	Mutation mutation `json:"mutation"`
}

func (s *Service) openChange(ctx context.Context) *openChange {
	raw, err := s.setting(ctx, SettingOpenChange)
	if err != nil || raw == "" {
		return nil
	}
	var open openChange
	if json.Unmarshal([]byte(raw), &open) != nil {
		return nil
	}
	return &open
}

// desired is the configuration the database describes, with the "keys only"
// switch as it is confirmed on this device.
func (s *Service) desired(ctx context.Context, confirmed sshd.Config) (sshd.Config, []keyRow, error) {
	rows, err := s.keys(ctx)
	if err != nil {
		return sshd.Config{}, nil, err
	}
	account, err := s.setting(ctx, SettingAccount)
	if err != nil {
		return sshd.Config{}, nil, err
	}
	cfg := sshd.Config{Account: account, KeysOnly: confirmed.KeysOnly, Keys: []sshkeys.Key{}}
	for _, row := range rows {
		cfg.Keys = append(cfg.Keys, row.Key)
	}
	return cfg, rows, nil
}

// change asks the root side for a configuration. If that is confirmed at
// once, the database is brought in line at once; if it waits for a key
// login, what to do then is remembered.
func (s *Service) change(ctx context.Context, actor, remote string, candidate sshd.Config, m mutation, action, what string) error {
	before, err := sshd.ReadState(s.cfg.Paths)
	if err != nil {
		return fmt.Errorf("read the SSH state: %w", err)
	}
	if err := s.cfg.Helper.SSHChange(ctx, candidate); err != nil {
		s.cfg.Log.Error("change SSH", "what", what, "error", err)
		message := "That did not work. Nothing was changed."
		// The root side says why, in the record of how its last change ended.
		if after, readErr := sshd.ReadState(s.cfg.Paths); readErr == nil && after.Last != nil &&
			after.Last.Result == sshd.ResultFailed && (before.Last == nil || after.Last.ID != before.Last.ID) {
			message = "That did not work: " + after.Last.Message + ". Nothing was changed."
		}
		s.record(ctx, actor, audit.ActionSSHChangeFailed, what, remote)
		return &ChangeError{message}
	}

	after, err := sshd.ReadState(s.cfg.Paths)
	if err != nil {
		return fmt.Errorf("read the SSH state: %w", err)
	}
	if after.Pending != nil && after.Pending.NeedsProof {
		open, _ := json.Marshal(openChange{ID: after.Pending.ID, Actor: actor, What: what, Remote: remote, Action: action, Mutation: m})
		if err := store.SetSetting(ctx, s.cfg.DB, SettingOpenChange, string(open)); err != nil {
			s.cfg.Log.Error("remember the started SSH change", "error", err)
		}
		s.record(ctx, actor, audit.ActionSSHChangeStarted, what, remote)
		select {
		case s.started <- struct{}{}:
		default:
		}
		return nil
	}
	return s.commit(ctx, actor, remote, m, action, what)
}

// commit brings the database in line with a confirmed change and writes it
// into the history.
func (s *Service) commit(ctx context.Context, actor, remote string, m mutation, action, detail string) error {
	// Carried out even if the request that caused it has gone away: the
	// change itself is already in effect on the device.
	ctx = context.WithoutCancel(ctx)
	if m.AddKey != nil {
		if _, err := s.cfg.DB.ExecContext(ctx,
			`INSERT INTO ssh_key (label, key_type, key_blob, fingerprint, added_at, added_by) VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (fingerprint) DO NOTHING`,
			m.AddLabel, m.AddKey.Type, m.AddKey.Blob, m.AddKey.Fingerprint, s.cfg.Now().Unix(), actor); err != nil {
			return fmt.Errorf("record the key: %w", err)
		}
	}
	if m.Account != "" {
		if err := store.SetSetting(ctx, s.cfg.DB, SettingAccount, m.Account); err != nil {
			return err
		}
	}
	if m.RemoveKey != 0 {
		if _, err := s.cfg.DB.ExecContext(ctx, "DELETE FROM ssh_key WHERE id = ?", m.RemoveKey); err != nil {
			return fmt.Errorf("forget the key: %w", err)
		}
	}
	if m.KeysOnly != nil {
		if err := store.SetSetting(ctx, s.cfg.DB, SettingKeysOnly, strconv.FormatBool(*m.KeysOnly)); err != nil {
			return err
		}
	}
	s.record(ctx, actor, action, detail, remote)
	return nil
}

func (s *Service) prepare(ctx context.Context) (sshd.State, error) {
	s.settle(ctx)
	state, err := sshd.ReadState(s.cfg.Paths)
	if err != nil {
		return state, fmt.Errorf("read the SSH state: %w", err)
	}
	if state.Pending != nil {
		return state, ErrChangePending
	}
	return state, nil
}

// cleanLabel makes a label out of what was typed, or out of the comment the
// key came with.
func cleanLabel(label, comment string, number int) string {
	clean := func(text string) string {
		text = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, strings.TrimSpace(text))
		if runes := []rune(text); len(runes) > maxLabel {
			text = string(runes[:maxLabel])
		}
		return strings.TrimSpace(text)
	}
	if text := clean(label); text != "" {
		return text
	}
	if text := clean(comment); text != "" {
		return text
	}
	return fmt.Sprintf("key %d", number)
}

// AddKey installs a pasted public key for an account. account may be empty
// when it is clear which one is meant: the one already in use, or the only
// one there is.
func (s *Service) AddKey(ctx context.Context, actor, remote, label, pasted, account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, comment, err := sshkeys.Parse(pasted)
	if err != nil {
		return &InputError{sentence(err)}
	}
	state, err := s.prepare(ctx)
	if err != nil {
		return err
	}
	candidate, rows, err := s.desired(ctx, state.Confirmed)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(rows, func(row keyRow) bool { return row.Key.Fingerprint == key.Fingerprint }) {
		return ErrDuplicate
	}
	// The account is chosen with the first key and stays while there are keys.
	if len(rows) == 0 || candidate.Account == "" {
		if account == "" {
			system, err := s.cfg.Helper.SSHStatus(ctx)
			if err != nil {
				return &ChangeError{"The device could not be asked which accounts it has. Nothing was changed."}
			}
			if len(system.Accounts) != 1 {
				return ErrNeedAccount
			}
			account = system.Accounts[0]
		}
		candidate.Account = account
	} else if account != "" && account != candidate.Account {
		return &InputError{"The keys already added are for the account " + candidate.Account + ". Remove them first to use another account."}
	}
	candidate.Keys = append(candidate.Keys, key)

	label = cleanLabel(label, comment, len(rows)+1)
	detail := fmt.Sprintf("%s (%s %s) for the account %s", label, key.Kind(), key.Fingerprint, candidate.Account)
	return s.change(ctx, actor, remote, candidate,
		mutation{AddKey: &key, AddLabel: label, Account: candidate.Account}, audit.ActionSSHKeyAdded, detail)
}

// RemoveKey takes a key away. Under "keys only" that waits for a login with
// one of the remaining keys, and the key comes back without one.
func (s *Service) RemoveKey(ctx context.Context, actor, remote string, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.prepare(ctx)
	if err != nil {
		return err
	}
	candidate, rows, err := s.desired(ctx, state.Confirmed)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(rows, func(row keyRow) bool { return row.ID == id })
	if index < 0 {
		return ErrNoSuchKey
	}
	row := rows[index]
	candidate.Keys = slices.Delete(candidate.Keys, index, index+1)
	detail := fmt.Sprintf("%s (%s %s)", row.Label, row.Key.Kind(), row.Key.Fingerprint)
	if sshd.NeedsProof(state.Confirmed, candidate) {
		detail = "removing " + detail
	}
	return s.change(ctx, actor, remote, candidate, mutation{RemoveKey: id}, audit.ActionSSHKeyRemoved, detail)
}

// SetKeysOnly switches "keys only" on or off. Switching it on takes effect
// at once and stays only if a login with a key is then seen.
func (s *Service) SetKeysOnly(ctx context.Context, actor, remote string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.prepare(ctx)
	if err != nil {
		return err
	}
	if state.Confirmed.KeysOnly == enabled {
		return ErrNoChange
	}
	candidate := state.Confirmed
	candidate.KeysOnly = enabled
	if !enabled {
		return s.change(ctx, actor, remote, candidate, mutation{KeysOnly: &enabled}, audit.ActionSSHKeysOnlyOff, "password logins allowed again")
	}

	system, err := s.cfg.Helper.SSHStatus(ctx)
	if err != nil {
		return &ChangeError{"The device's SSH server could not be asked about its state. Nothing was changed."}
	}
	switch {
	case !system.Installed:
		return &ChangeError{"This device has no SSH server."}
	case !system.Settings.LoginsVisible:
		return &ChangeError{"This device's SSH server is set up not to log logins, so SGC could not see that a key works. Nothing was changed."}
	case len(system.Logins) == 0:
		return ErrNoKeyLogin
	}
	return s.change(ctx, actor, remote, candidate, mutation{KeysOnly: &enabled}, audit.ActionSSHKeysOnlyOn, "switching to keys only")
}

// Install puts the keys the database knows onto this device. It is what the
// owner does after restoring an export on a new machine. account says which
// account they are for here, if the one from the export does not exist.
func (s *Service) Install(ctx context.Context, actor, remote, account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.prepare(ctx)
	if err != nil {
		return err
	}
	candidate, rows, err := s.desired(ctx, state.Confirmed)
	if err != nil {
		return err
	}
	if account != "" {
		candidate.Account = account
	}
	if len(rows) == 0 || candidate.Equal(state.Confirmed) {
		return ErrNoChange
	}
	if candidate.Account == "" {
		return ErrNeedAccount
	}
	detail := fmt.Sprintf("%d key(s) for the account %s", len(rows), candidate.Account)
	return s.change(ctx, actor, remote, candidate, mutation{Account: candidate.Account}, audit.ActionSSHKeysInstalled, detail)
}

// Undo puts the confirmed configuration back now, without waiting.
func (s *Service) Undo(ctx context.Context, actor, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := sshd.ReadState(s.cfg.Paths)
	if err != nil {
		return fmt.Errorf("read the SSH state: %w", err)
	}
	if state.Pending == nil {
		s.settle(ctx)
		return nil
	}
	if err := s.cfg.Helper.SSHUndo(ctx); err != nil {
		return fmt.Errorf("undo the SSH change: %w", err)
	}
	what := "a change to SSH"
	if open := s.openChange(ctx); open != nil {
		what = open.What
	}
	s.record(ctx, actor, audit.ActionSSHChangeUndone, what, remote)
	s.clearOpenChange(ctx)
	return nil
}

// RecordPasswordsAllowedAtConsole writes down that "keys only" was switched
// off with "sgc ssh allow-passwords" at the device itself.
func RecordPasswordsAllowedAtConsole(ctx context.Context, db *sql.DB, auditLog *audit.Log) error {
	if err := store.SetSetting(ctx, db, SettingKeysOnly, "false"); err != nil {
		return err
	}
	if err := store.SetSetting(ctx, db, SettingOpenChange, ""); err != nil {
		return err
	}
	return auditLog.Record(ctx, audit.ActorConsole, audit.ActionSSHKeysOnlyOff, "password logins allowed again", "")
}

// --- Changes that end without the owner ---------------------------------------------

// Run brings the database and the history in line with changes that ended
// on the root side: confirmed by a key login, or undone for lack of one. It
// runs until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	watching := true
	for {
		s.mu.Lock()
		if s.rescue(ctx) {
			watching = true
		}
		if watching {
			watching = s.settle(ctx)
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-s.started:
			watching = true
		case <-ticker.C:
		}
	}
}

// rescue asks for a change to be undone that is still in effect well past
// its deadline, which means the root side's own ways of undoing it failed.
func (s *Service) rescue(ctx context.Context) bool {
	state, err := sshd.ReadState(s.cfg.Paths)
	if err != nil || state.Pending == nil || !state.Pending.NeedsProof {
		return false
	}
	uptime, err := s.cfg.Uptime()
	if err != nil || uptime < state.Pending.DeadlineUptime+overdueGrace.Seconds() {
		return false
	}
	s.cfg.Log.Error("an SSH change is past its time and still in effect; undoing it", "id", state.Pending.ID)
	if err := s.cfg.Helper.SSHUndo(ctx); err != nil {
		s.cfg.Log.Error("undo the overdue SSH change", "error", err)
		return false
	}
	return true
}

// settle looks at the change remembered as open and, if it has ended, acts
// on how. It reports whether a change is still open. The caller holds the lock.
func (s *Service) settle(ctx context.Context) (stillOpen bool) {
	open := s.openChange(ctx)
	if open == nil {
		return false
	}
	state, err := sshd.ReadState(s.cfg.Paths)
	if err != nil {
		s.cfg.Log.Error("read the SSH state", "error", err)
		return true
	}
	if state.Pending != nil && state.Pending.ID == open.ID {
		return true
	}

	started := open.What + ", started by " + open.Actor
	switch last := state.Last; {
	case last != nil && last.ID == open.ID && last.Result == sshd.ResultConfirmed:
		detail := open.What
		if last.Proof != nil {
			detail += fmt.Sprintf(" (confirmed: %s logged in with a key, %s)", last.Proof.Account, last.Proof.Fingerprint)
		}
		if err := s.commit(ctx, open.Actor, open.Remote, open.Mutation, open.Action, detail); err != nil {
			s.cfg.Log.Error("record the confirmed SSH change", "error", err)
			return true
		}
	case last != nil && last.ID == open.ID && last.Result == sshd.ResultExpired:
		s.record(ctx, audit.ActorSystem, audit.ActionSSHChangeExpired, started, "")
	case last != nil && last.ID == open.ID && last.Result == sshd.ResultFailed:
		s.record(ctx, audit.ActorSystem, audit.ActionSSHChangeFailed, started+": "+last.Message, "")
	default:
		s.record(ctx, audit.ActorSystem, audit.ActionSSHChangeUndone, started+" (the wait for a login with a key was interrupted)", "")
	}
	s.clearOpenChange(ctx)
	return false
}

func (s *Service) clearOpenChange(ctx context.Context) {
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingOpenChange, ""); err != nil {
		s.cfg.Log.Error("forget the finished SSH change", "error", err)
	}
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

// sentence makes an error message presentable: capital first letter, full stop.
func sentence(err error) string {
	msg := err.Error()
	if msg == "" {
		return msg
	}
	msg = strings.ToUpper(msg[:1]) + msg[1:]
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
}
