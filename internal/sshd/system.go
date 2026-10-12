package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProofWindow is how long a change that takes away a way of logging in waits
// for somebody to log in with a key. Long enough to switch to a terminal
// and connect; the page asks for the terminal to be ready beforehand.
const ProofWindow = 2 * time.Minute

// recentLogins is how far back Status looks for key logins.
const recentLogins = 15 * time.Minute

// Paths says where everything is. The state and key files belong to root
// and are readable by everyone (they hold public keys only); the web
// process reads them to show the state and cannot change them.
type Paths struct {
	// StateFile holds the confirmed configuration. Everything else on disk
	// is written from it, and can be written again from it at any time.
	StateFile string
	// KeysDir holds one file of keys per account, read by the SSH server.
	KeysDir string
	// DropIn is SGC's file in the SSH server's configuration folder.
	DropIn string
	// RunDir holds what only matters until the next restart.
	RunDir string
	// RequestFile is where the helper puts what the web process asked for.
	RequestFile string
	PasswdFile  string
}

func DefaultPaths() Paths {
	return Paths{
		StateFile:   "/etc/sgc/ssh/state.json",
		KeysDir:     "/etc/sgc/ssh/keys",
		DropIn:      "/etc/ssh/sshd_config.d/00-sgc.conf",
		RunDir:      "/run/sgc-ssh",
		RequestFile: "/run/sgc-requests/ssh.json",
		PasswdFile:  "/etc/passwd",
	}
}

func (p Paths) pendingFile() string { return filepath.Join(p.RunDir, "pending.json") }
func (p Paths) outcomeFile() string { return filepath.Join(p.RunDir, "last.json") }
func (p Paths) lockFile() string    { return filepath.Join(p.RunDir, "lock") }

// Pending is a change that is in effect but not yet the confirmed one.
type Pending struct {
	ID     int64  `json:"id"`
	Config Config `json:"config"`
	// NeedsProof: it stays only if a key login is seen. Without it the
	// change is confirmed as soon as it has been applied and checked; it is
	// "pending" for that moment only, so that a crash in the middle is
	// cleaned up like any other unfinished change.
	NeedsProof bool      `json:"needsProof"`
	StartedAt  time.Time `json:"startedAt"`
	// AppliedAt is when the SSH server took up the change. Only logins
	// after it count as proof. Zero while the change is being applied.
	AppliedAt time.Time `json:"appliedAt"`
	// DeadlineUptime is when the change is undone, in seconds since the
	// machine started (see internal/firewall for why not a time of day).
	DeadlineUptime float64 `json:"deadlineUptime"`
}

// SecondsLeft is how long a pending change still waits for its proof.
func (p *Pending) SecondsLeft(uptime float64) int {
	left := p.DeadlineUptime - uptime
	if left <= 0 {
		return 0
	}
	return int(left + 0.999)
}

// How a change ended.
const (
	ResultConfirmed = "confirmed"
	ResultExpired   = "expired" // no key login was seen in time
	ResultUndone    = "undone"  // on request, or because the wait was interrupted
	ResultFailed    = "failed"  // it could not be put into effect
)

// Outcome is how the most recent change ended.
type Outcome struct {
	ID      int64  `json:"id"`
	Result  string `json:"result"`
	Message string `json:"message,omitempty"`
	// Proof is the key login that confirmed the change, if one was needed.
	Proof *Login    `json:"proof,omitempty"`
	At    time.Time `json:"at"`
}

// State is what SGC's files say.
type State struct {
	// Confirmed is the configuration the machine starts with.
	Confirmed Config
	Pending   *Pending
	Last      *Outcome
}

// ReadState reads the files. It needs no privileges.
func ReadState(paths Paths) (State, error) {
	state := State{Confirmed: Config{Keys: nil}}
	if _, err := readJSONFile(paths.StateFile, &state.Confirmed); err != nil {
		return state, err
	}
	var pending Pending
	if found, err := readJSONFile(paths.pendingFile(), &pending); err != nil {
		return state, err
	} else if found {
		state.Pending = &pending
	}
	var last Outcome
	if found, err := readJSONFile(paths.outcomeFile(), &last); err != nil {
		return state, err
	} else if found {
		state.Last = &last
	}
	return state, nil
}

// Status is what the SSH server and its log say right now. Reading it takes
// root: the server only reports its settings to root, and so does its log.
type Status struct {
	// Installed is false on a machine without an SSH server.
	Installed bool     `json:"installed"`
	Running   bool     `json:"running"`
	Settings  Settings `json:"settings"`
	// Accounts are the accounts on this machine a person can log in with.
	Accounts []string `json:"accounts"`
	// Logins are the key logins of those accounts in the last quarter of an
	// hour, oldest first.
	Logins []Login `json:"logins"`
}

var ErrNotInstalled = errors.New("this device has no SSH server")

// System carries out changes to the SSH server. It runs as root, in units
// of its own (installer/sgc-ssh-*.service).
type System struct {
	Paths  Paths
	Window time.Duration

	// Run runs a program and returns what it printed. Injected so that the
	// tests need neither root nor an SSH server.
	Run    func(ctx context.Context, program string, args ...string) ([]byte, error)
	Exists func(program string) bool
	Uptime func() (float64, error)
	Now    func() time.Time
	// Sleep waits; the tests do not.
	Sleep func(time.Duration)
	Log   *slog.Logger
}

func (s *System) Status(ctx context.Context) (Status, error) {
	status := Status{Accounts: []string{}, Logins: []Login{}}
	if !s.Exists(sshdProgram) {
		return status, nil
	}
	status.Installed = true
	status.Running = s.listening(ctx)
	settings, err := s.settings(ctx, "")
	if err != nil {
		return status, err
	}
	status.Settings = settings
	if status.Accounts, err = accounts(s.Paths.PasswdFile); err != nil {
		return status, err
	}
	entries, err := s.journalSince(ctx, s.Now().Add(-recentLogins))
	if err != nil {
		return status, err
	}
	status.Logins = keyLogins(entries, status.Accounts)
	return status, nil
}

// listening reports whether the SSH server accepts connections: as a
// running service or, on machines set up that way, started per connection.
func (s *System) listening(ctx context.Context) bool {
	if _, err := s.Run(ctx, systemctl, "is-active", "--quiet", serviceUnit); err == nil {
		return true
	}
	_, err := s.Run(ctx, systemctl, "is-active", "--quiet", socketUnit)
	return err == nil
}

// settings asks the SSH server what the configuration on disk amounts to,
// in general or (with an account) for one account's logins, which can
// differ where the configuration makes exceptions.
func (s *System) settings(ctx context.Context, account string) (Settings, error) {
	args := []string{"-T"}
	if account != "" {
		args = append(args, "-C", "user="+account+",host=localhost,addr=127.0.0.1")
	}
	output, err := s.Run(ctx, sshdProgram, args...)
	if err != nil {
		return Settings{}, fmt.Errorf("the SSH server does not accept its configuration: %s", lastLine(output, err))
	}
	return parseSettings(output)
}

// Change puts the requested configuration into effect and calls ready.
//
// If the change takes away a way of logging in, it then waits: for a key
// login, which makes the change the confirmed one; for the time to run out
// or ctx to be cancelled (the owner chose "undo", or the machine is shutting
// down), which puts the confirmed configuration back. Any other change is
// confirmed at once.
//
// An error means the confirmed configuration is (again) the one in effect.
func (s *System) Change(ctx context.Context, ready func()) error {
	pending, err := s.begin(ctx)
	if err != nil {
		return err
	}
	ready()
	if pending == nil {
		return nil // confirmed already
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return s.Revert(ctx, ResultUndone, "")
		case <-ticker.C:
		}
		current, err := s.readPending()
		if err == nil && (current == nil || current.ID != pending.ID) {
			return nil // undone by another job
		}
		if proof := s.proof(ctx, pending); proof != nil {
			return s.confirm(pending.ID, proof)
		}
		uptime, err := s.Uptime()
		if err != nil || uptime >= pending.DeadlineUptime {
			return s.Revert(ctx, ResultExpired, "")
		}
	}
}

// proof looks for a key login made after the change took effect.
func (s *System) proof(ctx context.Context, pending *Pending) *Login {
	names, err := accounts(s.Paths.PasswdFile)
	if err != nil {
		return nil
	}
	entries, err := s.journalSince(ctx, pending.AppliedAt)
	if err != nil {
		s.Log.Warn("look for a key login", "error", err)
		return nil
	}
	for _, login := range keyLogins(entries, names) {
		if login.At.After(pending.AppliedAt) {
			return &login
		}
	}
	return nil
}

// begin applies the requested configuration. It returns the pending change
// if it now waits for proof, or nil if it has been confirmed.
func (s *System) begin(ctx context.Context) (*Pending, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	// A change left behind by a process that died is undone first.
	if err := s.revertLocked(ctx, ResultUndone, "the change was interrupted"); err != nil {
		return nil, err
	}

	id := s.Now().UnixMilli()
	fail := func(err error) (*Pending, error) {
		s.recordOutcome(Outcome{ID: id, Result: ResultFailed, Message: err.Error(), At: s.Now().UTC()})
		return nil, err
	}
	if !s.Exists(sshdProgram) {
		return fail(ErrNotInstalled)
	}
	names, err := accounts(s.Paths.PasswdFile)
	if err != nil {
		return fail(err)
	}
	requested, err := s.readRequest()
	if err != nil {
		return fail(fmt.Errorf("read the request: %w", err))
	}
	candidate, err := requested.check(names)
	if err != nil {
		return fail(err)
	}
	state, err := ReadState(s.Paths)
	if err != nil {
		return fail(err)
	}
	confirmed := state.Confirmed
	needsProof := NeedsProof(confirmed, candidate)

	before, err := s.settings(ctx, "")
	if err != nil {
		return fail(err)
	}
	// SGC's key file is added to the usual places. On a machine that keeps
	// keys somewhere else, adding it would put the usual places back and
	// could switch off the keys in use, so SGC keeps out.
	if candidate.managesKeys() && !confirmed.managesKeys() && before.KeyFiles != defaultKeyFiles {
		return fail(errors.New("this device's SSH server is set up to keep keys in its own place (AuthorizedKeysFile), which SGC does not change. Add the key there by hand"))
	}
	if needsProof && !before.LoginsVisible {
		return fail(errors.New("this device's SSH server is set up not to log logins (LogLevel), so SGC could not see that a key works"))
	}

	uptime, err := s.Uptime()
	if err != nil {
		return fail(err)
	}
	pending := &Pending{
		ID:             id,
		Config:         candidate,
		NeedsProof:     needsProof,
		StartedAt:      s.Now().UTC(),
		DeadlineUptime: uptime + s.Window.Seconds(),
	}
	// Written before anything is changed. The files this changes survive a
	// restart, so whatever cleans up after a crash, at any point from here
	// on, must be able to tell that there is something to clean up.
	if err := writeJSONFile(s.Paths.pendingFile(), pending); err != nil {
		return fail(err)
	}

	appliedAt, err := s.apply(ctx, candidate)
	if err != nil {
		message := "the change could not be put into effect: " + err.Error()
		s.revertLocked(ctx, ResultFailed, message)
		return nil, errors.New(message)
	}
	if !needsProof {
		if err := s.confirmLocked(pending, nil); err != nil {
			s.revertLocked(ctx, ResultFailed, err.Error())
			return nil, err
		}
		return nil, nil
	}
	pending.AppliedAt = appliedAt
	if err := writeJSONFile(s.Paths.pendingFile(), pending); err != nil {
		s.revertLocked(ctx, ResultFailed, err.Error())
		return nil, err
	}
	s.Log.Info("SSH change in effect, waiting for a key login", "id", id, "seconds", int(s.Window.Seconds()))
	return pending, nil
}

// apply writes a configuration to disk, has the SSH server check it and take
// it up, and makes sure it then means what it should. It returns the moment
// from which the server works with it.
func (s *System) apply(ctx context.Context, cfg Config) (time.Time, error) {
	if _, err := s.write(cfg); err != nil {
		return time.Time{}, err
	}
	// The server's own check of the complete configuration, new file included.
	if output, err := s.Run(ctx, sshdProgram, "-t"); err != nil {
		return time.Time{}, fmt.Errorf("the SSH server refuses the configuration: %s", lastLine(output, err))
	}
	// And what it amounts to: a setting elsewhere on this machine may
	// override SGC's file, for everybody or for this account's logins.
	views := []string{""}
	if cfg.Account != "" {
		views = append(views, cfg.Account)
	}
	for _, account := range views {
		got, err := s.settings(ctx, account)
		if err != nil {
			return time.Time{}, err
		}
		if cfg.KeysOnly && (got.PasswordLogins || got.RootLogin != "no" || !got.KeyLogins) {
			return time.Time{}, errors.New("another setting on this device overrides SGC's, so \"keys only\" would not hold")
		}
		if cfg.managesKeys() && !strings.Contains(got.KeyFiles, s.Paths.KeysDir+"/%u") {
			return time.Time{}, errors.New("another setting on this device overrides where the SSH server looks for keys")
		}
	}
	return s.reload(ctx)
}

// reload makes the running SSH server take up the configuration on disk and
// returns the moment from which it has.
func (s *System) reload(ctx context.Context) (time.Time, error) {
	if _, err := s.Run(ctx, systemctl, "is-active", "--quiet", serviceUnit); err != nil {
		// Not running as a service. Either it is started per connection,
		// and then every new connection reads the files anyway, or there is
		// nothing running to tell.
		return s.Now(), nil
	}
	asked := s.Now()
	if output, err := s.Run(ctx, systemctl, "reload", serviceUnit); err != nil {
		return time.Time{}, fmt.Errorf("the SSH server did not take up the configuration: %s", lastLine(output, err))
	}
	// The server says in its log when it listens again, which is the exact
	// moment. On a machine whose log is too quiet for that, a short wait and
	// a look at whether the service still runs has to do.
	for range 15 {
		s.Sleep(200 * time.Millisecond)
		entries, err := s.journalSince(ctx, asked)
		if err != nil {
			break
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Message, listeningPrefix) {
				return entry.At, nil
			}
		}
	}
	if _, err := s.Run(ctx, systemctl, "is-active", "--quiet", serviceUnit); err != nil {
		return time.Time{}, errors.New("the SSH server stopped when it was asked to take up the configuration")
	}
	return s.Now(), nil
}

// write puts a configuration's two files in place: the keys and SGC's part
// of the SSH server's settings. Files a configuration does not need are
// removed, so the result depends on the configuration alone.
//
// changed reports whether anything was not already as it should be. The
// files are written either way; it only tells the caller whether the SSH
// server has something new to take up.
func (s *System) write(cfg Config) (changed bool, err error) {
	if err := os.MkdirAll(s.Paths.KeysDir, 0o755); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(s.Paths.KeysDir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !cfg.managesKeys() || entry.Name() != cfg.Account {
			if err := os.Remove(filepath.Join(s.Paths.KeysDir, entry.Name())); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	put := func(path string, content string) error {
		if !holds(path, []byte(content)) {
			changed = true
		}
		return writeFileAtomic(path, []byte(content))
	}
	if cfg.managesKeys() {
		if err := put(filepath.Join(s.Paths.KeysDir, cfg.Account), renderKeys(cfg)); err != nil {
			return changed, err
		}
	}
	dropIn := renderDropIn(cfg, s.Paths.KeysDir)
	if dropIn == "" {
		if _, err := os.Lstat(s.Paths.DropIn); err == nil {
			changed = true
		}
		return changed, removeIfExists(s.Paths.DropIn)
	}
	if _, err := os.Stat(filepath.Dir(s.Paths.DropIn)); err != nil {
		return changed, errors.New("this device's SSH server has no folder for additional settings (sshd_config.d), which SGC needs")
	}
	return changed, put(s.Paths.DropIn, dropIn)
}

// confirm makes the pending change the confirmed configuration.
func (s *System) confirm(id int64, proof *Login) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	pending, err := s.readPending()
	if err != nil {
		return err
	}
	if pending == nil || pending.ID != id {
		return nil // undone in the meantime; nothing to confirm
	}
	return s.confirmLocked(pending, proof)
}

func (s *System) confirmLocked(pending *Pending, proof *Login) error {
	if err := os.MkdirAll(filepath.Dir(s.Paths.StateFile), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pending.Config, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.Paths.StateFile, append(data, '\n')); err != nil {
		return fmt.Errorf("save the confirmed configuration: %w", err)
	}
	removeIfExists(s.Paths.pendingFile())
	s.recordOutcome(Outcome{ID: pending.ID, Result: ResultConfirmed, Proof: proof, At: s.Now().UTC()})
	s.Log.Info("SSH change confirmed", "id", pending.ID, "keysOnly", pending.Config.KeysOnly, "keys", len(pending.Config.Keys))
	return nil
}

// Revert puts the confirmed configuration back if a change is pending, and
// does nothing otherwise.
func (s *System) Revert(ctx context.Context, result, message string) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return s.revertLocked(ctx, result, message)
}

func (s *System) revertLocked(ctx context.Context, result, message string) error {
	// Undoing is never cut short (see internal/firewall).
	ctx = context.WithoutCancel(ctx)
	pending, readErr := s.readPending()
	if readErr == nil && pending == nil {
		return nil
	}
	safe, restoreErr := s.restoreConfirmed(ctx)
	if !safe {
		// The unconfirmed settings may still be in effect. The change stays
		// marked as pending, so that whatever runs next tries again instead
		// of finding nothing to do (see internal/firewall).
		s.Log.Error("undoing the SSH change failed; it stays marked as pending", "error", restoreErr)
		return restoreErr
	}
	removeIfExists(s.Paths.pendingFile())

	outcome := Outcome{Result: result, Message: message, At: s.Now().UTC()}
	if pending != nil {
		outcome.ID = pending.ID
	}
	if restoreErr != nil {
		outcome.Result = ResultFailed
		outcome.Message = "the change was undone, but not cleanly: " + restoreErr.Error()
	}
	s.recordOutcome(outcome)
	s.Log.Info("SSH change undone", "id", outcome.ID, "result", outcome.Result, "message", outcome.Message)
	return restoreErr
}

// restoreConfirmed writes the confirmed configuration to disk again and has
// the SSH server take it up. If even that is refused, SGC's settings file
// is taken away altogether: the machine's own SSH settings are better than
// a configuration nobody confirmed.
//
// safe reports whether the unconfirmed settings are out of effect. It can be
// true together with an error: the confirmed ones would not go back in, and
// the machine's own apply now.
func (s *System) restoreConfirmed(ctx context.Context) (safe bool, err error) {
	state, err := ReadState(s.Paths)
	if err == nil {
		_, err = s.apply(ctx, state.Confirmed)
	}
	if err == nil {
		return true, nil
	}
	if removeErr := removeIfExists(s.Paths.DropIn); removeErr != nil {
		return false, fmt.Errorf("%w; and SGC's settings could not be taken out: %v", err, removeErr)
	}
	if _, reloadErr := s.reload(ctx); reloadErr != nil {
		return false, fmt.Errorf("%w; and without SGC's settings: %v", err, reloadErr)
	}
	return true, fmt.Errorf("%w; SGC's SSH settings were taken out, the device's own apply", err)
}

// Restore writes the confirmed configuration to disk. It runs when the
// machine starts, before the SSH server does: a change that was waiting for
// its proof when the machine went down is thereby undone, like any other
// unconfirmed change.
//
// It also runs while the machine is up: every time SGC's own service starts
// (which wants this unit), and when the owner follows the doctor's advice
// after SGC's files were changed behind its back. There it must not get in
// the way of anything:
//
//   - A change that waits for its proof is left to its own ways out. Putting
//     the confirmed settings back under it would undo it without anybody
//     having asked.
//   - Files that are as they should be leave the SSH server alone.
//   - If something did have to be put back, the server is asked to take it up
//     and the answer is not waited for. It would never come: the unit this
//     runs in is ordered before the SSH server's, so systemd holds the
//     server's reload back until this has finished.
func (s *System) Restore(ctx context.Context) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	_, activeErr := s.Run(ctx, systemctl, "is-active", "--quiet", serviceUnit)
	serverRuns := activeErr == nil

	if serverRuns {
		pending, err := s.readPending()
		if err != nil {
			return fmt.Errorf("read the record of the change in progress: %w", err)
		}
		if pending != nil {
			s.Log.Info("an SSH change is waiting for its proof; the files are left to it", "id", pending.ID)
			return nil
		}
	} else {
		// Start-up, or a machine whose SSH server is started per connection.
		// Nothing can be waiting for a login; a record that says so is left
		// over (/run survives some kinds of restart) and goes with the
		// settings it describes.
		removeIfExists(s.Paths.pendingFile())
	}
	if _, err := os.Stat(s.Paths.StateFile); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(s.Paths.DropIn); errors.Is(err, os.ErrNotExist) {
			return nil // SGC never touched the SSH server here
		}
	}
	state, err := ReadState(s.Paths)
	if err != nil {
		return err
	}
	changed, err := s.write(state.Confirmed)
	if err != nil {
		return err
	}
	if !changed || !serverRuns {
		return nil
	}
	s.Log.Info("SGC's SSH settings were not as confirmed and have been put back; asking the SSH server to take them up")
	if output, err := s.Run(ctx, systemctl, "reload", "--no-block", serviceUnit); err != nil {
		return fmt.Errorf("the SSH server could not be asked to take up the settings: %s", lastLine(output, err))
	}
	return nil
}

// AllowPasswords switches "keys only" off for good, without waiting for
// anything: it only adds ways of logging in. It is offered on the command
// line, for someone at the machine whose key no longer works.
func (s *System) AllowPasswords(ctx context.Context) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.revertLocked(ctx, ResultUndone, "passwords were allowed again at the device"); err != nil {
		return err
	}
	state, err := ReadState(s.Paths)
	if err != nil {
		return err
	}
	cfg := state.Confirmed
	cfg.KeysOnly = false
	pending := &Pending{ID: s.Now().UnixMilli(), Config: cfg, StartedAt: s.Now().UTC()}
	if err := writeJSONFile(s.Paths.pendingFile(), pending); err != nil {
		return err
	}
	if _, err := s.apply(ctx, cfg); err != nil {
		s.revertLocked(ctx, ResultFailed, err.Error())
		return err
	}
	return s.confirmLocked(pending, nil)
}

func (s *System) readRequest() (Config, error) {
	var request Config
	data, err := readSmallFile(s.Paths.RequestFile)
	if err != nil {
		return request, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	return request, nil
}

func (s *System) readPending() (*Pending, error) {
	var pending Pending
	found, err := readJSONFile(s.Paths.pendingFile(), &pending)
	if err != nil || !found {
		return nil, err
	}
	return &pending, nil
}

func (s *System) recordOutcome(outcome Outcome) {
	if err := writeJSONFile(s.Paths.outcomeFile(), outcome); err != nil {
		s.Log.Error("record the SSH change's outcome", "error", err)
	}
}

// lock makes the jobs take turns.
func (s *System) lock() (unlock func(), err error) {
	if err := os.MkdirAll(s.Paths.RunDir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.Paths.lockFile(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Uptime returns the seconds since the machine started.
func Uptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("/proc/uptime is empty")
	}
	return strconv.ParseFloat(fields[0], 64)
}

// --- Careful file handling -----------------------------------------------------

const maxStateFile = 256 * 1024

func readJSONFile(path string, v any) (found bool, err error) {
	data, err := readSmallFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

// readSmallFile reads a plain file without following a symbolic link.
func readSmallFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStateFile {
		return nil, fmt.Errorf("%s is larger than expected", path)
	}
	return data, nil
}

// writeFileAtomic replaces a file so that a reader, or a power cut, finds
// either the old content or the new, and has the new content on disk before
// it returns. Mode 0644: everything written here is public and must be
// readable by the SSH server whatever account it serves.
func writeFileAtomic(path string, data []byte) error {
	temporary := path + ".new"
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(temporary)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Chmod(0o644); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

// holds reports whether path is a plain file with exactly this content and
// the permissions writeFileAtomic gives.
func holds(path string, data []byte) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
		return false
	}
	current, err := readSmallFile(path)
	return err == nil && bytes.Equal(current, data)
}

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// sameKeys reports whether two configurations list the same keys.
func sameKeys(a, b Config) bool {
	if len(a.Keys) != len(b.Keys) {
		return false
	}
	for _, key := range a.Keys {
		if !b.hasKey(key.Fingerprint) {
			return false
		}
	}
	return true
}

// Equal reports whether two configurations are the same in effect. The
// order of the keys does not matter.
func (c Config) Equal(other Config) bool {
	return c.Account == other.Account && c.KeysOnly == other.KeysOnly && sameKeys(c, other)
}
