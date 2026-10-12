package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Programs the root side runs: fixed paths, fixed arguments.
const (
	NftProgram  = "/usr/sbin/nft"
	sshdProgram = "/usr/sbin/sshd"
)

// ConfirmWindow is how long a change stays in effect without confirmation.
const ConfirmWindow = 60 * time.Second

var (
	ErrNotInstalled   = errors.New("the firewall software (nftables) is not installed")
	ErrNothingPending = errors.New("no firewall change is waiting for confirmation; it has already been undone")
)

// System carries out firewall changes. It runs as root, in units of its own
// (see installer/sgc-firewall-*.service), never inside the web process.
//
// How a change works, and why it cannot lock the owner out:
//
//  1. Change puts new rules into effect and then stays running. From that
//     moment the rules are "pending": active, but not what the machine
//     starts with.
//  2. Confirm, called within ConfirmWindow, makes them the confirmed rules.
//  3. Otherwise Change puts the confirmed rules back when the time is up.
//     If the Change process is killed instead, systemd runs Revert for it
//     (ExecStopPost), and if the whole machine goes down, it starts up with
//     the confirmed rules, because pending ones are only ever kept in memory.
type System struct {
	Paths   Paths
	WebPort int
	Window  time.Duration

	// Run runs a program and returns what it printed. Injected so that tests
	// need neither root nor nftables.
	Run func(ctx context.Context, program string, args ...string) ([]byte, error)
	// Exists reports whether a program is installed.
	Exists func(program string) bool
	Uptime func() (float64, error)
	Now    func() time.Time
	Log    *slog.Logger
}

// Change puts the requested rules into effect, calls ready, and then waits
// until they are confirmed, the time runs out, or ctx is cancelled (the
// owner chose "undo", or the machine is shutting down). In the last two
// cases it puts the confirmed rules back before returning.
//
// An error means the new rules never took effect.
func (s *System) Change(ctx context.Context, ready func()) error {
	pending, err := s.begin(ctx)
	if err != nil {
		return err
	}
	ready()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// The undoing itself must not be cut short by the cancellation.
			return s.Revert(context.WithoutCancel(ctx), ResultUndone, "")
		case <-ticker.C:
		}
		current, err := s.readPending()
		if err == nil && (current == nil || current.ID != pending.ID) {
			return nil // confirmed, or undone, by another job
		}
		uptime, err := s.Uptime()
		// Not being able to tell the time counts as time being up: undoing
		// too early is an inconvenience, too late is a lock-out.
		if err != nil || uptime >= pending.DeadlineUptime {
			return s.Revert(ctx, ResultExpired, "")
		}
	}
}

func (s *System) begin(ctx context.Context) (*Pending, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Only one Change runs at a time (systemd does not start a unit twice),
	// so a pending change found here was left behind by one that died
	// without cleaning up. Undo it before doing anything else.
	if err := s.revertLocked(ctx, ResultUndone, "the wait for confirmation was interrupted"); err != nil {
		return nil, err
	}

	id := s.Now().UnixMilli()
	fail := func(err error) (*Pending, error) {
		s.recordOutcome(Outcome{ID: id, Result: ResultFailed, Message: err.Error(), At: s.Now().UTC()})
		return nil, err
	}

	request, err := s.readRequest()
	if err != nil {
		return fail(fmt.Errorf("read the request: %w", err))
	}
	if !s.Exists(NftProgram) {
		return fail(ErrNotInstalled)
	}
	ports, err := s.sshPorts(ctx)
	if err != nil {
		return fail(err)
	}
	cfg := Config{Enabled: request.Enabled, SSHPorts: ports, WebPort: s.WebPort}
	rules, err := Render(cfg)
	if err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(s.Paths.pendingRules(), []byte(rules), false); err != nil {
		return fail(err)
	}
	// Checked by nftables itself before anything is loaded (-c: check only).
	if output, err := s.Run(ctx, NftProgram, "-c", "-f", s.Paths.pendingRules()); err != nil {
		removeIfExists(s.Paths.pendingRules())
		return fail(fmt.Errorf("nftables did not accept the new rules: %s", lastLine(output, err)))
	}

	uptime, err := s.Uptime()
	if err != nil {
		removeIfExists(s.Paths.pendingRules())
		return fail(err)
	}
	pending := &Pending{
		ID:             id,
		Config:         cfg.normalised(),
		StartedAt:      s.Now().UTC(),
		DeadlineUptime: uptime + s.Window.Seconds(),
	}
	// Written before the rules are loaded: if this process dies right after
	// loading them, whatever cleans up must be able to see that there is
	// something to undo.
	if err := writeJSONFile(s.Paths.pendingFile(), pending); err != nil {
		removeIfExists(s.Paths.pendingRules())
		return fail(err)
	}
	if output, err := s.Run(ctx, NftProgram, "-f", s.Paths.pendingRules()); err != nil {
		// nftables loads a file completely or not at all, so the previous
		// rules should still be in effect; reverting makes sure of it.
		message := fmt.Sprintf("the new rules could not be loaded: %s", lastLine(output, err))
		s.revertLocked(ctx, ResultFailed, message)
		return nil, errors.New(message)
	}
	s.Log.Info("firewall change in effect, waiting for confirmation",
		"id", pending.ID, "enabled", cfg.Enabled, "seconds", int(s.Window.Seconds()))
	return pending, nil
}

// Confirm makes the pending rules the confirmed ones.
func (s *System) Confirm(ctx context.Context) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	pending, err := s.readPending()
	if err != nil {
		return err
	}
	if pending == nil {
		return ErrNothingPending
	}
	// A confirmation that arrives after the time is up loses: the undoing is
	// already on its way, and two outcomes for one change must not happen.
	if uptime, err := s.Uptime(); err != nil || uptime >= pending.DeadlineUptime {
		return ErrNothingPending
	}
	rules, err := readSmallFile(s.Paths.pendingRules())
	if err != nil {
		return err
	}
	// The rules being confirmed must be the ones the pending change describes.
	if described, err := ParseConfig(rules); err != nil || !described.Equal(pending.Config) {
		return errors.New("the pending rules do not match the pending change")
	}
	if err := os.MkdirAll(filepath.Dir(s.Paths.ConfirmedFile), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(s.Paths.ConfirmedFile, rules, true); err != nil {
		return fmt.Errorf("save the confirmed rules: %w", err)
	}
	removeIfExists(s.Paths.pendingFile())
	removeIfExists(s.Paths.pendingRules())
	s.recordOutcome(Outcome{ID: pending.ID, Result: ResultConfirmed, At: s.Now().UTC()})
	s.Log.Info("firewall change confirmed", "id", pending.ID, "enabled", pending.Config.Enabled)
	return nil
}

// Revert puts the confirmed rules back if a change is pending, and does
// nothing otherwise. result says why, for the record.
func (s *System) Revert(ctx context.Context, result, message string) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return s.revertLocked(ctx, result, message)
}

func (s *System) revertLocked(ctx context.Context, result, message string) error {
	pending, readErr := s.readPending()
	if readErr == nil && pending == nil {
		return nil
	}
	// An unreadable pending file still means something is pending.
	loadErr := s.loadConfirmed(ctx)
	removeIfExists(s.Paths.pendingFile())
	removeIfExists(s.Paths.pendingRules())

	outcome := Outcome{Result: result, Message: message, At: s.Now().UTC()}
	if pending != nil {
		outcome.ID = pending.ID
	}
	if loadErr != nil {
		outcome.Result = ResultFailed
		outcome.Message = "the change was undone, but the confirmed rules could not be loaded: " + loadErr.Error()
	}
	s.recordOutcome(outcome)
	s.Log.Info("firewall change undone", "id", outcome.ID, "result", outcome.Result, "message", outcome.Message)
	return loadErr
}

// loadConfirmed makes the confirmed rules the ones in effect. If they cannot
// be loaded it removes SGC's table altogether: no firewall is better than
// unconfirmed rules that may be keeping the owner out.
func (s *System) loadConfirmed(ctx context.Context) error {
	if !s.Exists(NftProgram) {
		return nil // without nftables nothing of ours can be loaded
	}
	var loadErr error
	if _, err := os.Stat(s.Paths.ConfirmedFile); err == nil {
		output, err := s.Run(ctx, NftProgram, "-f", s.Paths.ConfirmedFile)
		if err == nil {
			return nil
		}
		loadErr = errors.New(lastLine(output, err))
	}
	if output, err := s.Run(ctx, NftProgram, "destroy", "table", "inet", tableName); err != nil {
		return fmt.Errorf("remove the firewall table: %s", lastLine(output, err))
	}
	return loadErr
}

// Off switches the firewall off for good, without a confirmation period. It
// is the way back in for someone sitting at the machine itself, and is only
// offered on the command line.
func (s *System) Off(ctx context.Context) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	cfg := Config{Enabled: false, WebPort: s.WebPort}
	rules, err := Render(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Paths.ConfirmedFile), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(s.Paths.ConfirmedFile, []byte(rules), true); err != nil {
		return err
	}
	removeIfExists(s.Paths.pendingFile())
	removeIfExists(s.Paths.pendingRules())
	if err := s.loadConfirmed(ctx); err != nil {
		return err
	}
	s.recordOutcome(Outcome{ID: s.Now().UnixMilli(), Result: ResultConfirmed, At: s.Now().UTC()})
	return nil
}

// TableLoaded reports whether SGC's table is in the kernel right now.
func (s *System) TableLoaded(ctx context.Context) (bool, error) {
	if !s.Exists(NftProgram) {
		return false, nil
	}
	output, err := s.Run(ctx, NftProgram, "list", "tables", "inet")
	if err != nil {
		return false, errors.New(lastLine(output, err))
	}
	for line := range strings.Lines(string(output)) {
		if strings.TrimSpace(line) == "table inet "+tableName {
			return true, nil
		}
	}
	return false, nil
}

// sshPorts asks the SSH server which ports it listens on. No SSH server: no
// ports. A server whose configuration cannot be read: the standard port,
// because leaving SSH closed on a guess would be the worse mistake.
func (s *System) sshPorts(ctx context.Context) ([]int, error) {
	if !s.Exists(sshdProgram) {
		return nil, nil
	}
	// -T prints the configuration the server would run with.
	output, err := s.Run(ctx, sshdProgram, "-T")
	if err != nil {
		s.Log.Warn("could not read the SSH server's configuration; assuming port 22", "error", lastLine(output, err))
		return []int{22}, nil
	}
	var ports []int
	for line := range strings.Lines(string(output)) {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "port" {
			continue
		}
		port, err := strconv.Atoi(fields[1])
		if err != nil || !validPort(port) {
			return nil, fmt.Errorf("the SSH server reports an unusable port %q", fields[1])
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return []int{22}, nil
	}
	return ports, nil
}

func (s *System) readRequest() (Request, error) {
	var request Request
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
		s.Log.Error("record the firewall change's outcome", "error", err)
	}
}

// lock makes the jobs take turns: a confirmation and the undoing at the end
// of the waiting time must never run into each other.
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

// lastLine picks the most telling line of a program's output for a message.
func lastLine(output []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	// nftables puts the error first and then quotes the offending line.
	for _, line := range lines {
		if strings.Contains(line, "Error") {
			return strings.TrimSpace(line)
		}
	}
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		return last
	}
	return err.Error()
}
