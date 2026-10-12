package sshd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/sshkeys"
)

// machine stands in for a real one with an SSH server. Its "server" reads
// SGC's settings file the way the real one would (the first value wins, and
// SGC's file comes first), keeps running with what it last took up, and
// writes a log.
type machine struct {
	t      *testing.T
	system *System

	mu      sync.Mutex
	calls   []string
	now     time.Time
	uptime  float64
	journal []journalEntry

	hasServer bool
	running   bool
	// Settings the machine has apart from SGC's file.
	own map[string]string
	// A setting somewhere else on the machine that beats SGC's file.
	override map[string]string
	// The server refuses its configuration.
	broken bool
	// The server dies when asked to take up the configuration.
	diesOnReload bool
	// Asking the server to take up the configuration fails, as when the
	// program doing the asking is killed half-way.
	reloadErr error
	// The caller runs in the unit that is ordered before the SSH server's.
	// systemd then holds a reload of the server back until that unit has
	// finished, so asking for one and waiting for it never returns (until
	// whoever asked is killed, which is what happened on a real machine).
	inBootUnit bool
	// What the running server last took up from SGC's file.
	live string
}

func newMachine(t *testing.T) *machine {
	t.Helper()
	dir := t.TempDir()
	m := &machine{
		t:         t,
		now:       time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC),
		uptime:    5000,
		hasServer: true,
		running:   true,
		own: map[string]string{
			"passwordauthentication":       "yes",
			"kbdinteractiveauthentication": "no",
			"permitrootlogin":              "without-password",
			"pubkeyauthentication":         "yes",
			"loglevel":                     "INFO",
			"authorizedkeysfile":           defaultKeyFiles,
		},
		override: map[string]string{},
	}
	passwd := filepath.Join(dir, "passwd")
	os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/bash\nsgc:x:999:999::/var/lib/sgc:/usr/sbin/nologin\nalex:x:1000:1000::/home/alex:/bin/bash\nrobin:x:1001:1001::/home/robin:/bin/bash\n"), 0o644)
	if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	m.system = &System{
		Paths: Paths{
			StateFile:   filepath.Join(dir, "etc", "state.json"),
			KeysDir:     filepath.Join(dir, "etc", "keys"),
			DropIn:      filepath.Join(dir, "sshd_config.d", "00-sgc.conf"),
			RunDir:      filepath.Join(dir, "run"),
			RequestFile: filepath.Join(dir, "request.json"),
			PasswdFile:  passwd,
		},
		Window: ProofWindow,
		Run:    m.run,
		Exists: func(string) bool { m.mu.Lock(); defer m.mu.Unlock(); return m.hasServer },
		Uptime: func() (float64, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.uptime, nil },
		Now:    func() time.Time { m.mu.Lock(); defer m.mu.Unlock(); return m.now },
		Sleep:  func(time.Duration) {},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return m
}

// effective is what "sshd -T" would print for the files on disk.
func (m *machine) effective() string {
	values := map[string]string{}
	set := func(name, value string) {
		if _, seen := values[name]; !seen {
			values[name] = value
		}
	}
	for name, value := range m.override {
		set(name, value)
	}
	dropIn, _ := os.ReadFile(m.system.Paths.DropIn)
	for line := range strings.Lines(string(dropIn)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, _ := strings.Cut(line, " ")
		set(strings.ToLower(name), value)
	}
	for name, value := range m.own {
		set(name, value)
	}
	var b strings.Builder
	for name, value := range values {
		fmt.Fprintf(&b, "%s %s\n", name, value)
	}
	return b.String()
}

func (m *machine) run(ctx context.Context, program string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		m.calls = append(m.calls, filepath.Base(program)+" (not run: cancelled)")
		return nil, ctx.Err()
	}
	call := filepath.Base(program) + " " + strings.Join(args, " ")
	switch {
	case program == sshdProgram && args[0] == "-t":
		m.calls = append(m.calls, "sshd -t")
		if m.broken {
			return []byte("/etc/ssh/sshd_config.d/00-sgc.conf line 3: Bad configuration option: Nonsense\n"), errors.New("exit status 255")
		}
		return nil, nil
	case program == sshdProgram && args[0] == "-T":
		if m.broken {
			return []byte("Bad configuration option\n"), errors.New("exit status 255")
		}
		return []byte(m.effective()), nil
	case program == systemctl && args[0] == "is-active":
		if m.running && args[len(args)-1] == serviceUnit {
			return nil, nil
		}
		return nil, errors.New("exit status 3")
	case program == systemctl && args[0] == "reload":
		if args[1] == "--no-block" {
			m.calls = append(m.calls, "reload --no-block")
		} else {
			m.calls = append(m.calls, "reload")
			if m.inBootUnit {
				return nil, errors.New("signal: killed")
			}
		}
		if m.reloadErr != nil {
			return nil, m.reloadErr
		}
		if m.diesOnReload {
			m.running = false
			return nil, nil
		}
		dropIn, _ := os.ReadFile(m.system.Paths.DropIn)
		m.live = string(dropIn)
		m.journal = append(m.journal, journalEntry{Message: "Server listening on 0.0.0.0 port 22.", At: m.now})
		return nil, nil
	case program == journalctl:
		var b strings.Builder
		for _, entry := range m.journal {
			line, _ := json.Marshal(map[string]string{"MESSAGE": entry.Message, "__REALTIME_TIMESTAMP": fmt.Sprint(entry.At.UnixMicro())})
			b.Write(line)
			b.WriteByte('\n')
		}
		return []byte(b.String()), nil
	}
	m.t.Errorf("unexpected program: %s", call)
	return nil, errors.New("unexpected")
}

// pass moves the clock.
func (m *machine) pass(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(d)
	m.uptime += d.Seconds()
}

// login makes the server log a successful key login, now.
func (m *machine) login(account string, key sshkeys.Key) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.journal = append(m.journal, journalEntry{
		Message: fmt.Sprintf("Accepted publickey for %s from 192.168.1.20 port 50000 ssh2: %s %s", account, key.Kind(), key.Fingerprint),
		At:      m.now,
	})
}

func (m *machine) request(cfg Config) {
	m.t.Helper()
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(m.system.Paths.RequestFile, data, 0o600); err != nil {
		m.t.Fatal(err)
	}
}

func (m *machine) state() State {
	m.t.Helper()
	state, err := ReadState(m.system.Paths)
	if err != nil {
		m.t.Fatal(err)
	}
	return state
}

// passwordsWork reports whether the running server lets passwords in.
func (m *machine) passwordsWork() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !strings.Contains(m.live, "PasswordAuthentication no")
}

func (m *machine) keysOnDisk(account string) string {
	data, _ := os.ReadFile(filepath.Join(m.system.Paths.KeysDir, account))
	return string(data)
}

func (m *machine) reloads() int { return m.count("reload") }

// count is how often a program was run in a certain way.
func (m *machine) count(call string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, made := range m.calls {
		if made == call {
			n++
		}
	}
	return n
}

// change runs Change the way the unit does. It returns once the change is in
// effect; wait then returns what Change returned.
func (m *machine) change(ctx context.Context, cfg Config) (wait func() error) {
	m.t.Helper()
	m.request(cfg)
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- m.system.Change(ctx, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		m.t.Fatalf("the change did not take effect: %v", err)
	case <-time.After(5 * time.Second):
		m.t.Fatal("the change did not report being ready")
	}
	return func() error {
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			m.t.Fatal("the change is still waiting")
			return nil
		}
	}
}

// mustChange makes a change that needs no proof and checks it went through.
func (m *machine) mustChange(cfg Config) {
	m.t.Helper()
	if err := m.change(context.Background(), cfg)(); err != nil {
		m.t.Fatal(err)
	}
	if state := m.state(); state.Pending != nil || !state.Confirmed.Equal(cfg) {
		m.t.Fatalf("after the change: %+v", state)
	}
}

var withKey = Config{Account: "alex", Keys: []sshkeys.Key{keyOne}}
var keysOnly = Config{Account: "alex", Keys: []sshkeys.Key{keyOne}, KeysOnly: true}

func TestAddingAKeyTakesEffectAtOnce(t *testing.T) {
	m := newMachine(t)
	m.mustChange(withKey)

	if got := m.keysOnDisk("alex"); got != keyOne.Line()+"\n" {
		t.Errorf("keys file = %q", got)
	}
	info, err := os.Stat(filepath.Join(m.system.Paths.KeysDir, "alex"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("keys file mode: %v, %v", info, err)
	}
	if !strings.Contains(m.live, "AuthorizedKeysFile "+defaultKeyFiles+" "+m.system.Paths.KeysDir+"/%u") {
		t.Errorf("the server was not told about the keys file:\n%s", m.live)
	}
	if !m.passwordsWork() {
		t.Error("adding a key switched passwords off")
	}
	if last := m.state().Last; last == nil || last.Result != ResultConfirmed || last.Proof != nil {
		t.Errorf("outcome: %+v", last)
	}

	// A second key, and then the first one taken away: still no proof needed.
	m.mustChange(Config{Account: "alex", Keys: []sshkeys.Key{keyOne, keyTwo}})
	m.mustChange(Config{Account: "alex", Keys: []sshkeys.Key{keyTwo}})
	if got := m.keysOnDisk("alex"); got != keyTwo.Line()+"\n" {
		t.Errorf("keys file = %q", got)
	}
	// The last key gone: nothing of SGC's is left.
	m.mustChange(Config{})
	if _, err := os.Stat(m.system.Paths.DropIn); !errors.Is(err, os.ErrNotExist) {
		t.Error("SGC's settings file is still there")
	}
	if entries, _ := os.ReadDir(m.system.Paths.KeysDir); len(entries) != 0 {
		t.Errorf("key files left: %v", entries)
	}
}

func TestKeysOnlyStaysWhenAKeyLoginIsSeen(t *testing.T) {
	m := newMachine(t)
	m.mustChange(withKey)
	// A login from before the change proves nothing about the change.
	m.login("alex", keyOne)
	m.pass(time.Second)

	wait := m.change(context.Background(), keysOnly)
	state := m.state()
	if state.Pending == nil || !state.Pending.NeedsProof || state.Confirmed.KeysOnly {
		t.Fatalf("after switching: %+v", state)
	}
	if m.passwordsWork() {
		t.Fatal("passwords still work while the change is in effect")
	}
	if left := state.Pending.SecondsLeft(m.uptime); left != 120 {
		t.Errorf("seconds left: %d", left)
	}

	m.pass(30 * time.Second)
	time.Sleep(1200 * time.Millisecond)
	if m.state().Pending == nil {
		t.Fatal("confirmed by a login from before the change")
	}
	// Root logging in with a key is no proof either: root is about to be shut out.
	m.login("root", keyOne)
	time.Sleep(1200 * time.Millisecond)
	if m.state().Pending == nil {
		t.Fatal("confirmed by a login as root")
	}

	m.login("alex", keyTwo)
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	state = m.state()
	if state.Pending != nil || !state.Confirmed.KeysOnly {
		t.Fatalf("after the login: %+v", state)
	}
	if state.Last.Result != ResultConfirmed || state.Last.Proof == nil || state.Last.Proof.Account != "alex" || state.Last.Proof.Fingerprint != keyTwo.Fingerprint {
		t.Errorf("outcome: %+v, proof %+v", state.Last, state.Last.Proof)
	}
	if m.passwordsWork() {
		t.Error("passwords work after confirmation")
	}
}

func TestKeysOnlyIsUndoneWithoutAKeyLogin(t *testing.T) {
	m := newMachine(t)
	m.mustChange(withKey)
	wait := m.change(context.Background(), keysOnly)

	m.pass(ProofWindow - time.Second)
	time.Sleep(1200 * time.Millisecond)
	if m.state().Pending == nil {
		t.Fatal("undone before the time was up")
	}
	m.pass(2 * time.Second)
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	state := m.state()
	if state.Pending != nil || state.Confirmed.KeysOnly || state.Last.Result != ResultExpired {
		t.Fatalf("after the time ran out: %+v, outcome %+v", state, state.Last)
	}
	if !m.passwordsWork() {
		t.Error("passwords do not work again")
	}
	// The key that was there before is still there.
	if got := m.keysOnDisk("alex"); got != keyOne.Line()+"\n" {
		t.Errorf("keys file = %q", got)
	}
	// A login now is too late to confirm anything.
	m.login("alex", keyOne)
	time.Sleep(100 * time.Millisecond)
	if m.state().Confirmed.KeysOnly {
		t.Error("a late login confirmed the change")
	}
}

func TestUndoOnRequest(t *testing.T) {
	m := newMachine(t)
	ctx, cancel := context.WithCancel(context.Background())
	wait := m.change(ctx, Config{KeysOnly: true})
	if m.passwordsWork() {
		t.Fatal("not in effect")
	}
	cancel()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if state := m.state(); state.Pending != nil || state.Confirmed.KeysOnly || state.Last.Result != ResultUndone {
		t.Fatalf("after undoing: %+v, outcome %+v", state, state.Last)
	}
	if !m.passwordsWork() {
		t.Error("passwords do not work again")
	}
	if _, err := os.Stat(m.system.Paths.DropIn); !errors.Is(err, os.ErrNotExist) {
		t.Error("SGC's settings file is still there although nothing of SGC's is confirmed")
	}
}

func TestTakingAKeyAwayUnderKeysOnlyNeedsProof(t *testing.T) {
	m := newMachine(t)
	both := Config{Account: "alex", Keys: []sshkeys.Key{keyOne, keyTwo}}
	m.mustChange(both)
	bothOnly := both
	bothOnly.KeysOnly = true
	wait := m.change(context.Background(), bothOnly)
	m.pass(time.Second)
	m.login("alex", keyOne)
	if err := wait(); err != nil {
		t.Fatal(err)
	}

	// Taking key one away. Nobody logs in: it comes back.
	wait = m.change(context.Background(), Config{Account: "alex", Keys: []sshkeys.Key{keyTwo}, KeysOnly: true})
	if got := m.keysOnDisk("alex"); got != keyTwo.Line()+"\n" {
		t.Fatalf("while waiting, keys file = %q", got)
	}
	m.pass(ProofWindow + time.Second)
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if got := m.keysOnDisk("alex"); got != keyOne.Line()+"\n"+keyTwo.Line()+"\n" {
		t.Errorf("after the time ran out, keys file = %q", got)
	}
	if state := m.state(); !state.Confirmed.KeysOnly || len(state.Confirmed.Keys) != 2 {
		t.Errorf("confirmed: %+v", state.Confirmed)
	}
	if m.passwordsWork() {
		t.Error("undoing a key removal switched passwords back on")
	}
}

func TestRefusedBeforeAnythingIsTouched(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*machine)
		cfg     Config
		message string
	}{
		{"no SSH server", func(m *machine) { m.hasServer = false }, withKey, "no SSH server"},
		{"keys kept in a place of the machine's own", func(m *machine) { m.own["authorizedkeysfile"] = "/etc/ssh/keys/%u" }, withKey, "its own place"},
		{"logins not logged", func(m *machine) { m.own["loglevel"] = "ERROR" }, Config{KeysOnly: true}, "not to log logins"},
		{"an account that cannot log in", func(*machine) {}, Config{Account: "sgc", Keys: []sshkeys.Key{keyOne}}, "no account"},
		{"root", func(*machine) {}, Config{Account: "root", Keys: []sshkeys.Key{keyOne}}, "no account"},
		{"not a key", func(*machine) {}, Config{Account: "alex", Keys: []sshkeys.Key{{Type: "ssh-ed25519", Blob: "AAAA"}}}, "not usable"},
		{"a configuration the server already refuses", func(m *machine) { m.broken = true }, withKey, "does not accept"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMachine(t)
			c.prepare(m)
			m.request(c.cfg)
			err := m.system.Change(context.Background(), func() { t.Error("reported ready") })
			if err == nil || !strings.Contains(err.Error(), c.message) {
				t.Fatalf("error: %v", err)
			}
			if m.reloads() != 0 {
				t.Error("the server was told to take up something")
			}
			if _, err := os.Stat(m.system.Paths.DropIn); !errors.Is(err, os.ErrNotExist) {
				t.Error("a settings file was written")
			}
			if state := m.state(); state.Pending != nil || state.Last == nil || state.Last.Result != ResultFailed {
				t.Errorf("state: %+v, outcome %+v", state, state.Last)
			}
		})
	}

	// Requests are read strictly.
	for _, text := range []string{``, `{`, `{"keysOnly":"yes"}`, `{"keysOnly":true,"extra":1}`, `{"account":"alex","keys":[{"type":"ssh-ed25519","blob":"x","options":"command"}]}`} {
		m := newMachine(t)
		os.WriteFile(m.system.Paths.RequestFile, []byte(text), 0o600)
		if err := m.system.Change(context.Background(), func() { t.Errorf("%q: reported ready", text) }); err == nil {
			t.Errorf("%q was accepted", text)
		}
	}
}

func TestAFailedChangeLeavesTheConfirmedConfiguration(t *testing.T) {
	// The server refuses the new file.
	m := newMachine(t)
	m.mustChange(withKey)
	before := m.live
	m.broken = true
	// It only starts refusing with the new content; the settings beforehand
	// are still readable. Simulated by breaking it after the first look.
	m.broken = false
	m.override["passwordauthentication"] = "yes" // something else on the machine wins
	m.request(keysOnly)
	err := m.system.Change(context.Background(), func() { t.Error("reported ready") })
	if err == nil || !strings.Contains(err.Error(), "overrides") {
		t.Fatalf("error: %v", err)
	}
	if state := m.state(); state.Pending != nil || state.Confirmed.KeysOnly || state.Last.Result != ResultFailed {
		t.Fatalf("state: %+v, outcome %+v", state, state.Last)
	}
	dropIn, _ := os.ReadFile(m.system.Paths.DropIn)
	if strings.Contains(string(dropIn), "PasswordAuthentication") || string(dropIn) != before {
		t.Errorf("the settings file is not the confirmed one:\n%s", dropIn)
	}

	// The server dies when told to take up the change.
	m = newMachine(t)
	m.diesOnReload = true
	m.request(withKey)
	if err := m.system.Change(context.Background(), func() { t.Error("reported ready") }); err == nil {
		t.Fatal("no error")
	}
	if state := m.state(); state.Pending != nil || state.Confirmed.managesKeys() {
		t.Errorf("state: %+v", state)
	}
	if _, err := os.Stat(m.system.Paths.DropIn); !errors.Is(err, os.ErrNotExist) {
		t.Error("a settings file was left behind")
	}
}

// The process dies in the middle: the files on disk are the new ones, and
// nothing is confirmed. Whatever runs next must clean that up.
func TestAnInterruptedChangeIsCleanedUp(t *testing.T) {
	m := newMachine(t)
	m.mustChange(withKey)
	m.request(keysOnly)
	if _, err := m.system.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.passwordsWork() {
		t.Fatal("not in effect")
	}

	// What systemd runs after the process has ended.
	if err := m.system.Revert(context.Background(), ResultUndone, "interrupted"); err != nil {
		t.Fatal(err)
	}
	if state := m.state(); state.Pending != nil || state.Confirmed.KeysOnly || state.Last.Result != ResultUndone {
		t.Fatalf("state: %+v, outcome %+v", state, state.Last)
	}
	if !m.passwordsWork() {
		t.Error("passwords do not work again")
	}
	// Reverting with nothing pending does nothing.
	reloads := m.reloads()
	if err := m.system.Revert(context.Background(), ResultUndone, ""); err != nil || m.reloads() != reloads {
		t.Errorf("reverting again: %v, reloads %d -> %d", err, reloads, m.reloads())
	}

	// And with a cancelled context the undoing still happens.
	m.request(keysOnly)
	if _, err := m.system.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.system.Revert(cancelled, ResultUndone, ""); err != nil {
		t.Fatal(err)
	}
	if !m.passwordsWork() {
		t.Error("a cancelled undo left the change in effect")
	}
}

// The undoing itself fails half-way (see the same test for the firewall).
// The unconfirmed settings are then still what the server runs with, and the
// change must stay marked as pending so that the next attempt finds it.
func TestAFailedUndoStaysPendingUntilItSucceeds(t *testing.T) {
	m := newMachine(t)
	m.mustChange(withKey)
	ctx, cancel := context.WithCancel(context.Background())
	wait := m.change(ctx, keysOnly)
	id := m.state().Pending.ID

	m.mu.Lock()
	m.reloadErr = errors.New("signal: terminated")
	m.mu.Unlock()
	cancel() // "undo now"
	if err := wait(); err == nil {
		t.Fatal("the failed undo was reported as done")
	}
	if state := m.state(); state.Pending == nil || state.Pending.ID != id {
		t.Fatalf("the change is no longer marked as pending although the server still runs with it: %+v", state)
	}
	if m.passwordsWork() {
		t.Fatal("the test did not leave the unconfirmed settings in effect")
	}

	m.mu.Lock()
	m.reloadErr = nil
	m.mu.Unlock()
	if err := m.system.Revert(context.Background(), ResultUndone, "interrupted"); err != nil {
		t.Fatal(err)
	}
	state := m.state()
	if state.Pending != nil || state.Last == nil || state.Last.ID != id || state.Last.Result != ResultUndone {
		t.Fatalf("after the second attempt: %+v, outcome %+v", state, state.Last)
	}
	if !m.passwordsWork() {
		t.Error("passwords do not work again")
	}
	if !m.state().Confirmed.managesKeys() || m.keysOnDisk("alex") != keyOne.Line()+"\n" {
		t.Error("the confirmed key was lost on the way")
	}
}

// The machine restarts while a change waits for its proof. The files of the
// unconfirmed change are still on disk; before the SSH server starts they
// must be the confirmed ones again.
func TestRestoreAtStartUp(t *testing.T) {
	m := newMachine(t)
	m.mustChange(withKey)
	m.request(keysOnly)
	if _, err := m.system.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The restart: /run is emptied, nothing runs yet.
	os.RemoveAll(m.system.Paths.RunDir)
	m.running = false
	reloads := m.reloads()

	if err := m.system.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	dropIn, _ := os.ReadFile(m.system.Paths.DropIn)
	if strings.Contains(string(dropIn), "PasswordAuthentication") || !strings.Contains(string(dropIn), "AuthorizedKeysFile") {
		t.Errorf("settings file after the restart:\n%s", dropIn)
	}
	if m.reloads() != reloads {
		t.Error("a server that is not running was told to reload")
	}
	if state := m.state(); state.Pending != nil || state.Confirmed.KeysOnly {
		t.Errorf("state: %+v", state)
	}

	// On a machine SGC never touched, nothing is created.
	fresh := newMachine(t)
	fresh.running = false
	if err := fresh.system.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fresh.system.Paths.KeysDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("a keys folder was created on an untouched machine")
	}
}

// The same job also runs while the machine is up: whenever SGC's service
// starts, and when the owner follows the doctor's advice. It runs in the unit
// that is ordered before the SSH server's, where waiting for the server to
// reload never ends. On a real machine that made every start of SGC's service
// hang for twenty seconds and leave a failed unit behind.
func TestRestoreOnARunningMachine(t *testing.T) {
	m := newMachine(t)
	m.confirmKeysOnly()
	m.mu.Lock()
	m.inBootUnit = true
	m.mu.Unlock()
	calls := func() (blocking, queued int) { return m.count("reload"), m.count("reload --no-block") }
	blockingBefore, _ := calls()

	// Nothing was touched: the server is left alone.
	if err := m.system.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if blocking, queued := calls(); blocking != blockingBefore || queued != 0 {
		t.Fatalf("the server was told to reload although nothing had changed (%d waited for, %d queued)", blocking-blockingBefore, queued)
	}

	// SGC's files were taken away behind its back, and the server runs
	// without them.
	os.Remove(m.system.Paths.DropIn)
	os.Remove(filepath.Join(m.system.Paths.KeysDir, "alex"))
	m.mu.Lock()
	m.live = ""
	m.mu.Unlock()
	if err := m.system.Restore(context.Background()); err != nil {
		t.Fatalf("putting the settings back: %v", err)
	}
	if blocking, queued := calls(); blocking != blockingBefore || queued != 1 {
		t.Fatalf("reloads: %d waited for, %d queued; want none waited for and one queued", blocking-blockingBefore, queued)
	}
	if m.passwordsWork() {
		t.Error("passwords still work after the settings were put back")
	}
	if m.keysOnDisk("alex") != keyOne.Line()+"\n" {
		t.Error("the key was not put back")
	}

	// A file with the right content that the SSH server may not read counts
	// as changed too.
	os.Chmod(filepath.Join(m.system.Paths.KeysDir, "alex"), 0o600)
	if err := m.system.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, queued := calls(); queued != 2 {
		t.Error("a key file with the wrong permissions was not noticed")
	}
}

// While a change waits for its proof, the job leaves everything to it.
func TestRestoreLeavesAWaitingChangeAlone(t *testing.T) {
	m := newMachine(t)
	m.mustChange(withKey)
	wait := m.change(context.Background(), keysOnly)
	id := m.state().Pending.ID
	m.mu.Lock()
	m.inBootUnit = true
	m.mu.Unlock()
	reloads := m.count("reload") + m.count("reload --no-block")

	if err := m.system.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := m.state(); state.Pending == nil || state.Pending.ID != id {
		t.Fatalf("the waiting change is gone: %+v", state)
	}
	if m.passwordsWork() {
		t.Error("the waiting change was undone")
	}
	if m.count("reload")+m.count("reload --no-block") != reloads {
		t.Error("the server was told to reload")
	}

	// And it can still be kept.
	m.mu.Lock()
	m.inBootUnit = false
	m.mu.Unlock()
	m.pass(5 * time.Second)
	m.login("alex", keyOne)
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if !m.state().Confirmed.KeysOnly {
		t.Error("the change was not kept after the login")
	}
}

// confirmKeysOnly makes "keys only" the confirmed configuration, the way it
// gets there: a key first, then the switch, then a login with the key.
func (m *machine) confirmKeysOnly() {
	m.t.Helper()
	m.mustChange(withKey)
	wait := m.change(context.Background(), keysOnly)
	m.pass(5 * time.Second)
	m.login("alex", keyOne)
	if err := wait(); err != nil {
		m.t.Fatal(err)
	}
	if !m.state().Confirmed.KeysOnly {
		m.t.Fatal("keys only was not confirmed")
	}
}

func TestAllowPasswords(t *testing.T) {
	m := newMachine(t)
	m.mustChange(withKey)
	wait := m.change(context.Background(), keysOnly)
	m.pass(time.Second)
	m.login("alex", keyOne)
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if m.passwordsWork() {
		t.Fatal("keys only is not in effect")
	}

	if err := m.system.AllowPasswords(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := m.state()
	if state.Confirmed.KeysOnly || !state.Confirmed.managesKeys() || state.Pending != nil {
		t.Fatalf("state: %+v", state)
	}
	if !m.passwordsWork() {
		t.Error("passwords do not work")
	}
	if got := m.keysOnDisk("alex"); got != keyOne.Line()+"\n" {
		t.Errorf("the keys were touched: %q", got)
	}
}

func TestStatus(t *testing.T) {
	m := newMachine(t)
	m.login("alex", keyOne)
	m.pass(20 * time.Minute)
	m.login("robin", keyTwo)
	m.login("root", keyOne)
	m.pass(time.Minute)

	status, err := m.system.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed || !status.Running || !status.Settings.PasswordLogins || status.Settings.RootLogin != "key" || !status.Settings.LoginsVisible {
		t.Errorf("status: %+v", status)
	}
	if strings.Join(status.Accounts, ",") != "alex,robin" {
		t.Errorf("accounts: %v", status.Accounts)
	}
	// Only the recent login of an account that counts.
	if len(status.Logins) != 1 || status.Logins[0].Account != "robin" || status.Logins[0].Fingerprint != keyTwo.Fingerprint {
		t.Errorf("logins: %+v", status.Logins)
	}

	m.hasServer = false
	if status, err := m.system.Status(context.Background()); err != nil || status.Installed {
		t.Errorf("without an SSH server: %+v, %v", status, err)
	}
}
