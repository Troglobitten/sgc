package firewall

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// machine stands in for the real one: it records which programs were run and
// decides what they answer, and its clock is moved by hand.
type machine struct {
	t      *testing.T
	system *System

	mu       sync.Mutex
	calls    []string
	uptime   float64
	programs map[string]bool
	sshd     string // what "sshd -T" prints
	sshdErr  error
	checkErr error // "nft -c" refuses the rules
	loadErr  map[string]error
}

func newMachine(t *testing.T) *machine {
	t.Helper()
	dir := t.TempDir()
	m := &machine{
		t:        t,
		uptime:   1000,
		programs: map[string]bool{NftProgram: true, sshdProgram: true},
		sshd:     "port 22\nlistenaddress 0.0.0.0:22\npasswordauthentication no\n",
		loadErr:  map[string]error{},
	}
	m.system = &System{
		Paths: Paths{
			ConfirmedFile: filepath.Join(dir, "etc", "firewall.nft"),
			RunDir:        filepath.Join(dir, "run"),
			RequestFile:   filepath.Join(dir, "request.json"),
		},
		WebPort: 8443,
		Window:  60 * time.Second,
		Run:     m.run,
		Exists:  func(program string) bool { m.mu.Lock(); defer m.mu.Unlock(); return m.programs[program] },
		Uptime:  func() (float64, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.uptime, nil },
		Now:     time.Now,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return m
}

func (m *machine) run(_ context.Context, program string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// File names differ per test; record what kind of file it was.
	shown := make([]string, len(args))
	for i, arg := range args {
		switch arg {
		case m.system.Paths.pendingRules():
			arg = "<pending>"
		case m.system.Paths.ConfirmedFile:
			arg = "<confirmed>"
		}
		shown[i] = arg
	}
	call := filepath.Base(program) + " " + strings.Join(shown, " ")
	m.calls = append(m.calls, call)

	switch {
	case program == sshdProgram:
		return []byte(m.sshd), m.sshdErr
	case len(args) > 0 && args[0] == "-c":
		if m.checkErr != nil {
			return []byte("/run/pending.nft:12:3-8: Error: syntax error\n\tbanana\n\t^^^^^^\n"), m.checkErr
		}
	case len(args) > 0 && args[0] == "-f":
		if err := m.loadErr[shown[1]]; err != nil {
			return []byte("Error: could not process rule\n"), err
		}
	}
	return nil, nil
}

func (m *machine) advance(seconds float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uptime += seconds
}

func (m *machine) request(text string) {
	m.t.Helper()
	if err := os.WriteFile(m.system.Paths.RequestFile, []byte(text), 0o600); err != nil {
		m.t.Fatal(err)
	}
}

// nftCalls returns the nft commands run so far, leaving out the read-only ones.
func (m *machine) nftCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var calls []string
	for _, call := range m.calls {
		if strings.HasPrefix(call, "nft ") {
			calls = append(calls, call)
		}
	}
	return calls
}

func (m *machine) state() State {
	m.t.Helper()
	state, err := ReadState(m.system.Paths)
	if err != nil {
		m.t.Fatal(err)
	}
	return state
}

// startChange runs Change the way the unit does and returns once the new
// rules are in effect. The returned function waits for Change to end.
func (m *machine) startChange(ctx context.Context) (wait func() error) {
	m.t.Helper()
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
		case <-time.After(5 * time.Second):
			m.t.Fatal("the change is still waiting")
			return nil
		}
	}
}

func expectCalls(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("programs run:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestChangeThenConfirm(t *testing.T) {
	m := newMachine(t)
	m.request(`{"enabled":true}`)
	wait := m.startChange(context.Background())

	state := m.state()
	if state.Pending == nil || !state.Pending.Config.Enabled || state.Confirmed != nil {
		t.Fatalf("after the change: %+v", state)
	}
	if left := state.Pending.SecondsLeft(1000); left != 60 {
		t.Errorf("seconds left: %d, want 60", left)
	}

	m.advance(20)
	if err := m.system.Confirm(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wait(); err != nil {
		t.Fatal(err)
	}

	state = m.state()
	if state.Pending != nil || state.Confirmed == nil || !state.Confirmed.Enabled {
		t.Fatalf("after confirming: %+v", state)
	}
	if got := state.Confirmed.SSHPorts; len(got) != 1 || got[0] != 22 {
		t.Errorf("confirmed SSH ports: %v", got)
	}
	if state.Last == nil || state.Last.Result != ResultConfirmed {
		t.Errorf("outcome: %+v", state.Last)
	}
	// Checked, loaded, and never touched again: confirming loads nothing.
	expectCalls(t, m.nftCalls(), "nft -c -f <pending>", "nft -f <pending>")
}

func TestChangeWithoutConfirmationIsUndone(t *testing.T) {
	m := newMachine(t)
	m.request(`{"enabled":true}`)
	wait := m.startChange(context.Background())

	m.advance(59)
	time.Sleep(600 * time.Millisecond)
	if m.state().Pending == nil {
		t.Fatal("undone before the time was up")
	}
	m.advance(2)
	if err := wait(); err != nil {
		t.Fatal(err)
	}

	state := m.state()
	if state.Pending != nil || state.Confirmed != nil {
		t.Fatalf("after the time ran out: %+v", state)
	}
	if state.Last == nil || state.Last.Result != ResultExpired {
		t.Errorf("outcome: %+v", state.Last)
	}
	// Nothing was ever confirmed here, so "back" means no table at all.
	expectCalls(t, m.nftCalls(), "nft -c -f <pending>", "nft -f <pending>", "nft destroy table inet sgc")

	if err := m.system.Confirm(context.Background()); !errors.Is(err, ErrNothingPending) {
		t.Errorf("confirming afterwards: %v", err)
	}
}

func TestUndoGoesBackToTheConfirmedRules(t *testing.T) {
	m := newMachine(t)
	m.request(`{"enabled":true}`)
	wait := m.startChange(context.Background())
	if err := m.system.Confirm(context.Background()); err != nil {
		t.Fatal(err)
	}
	wait()
	confirmed, _ := os.ReadFile(m.system.Paths.ConfirmedFile)

	// Now switch it off, and change one's mind.
	m.request(`{"enabled":false}`)
	ctx, cancel := context.WithCancel(context.Background())
	wait = m.startChange(ctx)
	cancel() // "undo now", or the machine shutting down
	if err := wait(); err != nil {
		t.Fatal(err)
	}

	state := m.state()
	if state.Pending != nil || state.Confirmed == nil || !state.Confirmed.Enabled {
		t.Fatalf("after undoing: %+v", state)
	}
	if state.Last.Result != ResultUndone {
		t.Errorf("outcome: %+v", state.Last)
	}
	if now, _ := os.ReadFile(m.system.Paths.ConfirmedFile); string(now) != string(confirmed) {
		t.Error("undoing changed the confirmed rules")
	}
	calls := m.nftCalls()
	if last := calls[len(calls)-1]; last != "nft -f <confirmed>" {
		t.Errorf("last command %q, want the confirmed rules being loaded", last)
	}
}

func TestConfirmAfterTheTimeIsUpLoses(t *testing.T) {
	m := newMachine(t)
	m.request(`{"enabled":true}`)
	// The waiting process is deliberately not running, as if it were slow.
	if _, err := m.system.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.advance(60)
	if err := m.system.Confirm(context.Background()); !errors.Is(err, ErrNothingPending) {
		t.Fatalf("a late confirmation: %v", err)
	}
	if m.state().Confirmed != nil {
		t.Error("a late confirmation was accepted")
	}
}

func TestRulesRefusedByTheCheckAreNeverLoaded(t *testing.T) {
	m := newMachine(t)
	m.checkErr = errors.New("exit status 1")
	m.request(`{"enabled":true}`)

	err := m.system.Change(context.Background(), func() { t.Error("reported ready") })
	if err == nil || !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("error: %v", err)
	}
	expectCalls(t, m.nftCalls(), "nft -c -f <pending>")
	state := m.state()
	if state.Pending != nil || state.Last == nil || state.Last.Result != ResultFailed {
		t.Errorf("state: pending %+v, outcome %+v", state.Pending, state.Last)
	}
}

func TestRulesThatFailToLoadAreUndone(t *testing.T) {
	m := newMachine(t)
	m.loadErr["<pending>"] = errors.New("exit status 1")
	m.request(`{"enabled":true}`)

	if err := m.system.Change(context.Background(), func() { t.Error("reported ready") }); err == nil {
		t.Fatal("no error")
	}
	expectCalls(t, m.nftCalls(), "nft -c -f <pending>", "nft -f <pending>", "nft destroy table inet sgc")
	if state := m.state(); state.Pending != nil || state.Last.Result != ResultFailed {
		t.Errorf("state: pending %+v, outcome %+v", state.Pending, state.Last)
	}
}

// If the confirmed rules themselves will not load, the table goes: an open
// machine can be fixed from the browser, a closed one cannot.
func TestUndoFallsBackToNoFirewall(t *testing.T) {
	m := newMachine(t)
	m.request(`{"enabled":true}`)
	wait := m.startChange(context.Background())
	m.system.Confirm(context.Background())
	wait()

	m.request(`{"enabled":false}`)
	wait = m.startChange(context.Background())
	m.loadErr["<confirmed>"] = errors.New("exit status 1")
	m.advance(61)
	if err := wait(); err == nil {
		t.Error("the failed reload was not reported")
	}
	calls := m.nftCalls()
	if last := calls[len(calls)-1]; last != "nft destroy table inet sgc" {
		t.Errorf("last command %q", last)
	}
	if state := m.state(); state.Pending != nil || state.Last.Result != ResultFailed {
		t.Errorf("state: pending %+v, outcome %+v", state.Pending, state.Last)
	}
}

func TestAChangeLeftBehindIsUndoneFirst(t *testing.T) {
	m := newMachine(t)
	m.request(`{"enabled":true}`)
	if _, err := m.system.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	left := m.state().Pending.ID

	// The cleanup systemd runs when the waiting process has died.
	if err := m.system.Revert(context.Background(), ResultUndone, "interrupted"); err != nil {
		t.Fatal(err)
	}
	state := m.state()
	if state.Pending != nil || state.Last.ID != left || state.Last.Result != ResultUndone {
		t.Fatalf("state: pending %+v, outcome %+v", state.Pending, state.Last)
	}

	// And with nothing pending it does nothing, however often it runs.
	before := len(m.nftCalls())
	if err := m.system.Revert(context.Background(), ResultUndone, ""); err != nil {
		t.Fatal(err)
	}
	if len(m.nftCalls()) != before || m.state().Last.Message != "interrupted" {
		t.Error("reverting with nothing pending did something")
	}
}

func TestWithoutNftablesNothingHappens(t *testing.T) {
	m := newMachine(t)
	m.programs[NftProgram] = false
	m.request(`{"enabled":true}`)
	err := m.system.Change(context.Background(), func() { t.Error("reported ready") })
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("error: %v", err)
	}
	if calls := m.nftCalls(); len(calls) != 0 {
		t.Errorf("programs run: %v", calls)
	}
}

func TestRequestsAreReadStrictly(t *testing.T) {
	for _, text := range []string{``, `{`, `{"enabled":"yes"}`, `{"enabled":true,"ports":[1]}`, `[true]`} {
		m := newMachine(t)
		m.request(text)
		if err := m.system.Change(context.Background(), func() { t.Errorf("%q was accepted", text) }); err == nil {
			t.Errorf("%q: no error", text)
		}
		if calls := m.nftCalls(); len(calls) != 0 {
			t.Errorf("%q: programs run: %v", text, calls)
		}
	}

	// No request at all, or a link planted where the request should be.
	m := newMachine(t)
	if err := m.system.Change(context.Background(), func() {}); err == nil {
		t.Error("a missing request was accepted")
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(elsewhere, []byte(`{"enabled":true}`), 0o600)
	if err := os.Symlink(elsewhere, m.system.Paths.RequestFile); err != nil {
		t.Fatal(err)
	}
	if err := m.system.Change(context.Background(), func() { t.Error("a request behind a link was accepted") }); err == nil {
		t.Error("a request behind a link: no error")
	}
}

func TestSSHPortsComeFromTheSSHServer(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*machine)
		want    string
		wantErr bool
	}{
		{"standard", func(m *machine) {}, "22", false},
		{"moved", func(m *machine) { m.sshd = "port 2222\n" }, "2222", false},
		{"two ports", func(m *machine) { m.sshd = "port 22\nport 2222\n" }, "22, 2222", false},
		{"no ssh server", func(m *machine) { m.programs[sshdProgram] = false }, "", false},
		// A broken SSH configuration must not close SSH on top of everything else.
		{"unreadable configuration", func(m *machine) { m.sshdErr = errors.New("exit status 255") }, "22", false},
		{"nothing reported", func(m *machine) { m.sshd = "usepam yes\n" }, "22", false},
		{"nonsense reported", func(m *machine) { m.sshd = "port 0\n" }, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMachine(t)
			c.prepare(m)
			m.request(`{"enabled":true}`)
			pending, err := m.system.begin(context.Background())
			if c.wantErr {
				if err == nil {
					t.Fatal("no error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			rules, _ := os.ReadFile(m.system.Paths.pendingRules())
			want := "tcp dport { 8443 } accept"
			if c.want != "" {
				want = "tcp dport { " + c.want + ", 8443 } accept"
			}
			if !strings.Contains(string(rules), want) {
				t.Errorf("rules do not contain %q (ports %v)", want, pending.Config.SSHPorts)
			}
		})
	}
}

func TestOff(t *testing.T) {
	m := newMachine(t)
	m.request(`{"enabled":true}`)
	wait := m.startChange(context.Background())
	m.system.Confirm(context.Background())
	wait()

	if err := m.system.Off(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := m.state()
	if state.Confirmed == nil || state.Confirmed.Enabled || state.Pending != nil {
		t.Fatalf("state: %+v", state)
	}
	calls := m.nftCalls()
	if last := calls[len(calls)-1]; last != "nft -f <confirmed>" {
		t.Errorf("last command %q", last)
	}
	rules, _ := os.ReadFile(m.system.Paths.ConfirmedFile)
	if strings.Contains(string(rules), "table inet sgc {") {
		t.Error("the confirmed rules still define the table")
	}
}

func TestTableLoaded(t *testing.T) {
	m := newMachine(t)
	answers := map[string]bool{
		"":                                    false,
		"table inet filter\n":                 false,
		"table inet sgc\n":                    true,
		"table inet filter\ntable inet sgc\n": true,
		"table inet sgc-other\n":              false,
	}
	for output, want := range answers {
		m.system.Run = func(context.Context, string, ...string) ([]byte, error) { return []byte(output), nil }
		got, err := m.system.TableLoaded(context.Background())
		if err != nil || got != want {
			t.Errorf("%q: %v, %v; want %v", output, got, err, want)
		}
	}
}
