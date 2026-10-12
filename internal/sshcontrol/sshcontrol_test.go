package sshcontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/sshd"
	"github.com/Troglobitten/sgc/internal/store"
)

// Throwaway public keys made for the tests (see internal/sshkeys).
const (
	laptopKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID25i1+d/VGOmeRQ2ZPpnryBGMe/B28pdc623ONJVCV1"
	laptopSum = "SHA256:ZcQJrTJFZ1DO2xgEpCKluYro6G3ehPZvDrs/oGfuJG4"
	phoneKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIkOC0Rmh/Nll43F/bs3QmA+Y7fKcfDEu+lizV4nuTh2"
	phoneSum  = "SHA256:2ZN+1VT4hgThq7IHkTviACZNBrB4C3vuQukDi7faHb4"
)

// rootSide stands in for the root helper and the units behind it. It keeps
// the files the real ones keep and decides the way they decide, without an
// SSH server.
type rootSide struct {
	t     *testing.T
	paths sshd.Paths

	accounts []string
	logins   []sshd.Login
	settings sshd.Settings
	// The helper cannot be reached.
	down bool
	// The next change is refused, with this reason.
	refuse string
	calls  []string
	nextID int64
	uptime float64
}

func (r *rootSide) write(path string, v any) {
	r.t.Helper()
	data, _ := json.Marshal(v)
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rootSide) pendingFile() string { return filepath.Join(r.paths.RunDir, "pending.json") }
func (r *rootSide) lastFile() string    { return filepath.Join(r.paths.RunDir, "last.json") }

func (r *rootSide) state() sshd.State {
	r.t.Helper()
	state, err := sshd.ReadState(r.paths)
	if err != nil {
		r.t.Fatal(err)
	}
	return state
}

func (r *rootSide) SSHStatus(context.Context) (sshd.Status, error) {
	if r.down {
		return sshd.Status{}, errors.New("helper not reachable")
	}
	return sshd.Status{Installed: true, Running: true, Settings: r.settings, Accounts: r.accounts, Logins: r.logins}, nil
}

func (r *rootSide) SSHChange(_ context.Context, cfg sshd.Config) error {
	r.nextID++
	r.calls = append(r.calls, "change")
	if r.down {
		return errors.New("helper not reachable")
	}
	if r.refuse != "" {
		r.write(r.lastFile(), sshd.Outcome{ID: r.nextID, Result: sshd.ResultFailed, Message: r.refuse, At: time.Now()})
		return errors.New("the change was refused")
	}
	confirmed := r.state().Confirmed
	if sshd.NeedsProof(confirmed, cfg) {
		r.write(r.pendingFile(), sshd.Pending{ID: r.nextID, Config: cfg, NeedsProof: true, DeadlineUptime: r.uptime + 120})
		return nil
	}
	r.write(r.paths.StateFile, cfg)
	r.write(r.lastFile(), sshd.Outcome{ID: r.nextID, Result: sshd.ResultConfirmed, At: time.Now()})
	return nil
}

// end finishes the pending change the way the root side would.
func (r *rootSide) end(result string, proof *sshd.Login) {
	r.t.Helper()
	pending := r.state().Pending
	if pending == nil {
		r.t.Fatal("nothing is pending")
	}
	if result == sshd.ResultConfirmed {
		r.write(r.paths.StateFile, pending.Config)
	}
	os.Remove(r.pendingFile())
	r.write(r.lastFile(), sshd.Outcome{ID: pending.ID, Result: result, Proof: proof, At: time.Now()})
}

func (r *rootSide) SSHUndo(context.Context) error {
	r.calls = append(r.calls, "undo")
	r.end(sshd.ResultUndone, nil)
	return nil
}

type env struct {
	t       *testing.T
	db      *sql.DB
	root    *rootSide
	service *Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	root := &rootSide{
		t: t,
		paths: sshd.Paths{
			StateFile: filepath.Join(dir, "etc", "state.json"),
			RunDir:    filepath.Join(dir, "run"),
		},
		accounts: []string{"alex"},
		settings: sshd.Settings{PasswordLogins: true, RootLogin: "key", KeyLogins: true, LoginsVisible: true},
		uptime:   900,
	}
	service := New(Config{
		DB:     db,
		Helper: root,
		Audit:  audit.New(db),
		Paths:  root.paths,
		Uptime: func() (float64, error) { return root.uptime, nil },
		Now:    time.Now,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return &env{t: t, db: db, root: root, service: service}
}

func (e *env) status() Status {
	e.t.Helper()
	status, err := e.service.Status(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return status
}

// history returns the audit log, oldest first, as "actor action detail".
func (e *env) history() []string {
	e.t.Helper()
	entries, err := audit.New(e.db).Recent(context.Background(), 50)
	if err != nil {
		e.t.Fatal(err)
	}
	var lines []string
	for i := len(entries) - 1; i >= 0; i-- {
		lines = append(lines, strings.TrimSpace(entries[i].Actor+" "+entries[i].Action+" "+entries[i].Detail))
	}
	return lines
}

func (e *env) expectHistory(want ...string) {
	e.t.Helper()
	got := e.history()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		e.t.Errorf("history:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func (e *env) add(label, key string) {
	e.t.Helper()
	if err := e.service.AddKey(context.Background(), "alex", "192.168.1.10", label, key, ""); err != nil {
		e.t.Fatal(err)
	}
}

// keyLogin makes the device report a recent login with a key.
func (e *env) keyLogin(fingerprint string) sshd.Login {
	login := sshd.Login{Account: "alex", Kind: "ED25519", Fingerprint: fingerprint, At: time.Now().UTC()}
	e.root.logins = append(e.root.logins, login)
	return login
}

func TestAddingAndRemovingKeys(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if s := e.status(); !s.Available || len(s.Keys) != 0 || s.KeysOnly || !s.PasswordLogins || s.Account != "" || s.ProofSeconds != 120 {
		t.Fatalf("fresh: %+v", s)
	}

	// The label defaults to the comment the key came with; the account to
	// the only one there is.
	e.add("", laptopKey+" alex@laptop")
	e.add("  phone\n", phoneKey)
	s := e.status()
	if len(s.Keys) != 2 || s.Account != "alex" || s.NeedsInstall {
		t.Fatalf("after adding: %+v", s)
	}
	if k := s.Keys[0]; k.Label != "alex@laptop" || k.Kind != "ED25519" || k.Fingerprint != laptopSum || !k.Installed || k.LastLogin != nil {
		t.Errorf("first key: %+v", k)
	}
	if s.Keys[1].Label != "phone" {
		t.Errorf("second key: %+v", s.Keys[1])
	}
	if confirmed := e.root.state().Confirmed; confirmed.Account != "alex" || len(confirmed.Keys) != 2 || confirmed.KeysOnly {
		t.Errorf("on the device: %+v", confirmed)
	}

	if err := e.service.AddKey(ctx, "alex", "", "again", laptopKey, ""); !errors.Is(err, ErrDuplicate) {
		t.Errorf("the same key again: %v", err)
	}
	var input *InputError
	if err := e.service.AddKey(ctx, "alex", "", "", "-----BEGIN OPENSSH PRIVATE KEY-----", ""); !errors.As(err, &input) || !strings.Contains(input.Message, "private key") {
		t.Errorf("a private key: %v", err)
	}
	if err := e.service.AddKey(ctx, "alex", "", "", `command="x" `+phoneKey, ""); !errors.As(err, &input) {
		t.Errorf("a key with options: %v", err)
	}

	if err := e.service.RemoveKey(ctx, "alex", "192.168.1.10", s.Keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := e.service.RemoveKey(ctx, "alex", "", 9999); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("a key that is not there: %v", err)
	}
	if s := e.status(); len(s.Keys) != 1 || s.Keys[0].Fingerprint != phoneSum {
		t.Errorf("after removing: %+v", s.Keys)
	}
	e.expectHistory(
		"alex ssh.key_added alex@laptop (ED25519 "+laptopSum+") for the account alex",
		"alex ssh.key_added phone (ED25519 "+phoneSum+") for the account alex",
		"alex ssh.key_removed alex@laptop (ED25519 "+laptopSum+")",
	)
}

func TestChoosingTheAccount(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root.accounts = []string{"alex", "robin"}

	if err := e.service.AddKey(ctx, "alex", "", "", laptopKey, ""); !errors.Is(err, ErrNeedAccount) {
		t.Fatalf("two accounts and none chosen: %v", err)
	}
	if err := e.service.AddKey(ctx, "alex", "", "", laptopKey, "robin"); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Account != "robin" || e.root.state().Confirmed.Account != "robin" {
		t.Errorf("account: %q, on the device %q", s.Account, e.root.state().Confirmed.Account)
	}
	// Further keys go to the same account; another one is refused.
	var input *InputError
	if err := e.service.AddKey(ctx, "alex", "", "", phoneKey, "alex"); !errors.As(err, &input) {
		t.Errorf("a second account: %v", err)
	}
	if err := e.service.AddKey(ctx, "alex", "", "", phoneKey, ""); err != nil {
		t.Errorf("a second key without naming the account: %v", err)
	}
}

func TestKeysOnlyNeedsAKeyLoginBeforeAndAfter(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add("laptop", laptopKey)

	// Nobody has been seen logging in with a key: not even tried.
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); !errors.Is(err, ErrNoKeyLogin) {
		t.Fatalf("without a key login: %v", err)
	}
	if got := strings.Join(e.root.calls, ","); got != "change" {
		t.Fatalf("the root side was asked: %s", got)
	}

	e.keyLogin(laptopSum)
	if s := e.status(); s.RecentLogin == nil || s.RecentLogin.Key != "laptop" || s.Keys[0].LastLogin == nil {
		t.Fatalf("the login is not shown: %+v", s)
	}
	if err := e.service.SetKeysOnly(ctx, "alex", "192.168.1.10", true); err != nil {
		t.Fatal(err)
	}
	e.root.uptime += 20
	s := e.status()
	if s.Pending == nil || s.Pending.What != "switching to keys only" || s.Pending.SecondsLeft != 100 || s.KeysOnly || s.Wanted {
		t.Fatalf("while waiting: %+v, pending %+v", s, s.Pending)
	}
	// Nothing else while it waits.
	if err := e.service.AddKey(ctx, "alex", "", "", phoneKey, ""); !errors.Is(err, ErrChangePending) {
		t.Errorf("a key added while a change waits: %v", err)
	}
	if e.service.settle(ctx) != true {
		t.Error("a waiting change was settled")
	}

	// The root side sees the login and confirms; SGC catches up.
	proof := e.keyLogin(laptopSum)
	e.root.end(sshd.ResultConfirmed, &proof)
	if e.service.settle(ctx) {
		t.Fatal("the confirmed change is still open")
	}
	if s := e.status(); !s.KeysOnly || !s.Wanted || s.Pending != nil {
		t.Fatalf("after the proof: %+v", s)
	}
	e.expectHistory(
		"alex ssh.key_added laptop (ED25519 "+laptopSum+") for the account alex",
		"alex ssh.change_started switching to keys only",
		"alex ssh.keys_only_on switching to keys only (confirmed: alex logged in with a key, "+laptopSum+")",
	)

	if err := e.service.SetKeysOnly(ctx, "alex", "", true); !errors.Is(err, ErrNoChange) {
		t.Errorf("switching on twice: %v", err)
	}
	// Switching off needs no proof.
	if err := e.service.SetKeysOnly(ctx, "alex", "", false); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.KeysOnly || s.Wanted {
		t.Errorf("after switching off: %+v", s)
	}
}

func TestKeysOnlyWithoutProofChangesNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add("laptop", laptopKey)
	e.keyLogin(laptopSum)
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	e.root.end(sshd.ResultExpired, nil)
	e.service.settle(ctx)
	e.service.settle(ctx)
	if s := e.status(); s.KeysOnly || s.Wanted || s.Pending != nil {
		t.Fatalf("after the time ran out: %+v", s)
	}
	e.expectHistory(
		"alex ssh.key_added laptop (ED25519 "+laptopSum+") for the account alex",
		"alex ssh.change_started switching to keys only",
		"system ssh.change_expired switching to keys only, started by alex",
	)

	// Undone on request.
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	if err := e.service.Undo(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.KeysOnly || s.Wanted || s.Pending != nil {
		t.Fatalf("after undoing: %+v", s)
	}
	if got := e.history(); got[len(got)-1] != "alex ssh.change_undone switching to keys only" {
		t.Errorf("last entry: %s", got[len(got)-1])
	}

	// The machine restarted while it waited: no record of the change is left.
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(e.root.paths.RunDir)
	e.service.settle(ctx)
	if got := e.history(); !strings.Contains(got[len(got)-1], "ssh.change_undone") || !strings.Contains(got[len(got)-1], "interrupted") {
		t.Errorf("last entry: %s", got[len(got)-1])
	}
}

// Under "keys only" a key is only really gone once a login with another key
// has been seen. Until then it stays in the list, and comes back if not.
func TestRemovingAKeyUnderKeysOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add("laptop", laptopKey)
	e.add("phone", phoneKey)
	e.keyLogin(laptopSum)
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	e.root.end(sshd.ResultConfirmed, nil)
	e.service.settle(ctx)
	laptop := e.status().Keys[0].ID

	if err := e.service.RemoveKey(ctx, "alex", "", laptop); err != nil {
		t.Fatal(err)
	}
	s := e.status()
	if s.Pending == nil || !strings.HasPrefix(s.Pending.What, "removing laptop") || len(s.Keys) != 2 {
		t.Fatalf("while waiting: pending %+v, keys %+v", s.Pending, s.Keys)
	}
	e.root.end(sshd.ResultExpired, nil)
	e.service.settle(ctx)
	if s := e.status(); len(s.Keys) != 2 || !s.Keys[0].Installed {
		t.Fatalf("after the time ran out: %+v", s.Keys)
	}

	if err := e.service.RemoveKey(ctx, "alex", "", laptop); err != nil {
		t.Fatal(err)
	}
	proof := e.keyLogin(phoneSum)
	e.root.end(sshd.ResultConfirmed, &proof)
	e.service.settle(ctx)
	if s := e.status(); len(s.Keys) != 1 || s.Keys[0].Label != "phone" || !s.KeysOnly {
		t.Fatalf("after the proof: %+v", s)
	}
	if got := e.history(); !strings.HasPrefix(got[len(got)-1], "alex ssh.key_removed removing laptop") {
		t.Errorf("last entry: %s", got[len(got)-1])
	}
}

// The root side confirms a change the moment it sees the login; this side
// catches up a little later. Somebody who asks for the state in between must
// not be shown half of it: "keys only" on but not recorded as wanted, or a
// key that is gone from the device still in the list. (The whole-machine test
// asked at exactly that moment.)
func TestTheStateShownIsNeverHalfOfAChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add("laptop", laptopKey)
	e.add("phone", phoneKey)
	e.keyLogin(laptopSum)
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	proof := e.keyLogin(laptopSum)
	e.root.end(sshd.ResultConfirmed, &proof)
	// Nothing has settled the change; the question itself does.
	s := e.status()
	if !s.KeysOnly || !s.Wanted || s.Pending != nil {
		t.Fatalf("right after the proof: keysOnly %v, wanted %v, pending %+v", s.KeysOnly, s.Wanted, s.Pending)
	}

	if err := e.service.RemoveKey(ctx, "alex", "", s.Keys[0].ID); err != nil {
		t.Fatal(err)
	}
	proof = e.keyLogin(phoneSum)
	e.root.end(sshd.ResultConfirmed, &proof)
	if s := e.status(); len(s.Keys) != 1 || s.Keys[0].Label != "phone" {
		t.Fatalf("right after the proof, the keys shown: %+v", s.Keys)
	}
	if got := e.history(); !strings.HasPrefix(got[len(got)-1], "alex ssh.key_removed removing laptop") {
		t.Errorf("last entry: %s", got[len(got)-1])
	}

	// While a change is being made, asking does not wait for it.
	e.service.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := e.service.Status(ctx); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("asking for the state waited for a change in progress")
	}
	e.service.mu.Unlock()
}

func TestFailuresChangeNothingAndAreExplained(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var failure *ChangeError

	e.root.refuse = "this device's SSH server is set up to keep keys in its own place"
	err := e.service.AddKey(ctx, "alex", "", "laptop", laptopKey, "")
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, "its own place") || !strings.Contains(failure.Message, "Nothing was changed") {
		t.Fatalf("error: %v", err)
	}
	if s := e.status(); len(s.Keys) != 0 || s.Account != "" {
		t.Errorf("a refused key was recorded: %+v", s)
	}
	e.expectHistory("alex ssh.change_failed laptop (ED25519 " + laptopSum + ") for the account alex")

	// The helper cannot be reached: the page still shows what it knows.
	e = newEnv(t)
	e.add("laptop", laptopKey)
	e.root.down = true
	if s := e.status(); s.Available || len(s.Keys) != 1 {
		t.Errorf("without the helper: %+v", s)
	}
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); !errors.As(err, &failure) {
		t.Errorf("keys only without the helper: %v", err)
	}

	// A server that does not log logins: the switch is not attempted.
	e = newEnv(t)
	e.root.settings.LoginsVisible = false
	e.keyLogin(laptopSum)
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); !errors.As(err, &failure) || !strings.Contains(failure.Message, "log logins") {
		t.Errorf("error: %v", err)
	}
}

// After restoring an export on another machine the keys are known but not
// installed, and "keys only" is remembered but not in effect.
func TestAfterARestore(t *testing.T) {
	old := newEnv(t)
	ctx := context.Background()
	old.add("laptop", laptopKey)
	old.keyLogin(laptopSum)
	if err := old.service.SetKeysOnly(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	old.root.end(sshd.ResultConfirmed, nil)
	old.service.settle(ctx)

	// The new machine: the same database, nothing on the device, and the
	// account from the old one does not exist here.
	fresh := newEnv(t)
	for _, statement := range []string{
		`INSERT INTO ssh_key (label, key_type, key_blob, fingerprint, added_at, added_by) VALUES ('laptop', 'ssh-ed25519', 'AAAAC3NzaC1lZDI1NTE5AAAAID25i1+d/VGOmeRQ2ZPpnryBGMe/B28pdc623ONJVCV1', '` + laptopSum + `', 100, 'alex')`,
		`INSERT INTO setting (key, value) VALUES ('ssh.account', 'alex'), ('ssh.keys_only', 'true')`,
	} {
		if _, err := fresh.db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	fresh.root.accounts = []string{"robin"}

	s := fresh.status()
	if !s.NeedsInstall || s.Keys[0].Installed || s.KeysOnly || !s.Wanted || s.Account != "alex" {
		t.Fatalf("after the restore: %+v", s)
	}
	if err := fresh.service.Install(ctx, "alex", "", "robin"); err != nil {
		t.Fatal(err)
	}
	s = fresh.status()
	if s.NeedsInstall || !s.Keys[0].Installed || s.Account != "robin" || s.KeysOnly {
		t.Fatalf("after installing: %+v", s)
	}
	if confirmed := fresh.root.state().Confirmed; confirmed.Account != "robin" || len(confirmed.Keys) != 1 || confirmed.KeysOnly {
		t.Errorf("on the device: %+v", confirmed)
	}
	if err := fresh.service.Install(ctx, "alex", "", ""); !errors.Is(err, ErrNoChange) {
		t.Errorf("installing again: %v", err)
	}
	fresh.expectHistory("alex ssh.keys_installed 1 key(s) for the account robin")
}

func TestAnOverdueChangeIsUndone(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.keyLogin(laptopSum)
	if err := e.service.SetKeysOnly(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	e.root.uptime += 120 + overdueGrace.Seconds() - 1
	if e.service.rescue(ctx) {
		t.Fatal("stepped in before the root side had its chance")
	}
	e.root.uptime += 2
	if !e.service.rescue(ctx) || e.root.calls[len(e.root.calls)-1] != "undo" {
		t.Fatalf("an overdue change was left in effect: %v", e.root.calls)
	}
	if e.service.rescue(ctx) {
		t.Error("stepped in with nothing pending")
	}
}

func TestLabels(t *testing.T) {
	cases := []struct{ label, comment, want string }{
		{"laptop", "alex@laptop", "laptop"},
		{"", "alex@laptop", "alex@laptop"},
		{"   ", "", "key 3"},
		{"work\tlaptop\n", "", "worklaptop"},
		{strings.Repeat("x", 200), "", strings.Repeat("x", maxLabel)},
		{"\x00\x1b[31m", "fallback", "[31m"},
	}
	for _, c := range cases {
		if got := cleanLabel(c.label, c.comment, 3); got != c.want {
			t.Errorf("cleanLabel(%q, %q) = %q, want %q", c.label, c.comment, got, c.want)
		}
	}
}
