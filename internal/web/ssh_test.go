package web

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/sshcontrol"
)

const pastedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID25i1+d/VGOmeRQ2ZPpnryBGMe/B28pdc623ONJVCV1 alex@laptop"

func TestSSHNeedsASession(t *testing.T) {
	e := newTestEnv(t)
	e.expectStatus(e.call("GET", "/api/ssh", nil, nil), http.StatusUnauthorized)
	for _, path := range []string{"/api/ssh/keys", "/api/ssh/keys/remove", "/api/ssh/keys/install", "/api/ssh/keys-only", "/api/ssh/undo"} {
		e.expectStatus(e.call("POST", path, map[string]any{}, nil), http.StatusUnauthorized)
	}
	if len(e.ssh.calls) != 0 {
		t.Errorf("SSH was touched without a session: %v", e.ssh.calls)
	}
}

// A key is a way to log in to the device itself. A signed-in browser is not
// enough to hand one out: the admin's password is asked for again.
func TestAddingAKeyNeedsThePasswordAgain(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	add := func(password string) *http.Response {
		return e.call("POST", "/api/ssh/keys", map[string]any{"password": password, "label": "laptop", "key": pastedKey, "account": ""}, nil)
	}

	e.expectStatus(add(""), http.StatusForbidden)
	e.expectStatus(add("not the password"), http.StatusForbidden)
	if len(e.ssh.calls) != 0 {
		t.Fatalf("a key was added without the password: %v", e.ssh.calls)
	}
	// Being refused does not end the session.
	e.expectStatus(e.call("GET", "/api/ssh", nil, nil), http.StatusOK)

	e.expectStatus(add(testPassword), http.StatusOK)
	want := `add "laptop" "` + pastedKey + `" for "" by ` + testUser
	if len(e.ssh.calls) != 1 || e.ssh.calls[0] != want {
		t.Errorf("calls = %v\nwant   %s", e.ssh.calls, want)
	}

	// The same for installing the keys known from an export.
	e.expectStatus(e.call("POST", "/api/ssh/keys/install", map[string]any{"password": "wrong", "account": "alex"}, nil), http.StatusForbidden)
	e.expectStatus(e.call("POST", "/api/ssh/keys/install", map[string]any{"password": testPassword, "account": "alex"}, nil), http.StatusOK)
	if got := e.ssh.calls[len(e.ssh.calls)-1]; got != `install for "alex" by `+testUser || len(e.ssh.calls) != 2 {
		t.Errorf("calls = %v", e.ssh.calls)
	}
}

// Guessing the password through this door counts like guessing it at sign-in.
func TestPasswordGuessesWhenAddingAKeyAreLimited(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var last *http.Response
	for range 6 {
		last = e.call("POST", "/api/ssh/keys", map[string]any{"password": "guess", "label": "", "key": pastedKey, "account": ""}, nil)
	}
	e.expectStatus(last, http.StatusTooManyRequests)
	// Even the right password is not looked at now.
	e.expectStatus(e.call("POST", "/api/ssh/keys", map[string]any{"password": testPassword, "label": "", "key": pastedKey, "account": ""}, nil), http.StatusTooManyRequests)
	if len(e.ssh.calls) != 0 {
		t.Errorf("a key was added: %v", e.ssh.calls)
	}
}

func TestSSHOperations(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()

	var status sshcontrol.Status
	e.expectStatus(e.call("GET", "/api/ssh", nil, &status), http.StatusOK)
	if !status.Available || status.ProofSeconds != 120 || len(status.Accounts) != 1 {
		t.Errorf("status = %+v", status)
	}
	e.expectStatus(e.call("POST", "/api/ssh/keys/remove", map[string]any{"id": 7}, nil), http.StatusOK)
	e.expectStatus(e.call("POST", "/api/ssh/keys-only", map[string]any{"enabled": true}, nil), http.StatusOK)
	e.expectStatus(e.call("POST", "/api/ssh/keys-only", map[string]any{"enabled": false}, nil), http.StatusOK)
	e.expectStatus(e.call("POST", "/api/ssh/undo", map[string]any{}, nil), http.StatusOK)
	want := "remove 7 by " + testUser + ", keys-only true by " + testUser + ", keys-only false by " + testUser + ", undo by " + testUser
	if got := strings.Join(e.ssh.calls, ", "); got != want {
		t.Errorf("calls = %s\nwant    %s", got, want)
	}

	// Requests are read strictly.
	e.expectStatus(e.call("POST", "/api/ssh/keys-only", map[string]any{"enabled": "yes"}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/ssh/keys-only", map[string]any{"enabled": true, "skipProof": true}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/ssh/keys/remove", map[string]any{"id": "all"}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/ssh/keys", map[string]any{"password": testPassword, "key": pastedKey, "options": "command=x"}, nil), http.StatusBadRequest)
}

func TestSSHErrorsAreExplained(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var answer struct{ Error string }
	keysOnly := func() *http.Response {
		return e.call("POST", "/api/ssh/keys-only", map[string]any{"enabled": true}, &answer)
	}

	cases := []struct {
		err     error
		status  int
		message string
	}{
		{sshcontrol.ErrNoKeyLogin, http.StatusConflict, "has not seen anyone log in with a key"},
		{sshcontrol.ErrChangePending, http.StatusConflict, "still waiting"},
		{sshcontrol.ErrNoChange, http.StatusConflict, "already"},
		{sshcontrol.ErrDuplicate, http.StatusConflict, "already been added"},
		{sshcontrol.ErrNeedAccount, http.StatusConflict, "Choose the account"},
		{sshcontrol.ErrNoSuchKey, http.StatusNotFound, "no such key"},
		{&sshcontrol.InputError{Message: "This is a private key."}, http.StatusBadRequest, "This is a private key."},
		{&sshcontrol.ChangeError{Message: "That did not work. Nothing was changed."}, http.StatusBadGateway, "Nothing was changed"},
	}
	for _, c := range cases {
		e.ssh.err = c.err
		e.expectStatus(keysOnly(), c.status)
		if !strings.Contains(answer.Error, c.message) {
			t.Errorf("%v: message = %q", c.err, answer.Error)
		}
	}

	// Internals stay in the log.
	e.ssh.err = errors.New("open /etc/sgc/ssh/state.json: permission denied")
	e.expectStatus(keysOnly(), http.StatusInternalServerError)
	if strings.Contains(answer.Error, "state.json") {
		t.Errorf("message leaks internals: %q", answer.Error)
	}
	e.expectStatus(e.call("POST", "/api/ssh/undo", map[string]any{}, &answer), http.StatusBadGateway)
	if !strings.Contains(answer.Error, "by itself") {
		t.Errorf("message = %q", answer.Error)
	}
}
