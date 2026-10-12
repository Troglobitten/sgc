package web

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/fwcontrol"
)

func TestFirewallNeedsASession(t *testing.T) {
	e := newTestEnv(t)
	e.expectStatus(e.call("GET", "/api/firewall", nil, nil), http.StatusUnauthorized)
	for _, path := range []string{"/api/firewall/change", "/api/firewall/confirm", "/api/firewall/undo"} {
		e.expectStatus(e.call("POST", path, map[string]any{"enabled": true}, nil), http.StatusUnauthorized)
	}
	if len(e.firewall.calls) != 0 {
		t.Errorf("the firewall was touched without a session: %v", e.firewall.calls)
	}
}

func TestFirewallStatusSaysWhetherThisBrowserIsInside(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()

	var status firewallResponse
	e.expectStatus(e.call("GET", "/api/firewall", nil, &status), http.StatusOK)
	if status.State != fwcontrol.StateOff || status.ConfirmSeconds != 60 || !status.Client.Inside || status.Client.Address != "127.0.0.1" {
		t.Errorf("status = %+v", status)
	}

	for address, inside := range map[string]bool{
		"192.168.1.20:50000":  true,
		"10.1.2.3:50000":      true,
		"203.0.113.9:50000":   false,
		"[2001:db8::1]:50000": false,
		"[fe80::1]:50000":     true,
	} {
		e.pretendFrom = address
		e.expectStatus(e.call("GET", "/api/firewall", nil, &status), http.StatusOK)
		if status.Client.Inside != inside {
			t.Errorf("%s: inside = %v, want %v", address, status.Client.Inside, inside)
		}
	}
}

// Switching the firewall on from an address it would refuse makes no sense:
// the owner would be cut off until it undoes itself.
func TestFirewallIsNotSwitchedOnFromOutside(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	e.pretendFrom = "203.0.113.9:50000"

	var answer struct{ Error string }
	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": true}, &answer), http.StatusConflict)
	if !strings.Contains(answer.Error, "203.0.113.9") || !strings.Contains(answer.Error, "not switched on") {
		t.Errorf("message = %q", answer.Error)
	}
	if len(e.firewall.calls) != 0 {
		t.Errorf("the firewall was touched: %v", e.firewall.calls)
	}

	// Switching it off from there is always allowed: that cannot lock anyone out.
	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": false}, nil), http.StatusAccepted)
}

func TestFirewallChangeConfirmUndo(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()

	var status firewallResponse
	resp := e.call("POST", "/api/firewall/change", map[string]any{"enabled": true}, &status)
	e.expectStatus(resp, http.StatusAccepted)
	if status.State != fwcontrol.StatePending || status.Pending == nil || status.Pending.SecondsLeft != 60 {
		t.Errorf("after the change: %+v", status)
	}
	// The connection the change was asked over is not kept.
	if !resp.Close {
		t.Error("the answer to a change does not close the connection")
	}

	e.expectStatus(e.call("POST", "/api/firewall/confirm", map[string]any{}, &status), http.StatusOK)
	if status.State != fwcontrol.StateOn {
		t.Errorf("after confirming: %+v", status)
	}

	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": false}, nil), http.StatusAccepted)
	e.expectStatus(e.call("POST", "/api/firewall/undo", map[string]any{}, &status), http.StatusOK)

	want := "change enabled=true by " + testUser + ", confirm by " + testUser + ", change enabled=false by " + testUser + ", undo by " + testUser
	if got := strings.Join(e.firewall.calls, ", "); got != want {
		t.Errorf("calls = %s\nwant    %s", got, want)
	}
}

// The heart of lock-out protection in the web layer: a confirmation only
// counts over a connection that was made after the change.
func TestFirewallConfirmationNeedsANewConnection(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()

	// A second browser window: its connection exists before the change and
	// stays open across it.
	other := *e.client
	other.Transport = e.client.Transport.(*http.Transport).Clone()
	window := &testEnv{t: t, url: e.url, client: &other}
	window.expectStatus(window.call("GET", "/api/firewall", nil, nil), http.StatusOK)

	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": true}, nil), http.StatusAccepted)

	// Confirming over the old connection is turned away, and that
	// connection is closed.
	var answer struct{ Error string }
	resp := window.call("POST", "/api/firewall/confirm", map[string]any{}, &answer)
	window.expectStatus(resp, http.StatusConflict)
	if resp.Header.Get(reconnectHeader) == "" || !resp.Close {
		t.Errorf("the refusal does not ask for a new connection: headers %v, close %v", resp.Header, resp.Close)
	}
	if len(e.firewall.calls) != 1 {
		t.Fatalf("the confirmation got through over an old connection: %v", e.firewall.calls)
	}

	// The same window trying again connects anew, and that counts.
	window.expectStatus(window.call("POST", "/api/firewall/confirm", map[string]any{}, nil), http.StatusOK)
	if got := e.firewall.calls[len(e.firewall.calls)-1]; got != "confirm by "+testUser {
		t.Errorf("last call = %q", got)
	}
}

func TestFirewallErrorsAreExplained(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var answer struct{ Error string }

	e.firewall.changeErr = fwcontrol.ErrChangePending
	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": true}, &answer), http.StatusConflict)
	if !strings.Contains(answer.Error, "waiting for confirmation") {
		t.Errorf("message = %q", answer.Error)
	}

	e.firewall.changeErr = &fwcontrol.ChangeError{Message: "The firewall software could not be installed."}
	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": true}, &answer), http.StatusBadGateway)
	if answer.Error != "The firewall software could not be installed." {
		t.Errorf("message = %q", answer.Error)
	}

	// Internals stay in the log.
	e.firewall.changeErr = errors.New("open /run/sgc-firewall/pending.json: permission denied")
	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": true}, &answer), http.StatusInternalServerError)
	if strings.Contains(answer.Error, "pending.json") {
		t.Errorf("message leaks internals: %q", answer.Error)
	}

	e.firewall.confirmErr = fwcontrol.ErrTooLate
	e.expectStatus(e.call("POST", "/api/firewall/confirm", map[string]any{}, &answer), http.StatusConflict)
	if !strings.Contains(answer.Error, "not confirmed in time") {
		t.Errorf("message = %q", answer.Error)
	}

	e.firewall.undoErr = errors.New("helper not reachable")
	e.expectStatus(e.call("POST", "/api/firewall/undo", map[string]any{}, &answer), http.StatusBadGateway)
	if !strings.Contains(answer.Error, "by itself") {
		t.Errorf("message = %q", answer.Error)
	}
}

func TestFirewallRequestsAreReadStrictly(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": true, "ports": []int{1}}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/firewall/change", map[string]any{"enabled": "yes"}, nil), http.StatusBadRequest)
	if len(e.firewall.calls) != 0 {
		t.Errorf("the firewall was touched: %v", e.firewall.calls)
	}
}
