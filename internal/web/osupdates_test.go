package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/oscontrol"
)

func TestOSUpdatesNeedASession(t *testing.T) {
	e := newTestEnv(t)
	e.expectStatus(e.call("GET", "/api/os-updates", nil, nil), http.StatusUnauthorized)
	for _, path := range []string{"/api/os-updates/mode", "/api/os-updates/check", "/api/os-updates/install"} {
		e.expectStatus(e.call("POST", path, map[string]any{"automatic": true}, nil), http.StatusUnauthorized)
	}
	if len(e.osUpdates.calls) != 0 {
		t.Errorf("the device's updates were touched without a session: %v", e.osUpdates.calls)
	}
}

func TestOSUpdatesOperations(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	checked := time.Date(2026, 10, 12, 14, 0, 0, 0, time.UTC)
	e.osUpdates.status.Mode, e.osUpdates.status.CheckedAt, e.osUpdates.status.Waiting = "by-hand", &checked, []string{"liblzma5", "xz-utils"}

	var status oscontrol.Status
	e.expectStatus(e.call("GET", "/api/os-updates", nil, &status), http.StatusOK)
	if !status.Available || status.Mode != "by-hand" || strings.Join(status.Waiting, " ") != "liblzma5 xz-utils" {
		t.Errorf("status = %+v", status)
	}

	e.expectStatus(e.call("POST", "/api/os-updates/mode", map[string]any{"automatic": true}, &status), http.StatusOK)
	e.expectStatus(e.call("POST", "/api/os-updates/mode", map[string]any{"automatic": false}, nil), http.StatusOK)
	// "By hand" must be said, not assumed from a request that says nothing.
	e.expectStatus(e.call("POST", "/api/os-updates/mode", map[string]any{}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/os-updates/mode", map[string]any{"automatic": "yes"}, nil), http.StatusBadRequest)
	// Started, not finished: the interface asks for the state from here on.
	e.expectStatus(e.call("POST", "/api/os-updates/check", map[string]any{}, &status), http.StatusAccepted)
	e.expectStatus(e.call("POST", "/api/os-updates/install", map[string]any{}, &status), http.StatusAccepted)

	want := "mode automatic=true by " + testUser + ", mode automatic=false by " + testUser + ", check, install by " + testUser
	if got := strings.Join(e.osUpdates.calls, ", "); got != want {
		t.Errorf("calls = %s\nwant    %s", got, want)
	}
}

func TestOSUpdatesRefusalsAreExplained(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var answer struct {
		Error string `json:"error"`
	}

	e.osUpdates.err = oscontrol.ErrBusy
	e.expectStatus(e.call("POST", "/api/os-updates/install", map[string]any{}, &answer), http.StatusConflict)
	if !strings.Contains(answer.Error, "already running") {
		t.Errorf("busy: %q", answer.Error)
	}
	e.osUpdates.err = oscontrol.ErrNotSetUp
	e.expectStatus(e.call("POST", "/api/os-updates/check", map[string]any{}, &answer), http.StatusConflict)
	if !strings.Contains(answer.Error, "Choose first") {
		t.Errorf("not set up: %q", answer.Error)
	}
	e.osUpdates.err = &oscontrol.ChangeError{Message: "That did not work: another settings file on this device overrules SGC's. Nothing was changed."}
	e.expectStatus(e.call("POST", "/api/os-updates/mode", map[string]any{"automatic": true}, &answer), http.StatusBadGateway)
	if !strings.Contains(answer.Error, "overrules SGC's") {
		t.Errorf("a refused choice: %q", answer.Error)
	}
}

// Restarting in the middle of an installation would cut it short.
func TestNoRestartWhileUpdatesAreBeingInstalled(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	e.osUpdates.installing = true
	var answer struct {
		Error string `json:"error"`
	}
	e.expectStatus(e.call("POST", "/api/device/restart", restartRequest{Confirm: true}, &answer), http.StatusConflict)
	if e.helper.restarts != 0 {
		t.Fatal("the device was restarted in the middle of an installation")
	}
	if !strings.Contains(answer.Error, "being installed") {
		t.Errorf("the refusal says: %q", answer.Error)
	}
	var entries []audit.Entry
	e.call("GET", "/api/audit", nil, &entries)
	for _, entry := range entries {
		if entry.Action == audit.ActionDeviceRestart {
			t.Error("a restart that did not happen is in the history")
		}
	}

	e.osUpdates.installing = false
	e.expectStatus(e.call("POST", "/api/device/restart", restartRequest{Confirm: true}, nil), http.StatusAccepted)
	if e.helper.restarts != 1 {
		t.Errorf("after the installation: restarted %d times", e.helper.restarts)
	}
}
