package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/maintenance"
)

func TestMaintenanceNeedsASession(t *testing.T) {
	e := newTestEnv(t)
	e.expectStatus(e.call("GET", "/api/maintenance", nil, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/maintenance", map[string]any{"enabled": true, "start": "04:00", "end": "05:00"}, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/maintenance/auto-update", map[string]any{"enabled": true}, nil), http.StatusUnauthorized)
	if len(e.maintenance.calls) != 0 {
		t.Errorf("the window was changed without a session: %v", e.maintenance.calls)
	}
}

func TestMaintenanceOperations(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var status maintenance.Status
	e.expectStatus(e.call("GET", "/api/maintenance", nil, &status), http.StatusOK)
	if status.Start != "04:00" || status.UpdateWaitDays != 3 {
		t.Errorf("status = %+v", status)
	}
	e.expectStatus(e.call("POST", "/api/maintenance", map[string]any{"enabled": true, "start": "03:00", "end": "04:30"}, nil), http.StatusOK)
	// Nothing left out is filled in: "off" and "midnight" must be said.
	for _, body := range []map[string]any{{}, {"enabled": true}, {"start": "03:00", "end": "04:00"}, {"enabled": "yes", "start": "03:00", "end": "04:00"}} {
		e.expectStatus(e.call("POST", "/api/maintenance", body, nil), http.StatusBadRequest)
	}
	e.expectStatus(e.call("POST", "/api/maintenance/auto-update", map[string]any{}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/maintenance/auto-update", map[string]any{"enabled": true}, &status), http.StatusOK)
	if !status.AutoUpdate {
		t.Errorf("after switching on: %+v", status)
	}

	// What the owner entered wrongly comes back as that, in words.
	e.maintenance.err = &maintenance.InputError{Message: "The window must end at another time than it begins."}
	var answer struct{ Error string }
	e.expectStatus(e.call("POST", "/api/maintenance", map[string]any{"enabled": true, "start": "03:00", "end": "03:00"}, &answer), http.StatusBadRequest)
	if !strings.Contains(answer.Error, "another time") {
		t.Errorf("the refusal says: %q", answer.Error)
	}
	e.maintenance.err = nil

	// Switching the daily look for new versions off takes "install by
	// themselves" with it.
	e.expectStatus(e.call("POST", "/api/update/settings", map[string]any{"autoCheck": false}, nil), http.StatusOK)
	want := "window true 03:00-04:30 by " + testUser + ", auto-update true by " + testUser + ", window true 03:00-03:00 by " + testUser + ", auto-update false by " + testUser
	if got := strings.Join(e.maintenance.calls, ", "); got != want {
		t.Errorf("calls = %s\nwant    %s", got, want)
	}
}
