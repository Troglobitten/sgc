package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/logcontrol"
)

func TestLog2ramNeedsASession(t *testing.T) {
	e := newTestEnv(t)
	e.expectStatus(e.call("GET", "/api/log2ram", nil, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/log2ram/enabled", map[string]any{"enabled": true}, nil), http.StatusUnauthorized)
	if len(e.log2ram.calls) != 0 {
		t.Errorf("log2ram was touched without a session: %v", e.log2ram.calls)
	}
}

func TestLog2ramOperations(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var status logcontrol.Status
	e.expectStatus(e.call("GET", "/api/log2ram", nil, &status), http.StatusOK)
	if !status.Available || !status.Installed || status.SizeBytes != 128<<20 {
		t.Errorf("status = %+v", status)
	}
	// A request that does not say on or off is not read as "off".
	e.expectStatus(e.call("POST", "/api/log2ram/enabled", map[string]any{}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/log2ram/enabled", map[string]any{"enabled": true}, nil), http.StatusOK)
	e.expectStatus(e.call("POST", "/api/log2ram/enabled", map[string]any{"enabled": false}, nil), http.StatusOK)
	if got := strings.Join(e.log2ram.calls, ", "); got != "switched on by "+testUser+", switched off by "+testUser {
		t.Errorf("calls = %s", got)
	}
	// A refusal reaches the owner in the root side's words.
	e.log2ram.err = &logcontrol.ChangeError{Message: "Logs in memory could not be switched on: the logs of this device would take 143 MB. Nothing was changed."}
	var answer struct{ Error string }
	e.expectStatus(e.call("POST", "/api/log2ram/enabled", map[string]any{"enabled": true}, &answer), http.StatusBadGateway)
	if !strings.Contains(answer.Error, "143 MB") {
		t.Errorf("the refusal says: %q", answer.Error)
	}
}
