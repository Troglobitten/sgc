package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/domaincontrol"
)

func TestDomainNeedsASession(t *testing.T) {
	e := newTestEnv(t)
	e.expectStatus(e.call("GET", "/api/domain", nil, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/domain", map[string]any{"domain": "domain.tld", "username": "alex", "apiKey": "a-made-up-api-key"}, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/domain/check", map[string]any{}, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/domain/remove", map[string]any{"confirm": true}, nil), http.StatusUnauthorized)
	if len(e.domain.calls) != 0 {
		t.Errorf("the domain was touched without a session: %v", e.domain.calls)
	}
}

func TestDomainOperations(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var status domaincontrol.Status
	e.expectStatus(e.call("GET", "/api/domain", nil, &status), http.StatusOK)
	if status.Configured {
		t.Errorf("status = %+v", status)
	}
	var answer map[string]any
	e.expectStatus(e.call("POST", "/api/domain", map[string]any{"domain": "domain.tld", "provider": "zone", "values": map[string]string{"username": "alex", "apiKey": "a-made-up-api-key"}}, &answer), http.StatusOK)
	// What comes back says nothing of the key, under any name.
	if raw, _ := json.Marshal(answer); strings.Contains(string(raw), "a-made-up-api-key") {
		t.Errorf("the answer carries the key: %s", raw)
	}
	// It lists the providers, for the form.
	if kinds, _ := answer["kinds"].([]any); len(kinds) < 4 {
		t.Errorf("the providers in the answer: %v", answer["kinds"])
	}
	// The request of a page from before 0.18.0 is a Zone.eu account.
	e.expectStatus(e.call("POST", "/api/domain", map[string]any{"domain": "domain.tld", "username": "alex", "apiKey": "a-made-up-api-key"}, nil), http.StatusOK)
	// Both kinds at once are not.
	e.expectStatus(e.call("POST", "/api/domain", map[string]any{"domain": "domain.tld", "provider": "cloudflare", "values": map[string]string{"apiToken": "x"}, "apiKey": "y"}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/domain/check", map[string]any{}, nil), http.StatusOK)
	e.expectStatus(e.call("POST", "/api/domain/remove", map[string]any{}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/domain/remove", map[string]any{"confirm": true}, nil), http.StatusOK)
	want := "save domain.tld at zone for alex by " + testUser + ", save domain.tld at zone for alex by " + testUser + ", check, remove by " + testUser
	if got := strings.Join(e.domain.calls, ", "); got != want {
		t.Errorf("calls = %s, want %s", got, want)
	}
	// A refusal reaches the owner in words.
	e.domain.err = &domaincontrol.ChangeError{Message: "Zone.eu does not accept the username and API key. Nothing was saved."}
	var refusal struct{ Error string }
	e.expectStatus(e.call("POST", "/api/domain", map[string]any{"domain": "domain.tld", "username": "alex", "apiKey": "another-key"}, &refusal), http.StatusBadRequest)
	if !strings.Contains(refusal.Error, "does not accept") {
		t.Errorf("the refusal says: %q", refusal.Error)
	}
}
