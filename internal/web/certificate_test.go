package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/certcontrol"
)

func TestCertificateNeedsASession(t *testing.T) {
	e := newTestEnv(t)
	e.expectStatus(e.call("GET", "/api/certificate", nil, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/certificate/request", map[string]any{"agreeToTerms": true}, nil), http.StatusUnauthorized)
	if len(e.certificate.calls) != 0 {
		t.Errorf("a certificate was requested without a session: %v", e.certificate.calls)
	}
}

func TestCertificateOperations(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var status certcontrol.Status
	e.expectStatus(e.call("GET", "/api/certificate", nil, &status), http.StatusOK)
	if status.Domain != "domain.tld" || status.Certificate != nil {
		t.Errorf("status = %+v", status)
	}
	// Started, not finished: the answer says so.
	e.expectStatus(e.call("POST", "/api/certificate/request", map[string]any{"agreeToTerms": true}, nil), http.StatusAccepted)
	e.expectStatus(e.call("POST", "/api/certificate/request", map[string]any{}, nil), http.StatusAccepted)
	if got := strings.Join(e.certificate.calls, ", "); got != "request by "+testUser+", agreeing, request by "+testUser {
		t.Errorf("calls = %s", got)
	}
	// A refusal reaches the owner in words.
	e.certificate.err = &certcontrol.ChangeError{Message: "A certificate from Let's Encrypt needs your agreement to its terms."}
	var refusal struct{ Error string }
	e.expectStatus(e.call("POST", "/api/certificate/request", map[string]any{}, &refusal), http.StatusConflict)
	if !strings.Contains(refusal.Error, "needs your agreement") {
		t.Errorf("the refusal says: %q", refusal.Error)
	}
}
