package web

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/dnscontrol"
)

func TestDNSNeedsASession(t *testing.T) {
	e := newTestEnv(t)
	e.expectStatus(e.call("GET", "/api/dns", nil, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/dns/install", map[string]any{}, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/dns/remove", map[string]any{"confirm": true}, nil), http.StatusUnauthorized)
	// AdGuard Home's own page has no login of its own. SGC's is the only one.
	for _, path := range []string{"/adguard", "/adguard/", "/adguard/control/status", "/adguard/control/dns_config"} {
		e.expectStatus(e.call("GET", path, nil, nil), http.StatusUnauthorized)
	}
	e.expectStatus(e.call("POST", "/adguard/control/dns_config", map[string]any{"upstream_dns": []string{"192.0.2.1"}}, nil), http.StatusUnauthorized)
	if len(e.dns.calls) != 0 {
		t.Errorf("AdGuard Home was touched without a session: %v", e.dns.calls)
	}
}

func TestDNSOperations(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	var status dnscontrol.Status
	e.expectStatus(e.call("GET", "/api/dns", nil, &status), http.StatusOK)
	if !status.Available || status.Pinned != "0.107.79" {
		t.Errorf("status = %+v", status)
	}
	e.expectStatus(e.call("POST", "/api/dns/install", map[string]any{}, nil), http.StatusOK)
	e.expectStatus(e.call("POST", "/api/dns/remove", map[string]any{}, nil), http.StatusBadRequest)
	e.expectStatus(e.call("POST", "/api/dns/remove", map[string]any{"confirm": true}, nil), http.StatusOK)
	if got := strings.Join(e.dns.calls, ", "); got != "install by "+testUser+", remove by "+testUser {
		t.Errorf("calls = %s", got)
	}
	e.dns.err = &dnscontrol.ChangeError{Message: "AdGuard Home could not be installed: port 53 is taken. Nothing was changed."}
	var answer struct{ Error string }
	e.expectStatus(e.call("POST", "/api/dns/install", map[string]any{}, &answer), http.StatusBadGateway)
	if !strings.Contains(answer.Error, "port 53") {
		t.Errorf("the refusal says: %q", answer.Error)
	}
}

// AdGuard Home's page behind SGC's login: it is told its own paths, it never
// sees SGC's session, and it cannot set cookies on SGC's address.
func TestAdguardPageBehindTheLogin(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	get := func(path string) (*http.Response, string) {
		t.Helper()
		resp, err := e.client.Get(e.url + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	resp, body := get("/adguard/control/status")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `adguard saw GET /control/status cookie=""`) {
		t.Errorf("a request passed on: %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Errorf("AdGuard Home set a cookie on SGC's address: %q", resp.Header.Get("Set-Cookie"))
	}
	if _, body := get("/adguard/"); !strings.Contains(body, "adguard saw GET / ") {
		t.Errorf("the page itself: %q", body)
	}
	// A redirect inside AdGuard Home stays inside /adguard/. (The test's
	// browser follows it: "/login.html" leads to "/", which must be AdGuard
	// Home's, not SGC's.)
	if _, body := get("/adguard/login.html"); !strings.Contains(body, "adguard saw GET / ") {
		t.Errorf("after a redirect: %q", body)
	}

	// AdGuard Home is not there.
	e.adguard.Close()
	if resp, body := get("/adguard/"); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "does not answer") {
		t.Errorf("with AdGuard Home gone: %d %q", resp.StatusCode, body)
	}
}
