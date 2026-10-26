package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/people"
)

// SGC's login on a public service: the sign-in under the service's own
// name, reached from the internet through the public door.
func TestTheGateFromTheInternet(t *testing.T) {
	s, ppl := gateServer(t)
	ctx := context.Background()
	if _, err := ppl.Add(ctx, "owner", "", people.Input{Name: "Kim", Network: people.NetworkServices, ServiceIDs: []int64{1},
		LoginEnabled: true, Username: "kim", Password: "a-made-up-password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ppl.Add(ctx, "owner", "", people.Input{Name: "Lee", Network: people.NetworkServices, ServiceIDs: []int64{2},
		LoginEnabled: true, Username: "lee", Password: "another-made-up-password"}); err != nil {
		t.Fatal(err)
	}
	internal := s.InternalHandler()
	call := func(req *http.Request) *http.Response {
		w := httptest.NewRecorder()
		internal.ServeHTTP(w, req)
		return w.Result()
	}
	// As Traefik passes it on: from this device, with the visitor's address.
	fromVisitor := func(method, target, visitor string, body string) *http.Request {
		req := httptest.NewRequest(method, "http://127.0.0.1:8444"+target, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("X-Forwarded-For", visitor)
		req.Header.Set("X-Forwarded-Host", "media.domain.tld")
		req.Host = "media.domain.tld"
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", "https://media.domain.tld")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		return req
	}
	signIn := func(visitor, username, password, rd string) *http.Response {
		form := url.Values{"username": {username}, "password": {password}, "rd": {rd}}.Encode()
		return call(fromVisitor(http.MethodPost, "/.sgc-gate/sign-in", visitor, form))
	}

	// Without a pass: off to the sign-in under the service's own name.
	check := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8444/gate/check-public", nil)
	check.Header.Set("X-Forwarded-Host", "media.domain.tld")
	check.Header.Set("X-Forwarded-Uri", "/movies?id=1")
	resp := call(check)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://media.domain.tld/.sgc-gate/sign-in?rd="+url.QueryEscape("/movies?id=1") {
		t.Fatalf("without a pass: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The form, as SGC's own page without scripts and not in a frame.
	resp = call(fromVisitor(http.MethodGet, "/.sgc-gate/sign-in?rd=%2Fmovies", "203.0.113.5", ""))
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in to media") || strings.Contains(string(body), "<script") ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("the form: %d %s", resp.StatusCode, body)
	}

	// Posted from another site: refused before anything is checked.
	req := fromVisitor(http.MethodPost, "/.sgc-gate/sign-in", "203.0.113.5", "username=kim&password=a-made-up-password&rd=%2F")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp := call(req); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a sign-in posted from another site: %d", resp.StatusCode)
	}

	// A wrong password; a person whose login does not have the service.
	if resp := signIn("203.0.113.5", "kim", "not-the-password", "/"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong password: %d", resp.StatusCode)
	}
	if resp := signIn("203.0.113.6", "lee", "another-made-up-password", "/"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a person without the service: %d", resp.StatusCode)
	}

	// Kim: the pass for media, and the way back on the same name only.
	resp = signIn("203.0.113.7", "kim", "a-made-up-password", "//evil.example/steal")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Errorf("a way back to another site: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	pass := cookieFrom(t, resp, gateCookie)
	check.AddCookie(&http.Cookie{Name: gateCookie, Value: pass})
	if resp := call(check); resp.StatusCode != http.StatusOK || resp.Header.Get("X-SGC-User") != "Kim" {
		t.Errorf("with the pass: %d %q", resp.StatusCode, resp.Header.Get("X-SGC-User"))
	}
	photos := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8444/gate/check-public", nil)
	photos.Header.Set("X-Forwarded-Host", "photos.domain.tld")
	photos.AddCookie(&http.Cookie{Name: gateCookie, Value: pass})
	if resp := call(photos); resp.StatusCode == http.StatusOK {
		t.Error("media's pass opened photos")
	}

	// Guessing Kim's password from many addresses: each address only
	// tries once, and the account is slowed down all the same.
	slowed := false
	for i := range 12 {
		resp := signIn("198.51.100."+string(rune('1'+i%9))+string(rune('0'+i/9)), "kim", "guess", "/")
		if resp.StatusCode == http.StatusTooManyRequests {
			slowed = true
			break
		}
	}
	if !slowed {
		t.Error("guessing one account from many addresses was not slowed down")
	}
	if resp := signIn("192.0.2.50", "kim", "a-made-up-password", "/"); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("right after the guessing, the right password from a new address: %d (want it to wait too)", resp.StatusCode)
	}
}

func TestSafePaths(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/movies?id=1": true, "//evil.example": false, "https://evil.example": false,
		"/\\evil.example": false, "relative": false, "/a\r\nSet-Cookie: x": false,
	} {
		if got := safePath(p); got != want {
			t.Errorf("safePath(%q) = %t", p, got)
		}
	}
}
