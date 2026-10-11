package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/health"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/update"
	"github.com/Troglobitten/sgc/internal/updater"
)

type fakeHelper struct {
	restarts int
	err      error
	// Versions the helper was asked to install.
	updates   []string
	updateErr error
}

func (f *fakeHelper) RestartDevice(context.Context) error {
	f.restarts++
	return f.err
}

func (f *fakeHelper) StartUpdate(_ context.Context, version string) error {
	f.updates = append(f.updates, version)
	return f.updateErr
}

// fakeUpdates stands in for the update checker.
type fakeUpdates struct {
	status   update.Status
	checks   int
	fetched  []string
	fetchErr error
}

func (f *fakeUpdates) Status(context.Context) (update.Status, error) { return f.status, nil }
func (f *fakeUpdates) Check(context.Context) (update.Status, error) {
	f.checks++
	return f.status, nil
}
func (f *fakeUpdates) Fetch(_ context.Context, version string) error {
	f.fetched = append(f.fetched, version)
	return f.fetchErr
}
func (f *fakeUpdates) SetAutoCheck(_ context.Context, enabled bool) error {
	f.status.AutoCheck = enabled
	return nil
}

type testEnv struct {
	t          *testing.T
	url        string
	client     *http.Client // keeps cookies, like a browser
	auth       *auth.Service
	helper     *fakeHelper
	updates    *fakeUpdates
	lastUpdate *updater.Status
	setupToken string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	authService, err := auth.NewService(db)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authService.NewSetupToken(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	helper := &fakeHelper{}
	updates := &fakeUpdates{status: update.Status{Current: "9.9.9", AutoCheck: true}}
	e := &testEnv{t: t, auth: authService, helper: helper, updates: updates, setupToken: token}
	server := &Server{
		Auth:       authService,
		Audit:      audit.New(db),
		Health:     health.NewMonitor(),
		Helper:     helper,
		Updates:    updates,
		LastUpdate: func() (*updater.Status, error) { return e.lastUpdate, nil },
		Version:    "9.9.9",
		UI: fstest.MapFS{
			"index.html":    {Data: []byte("<!doctype html><title>SGC</title>")},
			"assets/app.js": {Data: []byte("console.log('sgc')")},
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// TLS, because the session cookie is HTTPS-only.
	ts := httptest.NewTLSServer(server.Handler())
	t.Cleanup(ts.Close)
	client := ts.Client()
	client.Jar, _ = cookiejar.New(nil)

	e.url, e.client = ts.URL, client
	return e
}

// signIn takes a fresh environment straight to a signed-in admin.
func (e *testEnv) signIn() {
	e.t.Helper()
	body := setupRequest{Token: e.setupToken, Username: testUser, Password: testPassword}
	e.expectStatus(e.call("POST", "/api/setup", body, nil), http.StatusOK)
}

// call sends a JSON request and decodes a JSON answer into out (if not nil).
func (e *testEnv) call(method, path string, body, out any, headers ...string) *http.Response {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, e.url+path, reader)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			e.t.Fatalf("%s %s: answer is not the expected JSON: %v\n%s", method, path, err, data)
		}
	}
	return resp
}

func (e *testEnv) expectStatus(resp *http.Response, want int) {
	e.t.Helper()
	if resp.StatusCode != want {
		e.t.Errorf("%s %s: status = %d, want %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want)
	}
}

const (
	testUser     = "davy"
	testPassword = "correct horse battery"
)

// One continuous walk through the life of an installation. The steps depend
// on each other, like they do for a real user, and password hashing is slow
// by design, so a single shared environment keeps the test fast.
func TestFromFreshInstallToSignedOut(t *testing.T) {
	e := newTestEnv(t)

	t.Run("a fresh install asks for setup and protects everything else", func(t *testing.T) {
		var state stateResponse
		e.expectStatus(e.call("GET", "/api/state", nil, &state), http.StatusOK)
		if !state.SetupRequired || state.SignedIn || state.Version != "9.9.9" {
			t.Errorf("state = %+v", state)
		}
		for _, path := range []string{"/api/health", "/api/audit"} {
			e.expectStatus(e.call("GET", path, nil, nil), http.StatusUnauthorized)
		}
		e.expectStatus(e.call("POST", "/api/device/restart", restartRequest{Confirm: true}, nil), http.StatusUnauthorized)
		if e.helper.restarts != 0 {
			t.Error("the device was restarted without a session")
		}
	})

	t.Run("setup needs the right link", func(t *testing.T) {
		wrong := setupRequest{Token: "wrong", Username: testUser, Password: testPassword}
		e.expectStatus(e.call("POST", "/api/setup", wrong, nil), http.StatusForbidden)

		weak := setupRequest{Token: e.setupToken, Username: testUser, Password: "short"}
		e.expectStatus(e.call("POST", "/api/setup", weak, nil), http.StatusBadRequest)
	})

	t.Run("setup creates the admin and signs in", func(t *testing.T) {
		good := setupRequest{Token: e.setupToken, Username: testUser, Password: testPassword}
		resp := e.call("POST", "/api/setup", good, nil)
		e.expectStatus(resp, http.StatusOK)

		cookies := resp.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("got %d cookies, want 1", len(cookies))
		}
		c := cookies[0]
		if c.Name != "__Host-sgc_session" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
			t.Errorf("session cookie is not locked down: %+v", c)
		}

		var state stateResponse
		e.call("GET", "/api/state", nil, &state)
		if state.SetupRequired || !state.SignedIn || state.Username != testUser {
			t.Errorf("state after setup = %+v", state)
		}
	})

	t.Run("the setup link cannot be used twice", func(t *testing.T) {
		again := setupRequest{Token: e.setupToken, Username: "mallory", Password: testPassword}
		e.expectStatus(e.call("POST", "/api/setup", again, nil), http.StatusConflict)
	})

	t.Run("the dashboard data is available when signed in", func(t *testing.T) {
		var snapshot health.Snapshot
		e.expectStatus(e.call("GET", "/api/health", nil, &snapshot), http.StatusOK)
		if snapshot.MemoryTotalBytes == 0 || snapshot.Hostname == "" {
			t.Errorf("health looks empty: %+v", snapshot)
		}

		var entries []audit.Entry
		e.expectStatus(e.call("GET", "/api/audit", nil, &entries), http.StatusOK)
		if len(entries) != 2 || entries[0].Action != audit.ActionLogin || entries[1].Action != audit.ActionSetupCompleted {
			t.Errorf("audit log = %+v, want sign-in then setup", entries)
		}
	})

	t.Run("another website cannot act with the user's session", func(t *testing.T) {
		resp := e.call("POST", "/api/device/restart", restartRequest{Confirm: true}, nil,
			"Sec-Fetch-Site", "cross-site", "Origin", "https://evil.example")
		e.expectStatus(resp, http.StatusForbidden)
		if e.helper.restarts != 0 {
			t.Error("a cross-site request restarted the device")
		}
	})

	t.Run("restart needs confirmation and is recorded", func(t *testing.T) {
		e.expectStatus(e.call("POST", "/api/device/restart", restartRequest{Confirm: false}, nil), http.StatusBadRequest)
		if e.helper.restarts != 0 {
			t.Error("restarted without confirmation")
		}

		e.expectStatus(e.call("POST", "/api/device/restart", restartRequest{Confirm: true}, nil), http.StatusAccepted)
		if e.helper.restarts != 1 {
			t.Errorf("helper was asked %d times, want 1", e.helper.restarts)
		}
		var entries []audit.Entry
		e.call("GET", "/api/audit", nil, &entries)
		if entries[0].Action != audit.ActionDeviceRestart || entries[0].Actor != testUser {
			t.Errorf("newest audit entry = %+v, want the restart by %s", entries[0], testUser)
		}
	})

	t.Run("a helper failure is reported without internals", func(t *testing.T) {
		e.helper.err = errors.New("dial unix /run/secret/path: connection refused")
		var body struct{ Error string }
		resp := e.call("POST", "/api/device/restart", restartRequest{Confirm: true}, &body)
		e.expectStatus(resp, http.StatusBadGateway)
		if strings.Contains(body.Error, "/run/secret") {
			t.Errorf("internal detail leaked to the browser: %q", body.Error)
		}
		// The log must not be left claiming a restart that did not happen.
		var entries []audit.Entry
		e.call("GET", "/api/audit", nil, &entries)
		if entries[0].Action != audit.ActionDeviceRestartFailed {
			t.Errorf("newest audit entry = %q, want the failure to be recorded", entries[0].Action)
		}
		e.helper.err = nil
	})

	t.Run("signing out ends access", func(t *testing.T) {
		e.expectStatus(e.call("POST", "/api/logout", struct{}{}, nil), http.StatusOK)
		e.expectStatus(e.call("GET", "/api/health", nil, nil), http.StatusUnauthorized)
	})

	t.Run("signing in again", func(t *testing.T) {
		bad := loginRequest{Username: testUser, Password: "definitely wrong"}
		var body struct{ Error string }
		e.expectStatus(e.call("POST", "/api/login", bad, &body), http.StatusUnauthorized)
		if body.Error != "Wrong username or password." {
			t.Errorf("error = %q; it must not say which part was wrong", body.Error)
		}

		good := loginRequest{Username: testUser, Password: testPassword}
		e.expectStatus(e.call("POST", "/api/login", good, nil), http.StatusOK)
		e.expectStatus(e.call("GET", "/api/health", nil, nil), http.StatusOK)

		var entries []audit.Entry
		e.call("GET", "/api/audit", nil, &entries)
		if entries[1].Action != audit.ActionLoginFailed || strings.Contains(entries[1].Detail, "definitely wrong") {
			t.Errorf("failed sign-in entry = %+v; it must be recorded, without the password", entries[1])
		}
	})
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	e := newTestEnv(t)

	t.Run("not JSON", func(t *testing.T) {
		req, _ := http.NewRequest("POST", e.url+"/api/login", strings.NewReader("username=a&password=b"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		e.expectStatus(resp, http.StatusUnsupportedMediaType)
	})

	t.Run("unknown fields", func(t *testing.T) {
		body := map[string]any{"username": "a", "password": "b", "admin": true}
		e.expectStatus(e.call("POST", "/api/login", body, nil), http.StatusBadRequest)
	})

	t.Run("oversized body", func(t *testing.T) {
		body := loginRequest{Username: "a", Password: strings.Repeat("x", maxRequestBody)}
		e.expectStatus(e.call("POST", "/api/login", body, nil), http.StatusBadRequest)
	})

	t.Run("unknown endpoint answers in JSON", func(t *testing.T) {
		var body struct{ Error string }
		e.expectStatus(e.call("GET", "/api/nope", nil, &body), http.StatusNotFound)
		if body.Error == "" {
			t.Error("no error message")
		}
	})
}

func TestBrowserInterfaceIsServed(t *testing.T) {
	e := newTestEnv(t)

	get := func(path string) (*http.Response, string) {
		resp, err := e.client.Get(e.url + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp, string(data)
	}

	// The app handles its own page addresses, so they all get the app.
	for _, path := range []string{"/", "/setup", "/login"} {
		resp, body := get(path)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<title>SGC</title>") {
			t.Errorf("GET %s: status %d, body %q", path, resp.StatusCode, body)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
			t.Errorf("GET %s: Cache-Control = %q; the page must always be revalidated", path, got)
		}
	}

	resp, body := get("/assets/app.js")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "sgc") {
		t.Errorf("asset: status %d, body %q", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("asset Cache-Control = %q, want long-lived", resp.Header.Get("Cache-Control"))
	}

	if resp, _ := get("/assets/missing.js"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing asset: status %d, want 404 (not the app)", resp.StatusCode)
	}

	resp, _ = get("/")
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q", csp)
	}
}
