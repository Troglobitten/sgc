package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
)

type gateNames struct{}

func (gateNames) Status(context.Context) (gateway.Status, error) {
	return gateway.Status{Name: "sgc", Domain: "domain.tld", FQDN: "sgc.domain.tld", URL: "https://sgc.domain.tld:8443"}, nil
}
func (gateNames) SetName(context.Context, string, string, string) error { return nil }

// gateServices has two web services: media (protected) and open (not).
type gateServices struct{ Services }

func (gateServices) List(context.Context) ([]services.Service, error) {
	return []services.Service{
		{ID: 1, Name: "media", Kind: "http", Protected: true, Enabled: true},
		{ID: 2, Name: "photos", Kind: "http", Protected: true, Enabled: true},
		{ID: 3, Name: "open", Kind: "http", Enabled: true},
	}, nil
}

func gateServer(t *testing.T) (*Server, *people.Service) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	authService, _ := auth.NewService(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ppl := people.New(people.Config{DB: db, Audit: audit.New(db), Log: log, AdminUsername: func(context.Context) (string, error) { return "owner", nil }})
	db.Exec("INSERT INTO service (id, name, kind, upstream_ip, upstream_port, created_at, updated_at) VALUES (1, 'media', 'http', '192.168.1.30', 80, 0, 0), (2, 'photos', 'http', '192.168.1.31', 80, 0, 0)")
	return &Server{Auth: authService, Audit: audit.New(db), People: ppl, Names: gateNames{}, Services: gateServices{},
		Gate: &GateStore{DB: db}, Log: log}, ppl
}

func cookieFrom(t *testing.T, resp *http.Response, name string) string {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	t.Fatalf("no cookie %s in %v", name, resp.Header["Set-Cookie"])
	return ""
}

func TestTheGate(t *testing.T) {
	s, ppl := gateServer(t)
	ctx := context.Background()
	_, err := ppl.Add(ctx, "owner", "", people.Input{Name: "Kim", Network: people.NetworkServices, ServiceIDs: []int64{1},
		LoginEnabled: true, Username: "kim", Password: "a-made-up-password"})
	if err != nil {
		t.Fatal(err)
	}
	internal, page := s.InternalHandler(), s.Handler()
	call := func(h http.Handler, req *http.Request) *http.Response {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Result()
	}
	check := func(host, cookie string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8444/gate/check", nil)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Uri", "/movies?id=1")
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: gateCookie, Value: cookie})
		}
		return call(internal, req)
	}

	// Without a pass: off to SGC's sign-in, with the way back.
	resp := check("media.domain.tld", "")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://sgc.domain.tld:8443/gate?rd="+url.QueryEscape("https://media.domain.tld/movies?id=1") {
		t.Fatalf("without a pass: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Signing in as Kim.
	req := httptest.NewRequest(http.MethodPost, "https://sgc.domain.tld:8443/api/gate/login", strings.NewReader(`{"username":"kim","password":"a-made-up-password"}`))
	req.Header.Set("Content-Type", "application/json")
	person := cookieFrom(t, call(page, req), personCookie)

	ticketFor := func(rd string) *http.Response {
		req := httptest.NewRequest(http.MethodPost, "https://sgc.domain.tld:8443/api/gate/ticket", strings.NewReader(`{"rd":"`+rd+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: personCookie, Value: person})
		return call(page, req)
	}
	resp = ticketFor("https://media.domain.tld/movies?id=1")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "https://media.domain.tld/.sgc-gate/return?ticket=") {
		t.Fatalf("a ticket: %d %s", resp.StatusCode, body)
	}
	back := string(body)[strings.Index(string(body), "https://"):]
	back = back[:strings.Index(back, `"`)]

	// Elsewhere, or not on Kim's list, or not protected: no ticket.
	for _, rd := range []string{"https://photos.domain.tld/", "https://evil.example.com/", "https://open.domain.tld/", "http://media.domain.tld/", "https://media.domain.tld:8080/"} {
		if resp := ticketFor(rd); resp.StatusCode == http.StatusOK {
			t.Errorf("a ticket for %s", rd)
		}
	}

	// The ticket on another name is refused; on its own name it becomes the pass.
	returnOn := func(host string) *http.Response {
		u, _ := url.Parse(back)
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8444"+u.RequestURI(), nil)
		req.Host = host
		return call(internal, req)
	}
	if resp := returnOn("photos.domain.tld"); resp.StatusCode == http.StatusFound {
		t.Error("a ticket worked on another name")
	}
	// Taken once by the wrong name, the ticket is gone: a new one.
	resp = ticketFor("https://media.domain.tld/movies?id=1")
	body, _ = io.ReadAll(resp.Body)
	back = string(body)[strings.Index(string(body), "https://"):]
	back = back[:strings.Index(back, `"`)]
	resp = returnOn("media.domain.tld")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://media.domain.tld/movies?id=1" {
		t.Fatalf("the way back: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	pass := cookieFrom(t, resp, gateCookie)
	if resp := returnOn("media.domain.tld"); resp.StatusCode == http.StatusFound {
		t.Error("a ticket worked twice")
	}

	// With the pass Kim gets in, as Kim; on another name the pass is nothing.
	resp = check("media.domain.tld", pass)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-SGC-User") != "Kim" {
		t.Errorf("with the pass: %d %q", resp.StatusCode, resp.Header.Get("X-SGC-User"))
	}
	if resp := check("photos.domain.tld", pass); resp.StatusCode == http.StatusOK {
		t.Error("the pass of one name opened another")
	}

	// Kim's login switched off: the pass stops working at once.
	everyone, _ := ppl.List(ctx)
	ppl.Update(ctx, "owner", "", everyone[0].ID, people.Input{Name: "Kim", Network: people.NetworkServices, ServiceIDs: []int64{1}})
	if resp := check("media.domain.tld", pass); resp.StatusCode == http.StatusOK {
		t.Error("a pass worked after the login was switched off")
	}
}
