package dnsnames

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Troglobitten/sgc/internal/store"
)

// fakeAdGuard answers the four calls SGC makes, the way AdGuard Home 0.107.79
// describes them.
type fakeAdGuard struct {
	mu       sync.Mutex
	rewrites []Rewrite
	off      bool
}

func (f *fakeAdGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method + " " + r.URL.Path {
	case "GET /control/rewrite/list":
		json.NewEncoder(w).Encode(f.rewrites)
	case "GET /control/rewrite/settings":
		json.NewEncoder(w).Encode(map[string]bool{"enabled": !f.off})
	case "POST /control/rewrite/add", "POST /control/rewrite/delete":
		var entry Rewrite
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &entry); err != nil || entry.Domain == "" || entry.Answer == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if strings.HasSuffix(r.URL.Path, "add") {
			f.rewrites = append(f.rewrites, entry)
			return
		}
		for i, existing := range f.rewrites {
			if existing.Domain == entry.Domain && existing.Answer == entry.Answer {
				f.rewrites = append(f.rewrites[:i], f.rewrites[i+1:]...)
				return
			}
		}
		http.Error(w, "not found", http.StatusBadRequest)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAdGuard) has(domain, answer string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rewrites {
		if r.Domain == domain && r.Answer == answer {
			return true
		}
	}
	return false
}

func setup(t *testing.T, fake *fakeAdGuard, wanted *[]Name) *Service {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return New(Config{
		DB:      db,
		AdGuard: &Client{Base: server.URL, HTTP: server.Client()},
		Desired: func(context.Context) ([]Name, error) { return *wanted, nil },
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func TestNamesAreAddedChangedAndRemoved(t *testing.T) {
	fake := &fakeAdGuard{rewrites: []Rewrite{{Domain: "printer.home", Answer: "192.168.1.9"}}}
	wanted := []Name{{Domain: "SGC.domain.tld", Answer: "192.168.1.50", For: "SGC's page"}, {Domain: "nas.domain.tld", Answer: "192.168.1.20"}}
	s := setup(t, fake, &wanted)

	status := s.Sync(context.Background())
	if status.Problem != "" || !fake.has("sgc.domain.tld", "192.168.1.50") || !fake.has("nas.domain.tld", "192.168.1.20") {
		t.Fatalf("first round: %+v, AdGuard Home has %+v", status, fake.rewrites)
	}
	for _, n := range status.Names {
		if !n.InPlace {
			t.Errorf("%s not in place", n.Domain)
		}
	}

	// The device got another address; the NAS was removed.
	wanted = []Name{{Domain: "sgc.domain.tld", Answer: "192.168.1.51"}}
	s.Sync(context.Background())
	if fake.has("sgc.domain.tld", "192.168.1.50") || fake.has("nas.domain.tld", "192.168.1.20") || !fake.has("sgc.domain.tld", "192.168.1.51") {
		t.Errorf("after the change AdGuard Home has %+v", fake.rewrites)
	}
	// The owner's own rewrite was never touched.
	if !fake.has("printer.home", "192.168.1.9") {
		t.Error("the owner's rewrite was removed")
	}
	// The same again changes nothing.
	before := len(fake.rewrites)
	s.Sync(context.Background())
	if len(fake.rewrites) != before {
		t.Errorf("a second round changed something: %+v", fake.rewrites)
	}
}

func TestTheOwnersRewriteForTheSameNameIsLeftAlone(t *testing.T) {
	fake := &fakeAdGuard{rewrites: []Rewrite{{Domain: "nas.domain.tld", Answer: "192.168.1.77"}}}
	wanted := []Name{{Domain: "nas.domain.tld", Answer: "192.168.1.20"}}
	s := setup(t, fake, &wanted)
	status := s.Sync(context.Background())
	if fake.has("nas.domain.tld", "192.168.1.20") || !fake.has("nas.domain.tld", "192.168.1.77") {
		t.Errorf("AdGuard Home has %+v", fake.rewrites)
	}
	if status.Names[0].InPlace || !strings.Contains(status.Names[0].Conflict, "192.168.1.77") {
		t.Errorf("reported %+v", status.Names[0])
	}
	// Once the owner removes theirs, SGC's goes in, and SGC later removes
	// only its own.
	fake.mu.Lock()
	fake.rewrites = nil
	fake.mu.Unlock()
	s.Sync(context.Background())
	if !fake.has("nas.domain.tld", "192.168.1.20") {
		t.Error("not added once the name was free")
	}
	wanted = nil
	fake.mu.Lock()
	fake.rewrites = append(fake.rewrites, Rewrite{Domain: "nas.domain.tld", Answer: "192.168.1.77"})
	fake.mu.Unlock()
	s.Sync(context.Background())
	if fake.has("nas.domain.tld", "192.168.1.20") || !fake.has("nas.domain.tld", "192.168.1.77") {
		t.Errorf("SGC removed more or less than its own: %+v", fake.rewrites)
	}
}

func TestWhenAdGuardHomeIsNotThere(t *testing.T) {
	wanted := []Name{{Domain: "sgc.domain.tld", Answer: "192.168.1.50"}}
	s := setup(t, &fakeAdGuard{}, &wanted)
	s.cfg.AdGuard.Base = "http://127.0.0.1:1"
	if status := s.Sync(context.Background()); status.Problem == "" {
		t.Error("no problem reported")
	}
}

func TestRewritesSwitchedOffAreReported(t *testing.T) {
	wanted := []Name{{Domain: "sgc.domain.tld", Answer: "192.168.1.50"}}
	s := setup(t, &fakeAdGuard{off: true}, &wanted)
	if status := s.Sync(context.Background()); !status.RewritesOff {
		t.Error("not reported")
	}
}

func TestOnlyIPv4AnswersAreUsed(t *testing.T) {
	got := normalise([]Name{{Domain: "a.domain.tld", Answer: "fe80::1"}, {Domain: "", Answer: "192.168.1.2"}, {Domain: "b.domain.tld.", Answer: "192.168.1.2"}, {Domain: "b.domain.tld", Answer: "192.168.1.2"}})
	if len(got) != 1 || got[0].Domain != "b.domain.tld" {
		t.Errorf("got %+v", got)
	}
}
