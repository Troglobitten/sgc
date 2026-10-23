package eol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/store"
)

func TestEndOfLife(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	answering := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !answering {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/api/v1/products/debian/releases/13":
			w.Write([]byte(`{"result":{"eoasFrom":"2027-01-31","eolFrom":"2030-06-30"}}`))
		case "/api/v1/products/traefik/releases/3.7":
			w.Write([]byte(`{"result":{"eoasFrom":null,"eolFrom":null}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Transport = rewrite{to: server.URL, next: http.DefaultTransport}
	s := New(Config{DB: db, HTTP: client, DebianCycle: func() string { return "13" }, TraefikCycle: "3.7",
		Now: func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }})

	state := s.Check(context.Background())
	if state.Problem != "" || len(state.Items) != 2 {
		t.Fatalf("got %+v", state)
	}
	debian := state.Items[0]
	if !strings.Contains(debian.Warning, "in 99 days") || debian.Source != "online" {
		t.Errorf("Debian: %+v", debian)
	}
	if state.Items[1].Warning != "" {
		t.Errorf("Traefik without an end date: %+v", state.Items[1])
	}
	// Not reachable: said, and SGC's own table is used.
	answering = false
	state = s.Check(context.Background())
	if state.Problem == "" || state.Items[0].Source != "table" || state.Items[0].SecurityEnd == nil {
		t.Errorf("unreachable: %+v", state)
	}
	if got := s.State(context.Background()); got.Problem == "" {
		t.Error("the look was not kept")
	}
}

// rewrite sends requests for endoflife.date to the test's server.
type rewrite struct {
	to   string
	next http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	target, _ := http.NewRequestWithContext(req.Context(), req.Method, r.to+u.Path, nil)
	return r.next.RoundTrip(target)
}
