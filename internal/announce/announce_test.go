package announce

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
)

type world struct {
	t        *testing.T
	catalog  *services.Catalog
	announce *Service
	alerts   []string
	changes  int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	w := &world{t: t}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w.catalog = services.New(services.Config{
		DB: db, Audit: audit.New(db), Log: log,
		Domain: func(context.Context) (string, bool, error) { return "domain.tld", true, nil },
		LAN:    func() (netinfo.LAN, error) { return netinfo.LAN{}, errors.New("not needed") },
		Reserved: func(context.Context) (map[string]string, error) {
			return map[string]string{"sgc": "SGC's page", "adguard": "AdGuard Home's page"}, nil
		},
		Changed: func() { w.changes++ },
	})
	w.announce = New(Config{DB: db, Audit: audit.New(db), Services: w.catalog, Log: log,
		Alert: func(_ context.Context, title, _ string) { w.alerts = append(w.alerts, title) }})
	return w
}

func (w *world) token(label string) string {
	w.t.Helper()
	_, secret, err := w.announce.Create(context.Background(), "alex", "192.168.1.2", label)
	if err != nil {
		w.t.Fatal(err)
	}
	return secret
}

func form(fields ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(fields); i += 2 {
		v.Add(fields[i], fields[i+1])
	}
	return v
}

func (w *world) send(token, ip string, f url.Values) ([]services.AnnounceResult, error) {
	return w.announce.Handle(context.Background(), token, ip, f)
}

func TestAnnouncingAndThePin(t *testing.T) {
	w := newWorld(t)
	token := w.token("media server")
	results, err := w.send(token, "192.168.1.30", form("service", "jellyfin:8096", "service", "music:4533", "category", "Media"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].URL != "https://jellyfin.domain.tld" || !results[0].New || results[1].Refused != "" {
		t.Fatalf("results: %+v", results)
	}
	list, _ := w.catalog.List(context.Background())
	if len(list) != 2 || list[0].UpstreamIP != "192.168.1.30" || list[0].Category != "Media" || list[0].TokenLabel != "media server" {
		t.Fatalf("services: %+v", list)
	}
	// The same again changes nothing.
	changes := w.changes
	if _, err := w.send(token, "192.168.1.30", form("service", "jellyfin:8096", "service", "music:4533", "category", "Media")); err != nil {
		t.Fatal(err)
	}
	if w.changes != changes {
		t.Error("announcing the same again was a change")
	}
	// A new port is taken up.
	w.send(token, "192.168.1.30", form("service", "jellyfin:8920"))
	list, _ = w.catalog.List(context.Background())
	if list[0].UpstreamPort != 8920 || list[0].Category != "Media" {
		t.Errorf("after a new port: %+v", list[0])
	}
	// From another address the token is refused.
	var refusal *Refusal
	if _, err := w.send(token, "192.168.1.31", form("service", "jellyfin:8096")); !errors.As(err, &refusal) || refusal.Status != 403 {
		t.Errorf("from another address: %v", err)
	}
	tokens, _ := w.announce.List(context.Background())
	if tokens[0].PinnedIP != "192.168.1.30" || len(tokens[0].Services) != 2 || !strings.HasPrefix(tokens[0].Hint, "sgc_") {
		t.Errorf("token: %+v", tokens[0])
	}
	// Until the owner moves it.
	if err := w.announce.Repin(context.Background(), "alex", "192.168.1.2", tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.send(token, "192.168.1.31", form("service", "jellyfin:8096")); err != nil {
		t.Errorf("after moving it: %v", err)
	}
}

func TestFirstClaimWins(t *testing.T) {
	w := newWorld(t)
	first, second := w.token("one"), w.token("two")
	w.send(first, "192.168.1.30", form("service", "photos:2342"))
	results, err := w.send(second, "192.168.1.40", form("service", "photos:80", "service", "sgc:80", "service", "Bad_Name:80"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Refused == "" {
			t.Errorf("%s was accepted", r.Name)
		}
	}
	if !results[0].Conflict || !results[1].Conflict {
		t.Errorf("conflicts not marked: %+v", results)
	}
	// A name the owner added in the page is not taken over either.
	w.catalog.Add(context.Background(), "alex", "192.168.1.2", services.Input{Name: "router", UpstreamIP: "192.168.1.1", UpstreamPort: 80, Enabled: true})
	if results, _ := w.send(first, "192.168.1.30", form("service", "router:80")); results[0].Refused == "" {
		t.Error("the owner's service was taken over")
	}
	if len(w.alerts) == 0 {
		t.Error("no alert about the conflicts")
	}
}

func TestTokensSGCDoesNotKnow(t *testing.T) {
	w := newWorld(t)
	var refusal *Refusal
	for i := range 5 {
		if _, err := w.send("sgc_made-up", "192.168.1.66", form("service", "x:80")); !errors.As(err, &refusal) || refusal.Status != 401 {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// The sixth is not even looked at.
	if _, err := w.send(w.token("real"), "192.168.1.66", form("service", "x:80")); !errors.As(err, &refusal) || refusal.Status != 429 {
		t.Errorf("after five failures: %v", err)
	}
}

func TestApproval(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.catalog.SetSettings(ctx, "alex", "", services.Settings{ApproveNew: true, IconCatalogue: true, AbandonedDays: 14})
	results, _ := w.send(w.token("one"), "192.168.1.30", form("service", "wiki:3000"))
	if !results[0].Pending {
		t.Fatalf("not pending: %+v", results[0])
	}
	if names, _ := w.catalog.ProxyServices(ctx, nil); len(names) != 0 {
		t.Error("a pending service has a route")
	}
	list, _ := w.catalog.List(ctx)
	w.catalog.Approve(ctx, "alex", "", list[0].ID)
	if names, _ := w.catalog.ProxyServices(ctx, nil); len(names) != 1 {
		t.Error("an approved service has no route")
	}
}

func TestRemovingAToken(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	one, two := w.token("one"), w.token("two")
	w.send(one, "192.168.1.30", form("service", "a:80"))
	w.send(two, "192.168.1.40", form("service", "b:80"))
	tokens, _ := w.announce.List(ctx)
	// Newest first: two, then one.
	w.announce.Remove(ctx, "alex", "", tokens[1].ID, false)
	w.announce.Remove(ctx, "alex", "", tokens[0].ID, true)
	list, _ := w.catalog.List(ctx)
	byName := map[string]services.Service{}
	for _, s := range list {
		byName[s.Name] = s
	}
	if byName["a"].Enabled || byName["a"].TokenID != nil {
		t.Errorf("a: %+v", byName["a"])
	}
	if !byName["b"].Enabled || byName["b"].TokenID != nil {
		t.Errorf("b: %+v", byName["b"])
	}
	if _, err := w.send(one, "192.168.1.30", form("service", "a:80")); err == nil {
		t.Error("a removed token still works")
	}
}

func TestWhatAnAnnouncementMaySay(t *testing.T) {
	for _, f := range []url.Values{
		form(),
		form("service", "nocolon"),
		form("service", "x:99999"),
		form("service", "x:80", "type", "ftp"),
		form("service", "x:80", "mode", "sideways"),
	} {
		if _, err := parse(f); err == nil {
			t.Errorf("accepted %v", f)
		}
	}
	got, err := parse(form("service", "Game:25565", "type", "tcp", "mode", "proxied"))
	if err != nil || got[0].Name != "game" || got[0].Kind != "tcp" || got[0].Mode != "proxied" {
		t.Errorf("got %+v, %v", got, err)
	}
}
