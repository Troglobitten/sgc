package publiccontrol

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsprovider"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/public"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

type fakeHelper struct{ installed []string }

func (f *fakeHelper) InstallPackages(_ context.Context, feature string) error {
	f.installed = append(f.installed, feature)
	return nil
}
func (f *fakeHelper) PublicBans(context.Context) ([]public.Ban, error) { return nil, nil }
func (f *fakeHelper) PublicUnban(context.Context, string) error        { return nil }

type world struct {
	s       *Service
	catalog *services.Catalog
	zone    *zonetest.Server
	applied atomic.Int32
	home    atomic.Value // netip.Addr
	lists   *httptest.Server
	broken  atomic.Bool
	now     time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	w := &world{now: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
	w.home.Store(netip.MustParseAddr("203.0.113.10"))
	w.zone = zonetest.New("alex", "a-made-up-key", "domain.tld")
	api := httptest.NewServer(w.zone)
	t.Cleanup(api.Close)
	w.lists = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.broken.Load() {
			http.Error(rw, "no", http.StatusInternalServerError)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		switch {
		case strings.HasPrefix(name, "firehol_level"):
			level := strings.TrimSuffix(name, ".netset")
			fmt.Fprintf(rw, "#\n# %s\n#\n198.51.100.0/24\n192.0.2.66\n", level)
		case name == countryFile(w.now):
			rw.Write(countryList(t))
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(w.lists.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lan := func() (netinfo.LAN, error) {
		return netinfo.LAN{Address: netip.MustParseAddr("192.168.1.50"), Network: netip.MustParsePrefix("192.168.1.0/24")}, nil
	}
	w.catalog = services.New(services.Config{DB: db, Audit: audit.New(db), Log: log, LAN: lan,
		Domain:   func(context.Context) (string, bool, error) { return "domain.tld", true, nil },
		Reserved: func(context.Context) (map[string]string, error) { return map[string]string{"sgc": "SGC's page"}, nil }})
	w.s = New(Config{
		DB: db, Audit: audit.New(db), Helper: &fakeHelper{}, Catalog: w.catalog,
		FirewallOn: func(context.Context) bool { return true },
		ProxyOn:    func(context.Context) bool { return true },
		Apply:      func(context.Context) error { w.applied.Add(1); return nil },
		DNS: func(context.Context) (dnsprovider.Provider, dnsprovider.Account, bool, error) {
			account := dnsprovider.Account{Domain: "domain.tld", Provider: dnsprovider.ZoneID, Values: map[string]string{"username": "alex", "apiKey": "a-made-up-key"}}
			p, err := dnsprovider.Open(account, dnsprovider.Options{ZoneEndpoint: api.URL + "/v2/", StandIn: true})
			return p, account, true, err
		},
		PublicIP:    func(context.Context) (netip.Addr, error) { return w.home.Load().(netip.Addr), nil },
		LAN:         lan,
		HTTP:        &http.Client{Timeout: 5 * time.Second},
		ListsDir:    t.TempDir(),
		FireHOLBase: w.lists.URL + "/",
		DBIPBase:    w.lists.URL + "/",
		Window:      func(context.Context) (int, int, error) { return 4 * 60, 5 * 60, nil },
		Now:         func() time.Time { return w.now },
		Log:         log,
	})
	return w
}

func countryList(t *testing.T) []byte {
	var csv strings.Builder
	csv.WriteString("2.56.0.0,2.56.3.255,EE\n5.0.0.0,5.0.0.255,NL\n")
	for i := range 1200 {
		fmt.Fprintf(&csv, "%d.%d.0.0,%d.%d.255.255,ZZ\n", 100+i/250, i%250, 100+i/250, i%250)
	}
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	gz.Write([]byte(csv.String()))
	gz.Close()
	return b.Bytes()
}

func (w *world) add(t *testing.T, in services.Input) services.Service {
	t.Helper()
	in.Enabled = true
	s, err := w.catalog.Add(context.Background(), "alex", "", in)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOpeningAndClosingAServiceMakesAndRemovesItsName(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	web := w.add(t, services.Input{Name: "media", UpstreamIP: "192.168.1.30", UpstreamPort: 8096})
	game := w.add(t, services.Input{Name: "mc", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.40", UpstreamPort: 25565, SRVService: "minecraft"})

	if err := w.s.SetServicePublic(ctx, "alex", "", web.ID, true); err == nil {
		t.Fatal("a service was made public with internet access off")
	}
	if err := w.s.SetEnabled(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{web.ID, game.ID} {
		if err := w.s.SetServicePublic(ctx, "alex", "", id, true); err != nil {
			t.Fatal(err)
		}
	}
	w.s.keepRecords(ctx)
	if got := w.zone.A("media.domain.tld"); !slices.Equal(got, []string{"203.0.113.10"}) {
		t.Errorf("media's public name points at %q", got)
	}
	if got := w.zone.SRV("_minecraft._tcp.mc.domain.tld"); !slices.Equal(got, []string{"0 5 25565 mc.domain.tld"}) {
		t.Errorf("mc's service record is %q", got)
	}
	status, _ := w.s.Status(ctx)
	if len(status.Services) != 2 || status.Problem != "" {
		t.Errorf("status: %+v", status)
	}

	// The home gets another address: the names follow.
	w.home.Store(netip.MustParseAddr("203.0.113.11"))
	w.s.keepRecords(ctx)
	if got := w.zone.A("mc.domain.tld"); !slices.Equal(got, []string{"203.0.113.11"}) {
		t.Errorf("after the home's address changed, mc points at %q", got)
	}

	// Closed: the names go.
	if err := w.s.SetServicePublic(ctx, "alex", "", game.ID, false); err != nil {
		t.Fatal(err)
	}
	w.s.keepRecords(ctx)
	if got := w.zone.A("mc.domain.tld"); len(got) != 0 {
		t.Errorf("a closed service still has a public name: %q", got)
	}
	if got := w.zone.SRV("_minecraft._tcp.mc.domain.tld"); len(got) != 0 {
		t.Errorf("a closed service still has a service record: %q", got)
	}
	if got := w.zone.A("media.domain.tld"); len(got) != 1 {
		t.Errorf("closing mc took media's name too: %q", got)
	}

	// Internet access off: every name goes.
	if err := w.s.SetEnabled(ctx, "alex", "", false); err != nil {
		t.Fatal(err)
	}
	w.s.keepRecords(ctx)
	if got := w.zone.A("media.domain.tld"); len(got) != 0 {
		t.Errorf("with internet access off, media still has a public name: %q", got)
	}
	if w.applied.Load() < 5 {
		t.Errorf("the proxy was told %d times, want after every change", w.applied.Load())
	}
	// And on again: nothing is public until the owner opens it again.
	if err := w.s.SetEnabled(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	if open, _ := w.catalog.PublicServices(ctx); len(open) != 0 {
		t.Errorf("switched off and on again, %d service(s) are public by themselves", len(open))
	}
}

func TestAProviderOutOfReachIsNewsOnlyOnceItLasts(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	web := w.add(t, services.Input{Name: "media", UpstreamIP: "192.168.1.30", UpstreamPort: 8096})
	w.s.SetEnabled(ctx, "alex", "", true)
	if err := w.s.SetServicePublic(ctx, "alex", "", web.ID, true); err != nil {
		t.Fatal(err)
	}
	w.s.keepRecords(ctx)
	w.zone.FailWith(http.StatusBadGateway)
	for minutes := 0; minutes < 30; minutes += 5 {
		w.s.keepRecords(ctx)
		if status, _ := w.s.Status(ctx); status.Problem != "" {
			t.Fatalf("after %d minutes out of reach, news already: %s", minutes, status.Problem)
		}
		w.now = w.now.Add(5 * time.Minute)
	}
	w.s.keepRecords(ctx)
	if status, _ := w.s.Status(ctx); !strings.Contains(status.Problem, "could not be asked") {
		t.Errorf("after half an hour out of reach: %q", status.Problem)
	}
	w.zone.FailWith(0)
	w.s.keepRecords(ctx)
	if status, _ := w.s.Status(ctx); status.Problem != "" {
		t.Errorf("back in reach: %q", status.Problem)
	}
	if st := w.s.state(ctx); st.Failing.Since != nil {
		t.Errorf("the run of failures was not cleared: %+v", st.Failing)
	}
}

func TestANameAlreadyGoneAtTheProviderIsNoProblem(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	game := w.add(t, services.Input{Name: "mc", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.40", UpstreamPort: 25565, SRVService: "minecraft"})
	if err := w.s.SetEnabled(ctx, "alex", "", true); err != nil {
		t.Fatal(err)
	}
	if err := w.s.SetServicePublic(ctx, "alex", "", game.ID, true); err != nil {
		t.Fatal(err)
	}
	w.s.keepRecords(ctx)
	if len(w.zone.A("mc.domain.tld")) != 1 || len(w.zone.SRV("_minecraft._tcp.mc.domain.tld")) != 1 {
		t.Fatal("the names were not made")
	}
	// The owner removes both at the provider, then closes the service (or
	// this is a restored device whose old names went meanwhile).
	w.zone.RemoveByHand("mc.domain.tld")
	w.zone.RemoveByHand("_minecraft._tcp.mc.domain.tld")
	if err := w.s.SetServicePublic(ctx, "alex", "", game.ID, false); err != nil {
		t.Fatal(err)
	}
	w.s.keepRecords(ctx)
	if status, _ := w.s.Status(ctx); status.Problem != "" {
		t.Errorf("a name already gone is reported as a problem: %s", status.Problem)
	}
	if mine := w.s.madeRecords(ctx); len(mine) != 0 {
		t.Errorf("SGC still counts %d record(s) as its own", len(mine))
	}
}

func TestARecordSGCDidNotMakeIsNeverTouched(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	web := w.add(t, services.Input{Name: "media", UpstreamIP: "192.168.1.30", UpstreamPort: 8096})
	w.zone.AddA("domain.tld", "media.domain.tld", "198.51.100.1")
	w.s.SetEnabled(ctx, "alex", "", true)
	err := w.s.SetServicePublic(ctx, "alex", "", web.ID, true)
	if err == nil || !strings.Contains(err.Error(), "did not make") {
		t.Errorf("opening a name with someone else's record: %v", err)
	}
	w.s.keepRecords(ctx)
	if got := w.zone.A("media.domain.tld"); !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Errorf("the owner's own record became %q", got)
	}
}

func TestWhatCanBeMadePublic(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	direct := w.add(t, services.Input{Name: "nas", Kind: "tcp", Mode: "direct", UpstreamIP: "192.168.1.20", UpstreamPort: 445})
	w.s.SetEnabled(ctx, "alex", "", true)
	if err := w.s.SetServicePublic(ctx, "alex", "", direct.ID, true); err == nil {
		t.Error("a service that does not go through SGC was made public")
	}
	off := New(w.s.cfg)
	off.cfg.FirewallOn = func(context.Context) bool { return false }
	if err := off.SetEnabled(ctx, "alex", "", true); err == nil {
		// SetEnabled with the firewall off writes nothing.
		t.Error("internet access was switched on with the firewall off")
	}
}

func TestSettingsAndTheLists(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	s := defaults()
	s.Allow = []string{"friend.example"}
	if err := w.s.SetSettings(ctx, "alex", "", s); err == nil {
		t.Error("a name on the allow list was taken")
	}
	s.Allow = []string{" 198.51.100.7 ", "198.51.100.7"}
	s.Levels = []string{public.ListLevel1}
	s.CountryMode, s.Countries = public.CountryAllow, []string{"ee", "nl"}
	if err := w.s.SetSettings(ctx, "alex", "", s); err != nil {
		t.Fatal(err)
	}
	got := w.s.Settings(ctx)
	if !slices.Equal(got.Allow, []string{"198.51.100.7"}) || !slices.Equal(got.Countries, []string{"EE", "NL"}) {
		t.Errorf("the settings as kept: %+v", got)
	}
	built, err := w.s.BuildPublic(ctx)
	if err != nil || len(built.FireHOL) != 1 || built.FireHOL[0].Name != public.ListLevel1 || built.CountryList == nil || built.CountryMode != public.CountryAllow {
		t.Errorf("BuildPublic = %+v, %v", built, err)
	}

	// A level that cannot be fetched is not switched on.
	w.broken.Store(true)
	s.Levels = []string{public.ListLevel1, public.ListLevel4}
	if err := w.s.SetSettings(ctx, "alex", "", s); err == nil {
		t.Error("a level that could not be fetched was switched on")
	}
	if got := w.s.Settings(ctx); slices.Contains(got.Levels, public.ListLevel4) {
		t.Error("the failed level is in the settings all the same")
	}
	// The daily round keeps the last good list when the download fails.
	w.now = w.now.Add(24 * time.Hour)
	w.s.refresh(ctx)
	if _, ok := w.s.fileHash(public.ListLevel1); !ok {
		t.Error("a failed download removed the last good list")
	}
	lists := w.s.Lists(ctx)
	if lists[0].Error == "" || lists[0].UpdatedAt == nil {
		t.Errorf("the failed download is not shown: %+v", lists[0])
	}
}

func TestTheDailyRound(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.now = time.Date(2026, 10, 26, 3, 0, 0, 0, time.UTC)
	if !w.s.refreshDue(ctx) {
		t.Error("never run: not due")
	}
	w.s.refresh(ctx)
	if w.s.refreshDue(ctx) {
		t.Error("due again right after a round")
	}
	// The window is 04:00 to 05:00: the round is at 04:30.
	w.now = time.Date(2026, 10, 26, 4, 20, 0, 0, time.UTC)
	if w.s.refreshDue(ctx) {
		t.Error("due before half past four")
	}
	w.now = time.Date(2026, 10, 26, 4, 31, 0, 0, time.UTC)
	if !w.s.refreshDue(ctx) {
		t.Error("not due after half past four")
	}
}

func TestARestoredDeviceKeepsInternetAccessOff(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	web := w.add(t, services.Input{Name: "media", UpstreamIP: "192.168.1.30", UpstreamPort: 8096})
	w.s.SetEnabled(ctx, "alex", "", true)
	if err := w.s.SetServicePublic(ctx, "alex", "", web.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := w.s.MarkRestored(ctx); err != nil {
		t.Fatal(err)
	}
	if w.s.On(ctx) {
		t.Error("internet access is on after a restore")
	}
	w.s.SetEnabled(ctx, "alex", "", true)
	if open, _ := w.catalog.PublicServices(ctx); len(open) != 0 {
		t.Errorf("on a restored device, %d service(s) became public without the owner opening them", len(open))
	}
}
