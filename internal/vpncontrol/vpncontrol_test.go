package vpncontrol

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/wireguard"
	"github.com/Troglobitten/sgc/internal/zone"
	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

type fakeHelper struct {
	applied []wireguard.Config
	refuse  bool
}

func (f *fakeHelper) VPNStatus(context.Context) (helper.VPNStatus, error) {
	return helper.VPNStatus{Installed: true, On: len(f.applied) > 0 && f.applied[len(f.applied)-1].Enabled}, nil
}
func (f *fakeHelper) VPNApply(_ context.Context, cfg wireguard.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if f.refuse {
		return errors.New("refused on purpose")
	}
	f.applied = append(f.applied, cfg)
	return nil
}
func (f *fakeHelper) InstallPackages(context.Context, string) error { return nil }

type world struct {
	vpn     *Service
	people  *people.Service
	catalog *services.Catalog
	helper  *fakeHelper
}

func newWorld(t *testing.T) *world {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lan := func() (netinfo.LAN, error) {
		return netinfo.LAN{Address: netip.MustParseAddr("192.168.1.50"), Network: netip.MustParsePrefix("192.168.1.0/24")}, nil
	}
	domain := func(context.Context) (string, bool, error) { return "domain.tld", true, nil }
	w := &world{helper: &fakeHelper{}}
	w.catalog = services.New(services.Config{DB: db, Audit: audit.New(db), Log: log, Domain: domain, LAN: lan,
		Reserved: func(context.Context) (map[string]string, error) { return nil, nil }})
	w.people = people.New(people.Config{DB: db, Audit: audit.New(db), Log: log,
		AdminUsername: func(context.Context) (string, error) { return "owner", nil }})
	w.vpn = New(Config{DB: db, Helper: w.helper, Audit: audit.New(db), People: w.people, Services: w.catalog,
		Domain: domain, LAN: lan, Log: log,
		VerifyAdmin: func(_ context.Context, password, _ string) error {
			if password != "the admin's password" {
				return auth.ErrWrongPassword
			}
			return nil
		}})
	return w
}

func (w *world) on(t *testing.T) {
	t.Helper()
	err := w.vpn.SetSettings(context.Background(), "alex", "", Settings{Enabled: true, Port: 51820, Network: DefaultNetwork, Name: "vpn", EndpointMode: ModeDynamic},
		func(context.Context, string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
}

func TestDevicesAndWhatTheyReach(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.on(t)
	nas, _ := w.catalog.Add(ctx, "alex", "", services.Input{Name: "nas", UpstreamIP: "192.168.1.20", UpstreamPort: 5000, Enabled: true})
	photos, _ := w.catalog.Add(ctx, "alex", "", services.Input{Name: "photos", UpstreamIP: "192.168.1.21", UpstreamPort: 2342, Enabled: true})
	voice, _ := w.catalog.Add(ctx, "alex", "", services.Input{Name: "voice", Kind: "udp", UpstreamIP: "192.168.1.40", UpstreamPort: 9987, Enabled: true})
	game, _ := w.catalog.Add(ctx, "alex", "", services.Input{Name: "game", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.41", UpstreamPort: 25565, Enabled: true})

	owner, _ := w.people.Add(ctx, "alex", "", people.Input{Name: "Owner", Network: people.NetworkFull})
	guest, _ := w.people.Add(ctx, "alex", "", people.Input{Name: "Guest", Network: people.NetworkServices, ServiceIDs: []int64{photos.ID, voice.ID}})
	phone, err := w.vpn.AddDevice(ctx, "alex", "", owner.ID, "phone", false)
	if err != nil {
		t.Fatal(err)
	}
	tablet, _ := w.vpn.AddDevice(ctx, "alex", "", guest.ID, "tablet", true)
	if phone.Address != "10.86.0.2" || tablet.Address != "10.86.0.3" {
		t.Errorf("addresses: %s, %s", phone.Address, tablet.Address)
	}
	if _, err := w.vpn.AddDevice(ctx, "alex", "", owner.ID, "phone", false); err == nil {
		t.Error("two devices with one name for one person")
	}

	cfg, err := w.vpn.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("SGC builds what the root side refuses: %v", err)
	}
	byAddress := map[string]wireguard.Peer{}
	for _, p := range cfg.Peers {
		byAddress[p.Address] = p
	}
	if byAddress["10.86.0.2"].Access != wireguard.AccessFull {
		t.Errorf("the owner's phone: %+v", byAddress["10.86.0.2"])
	}
	g := byAddress["10.86.0.3"]
	if g.Access != wireguard.AccessServices || len(g.Direct) != 1 || g.Direct[0].Port != 9987 || len(g.GatewayPorts) != 0 {
		t.Errorf("the guest's tablet: %+v", g)
	}

	// The proxy keeps the guest's tablet out of the NAS, not out of photos.
	allow := w.vpn.AllowFor(ctx)
	nasAllowed := strings.Join(allow(nas.ID), " ")
	photosAllowed := strings.Join(allow(photos.ID), " ")
	if strings.Contains(nasAllowed, "10.86.0.3/32") || !strings.Contains(nasAllowed, "10.86.0.2/32") || !strings.Contains(nasAllowed, "192.168.0.0/16") {
		t.Errorf("who may reach the NAS: %s", nasAllowed)
	}
	// Every device may reach photos: no list at all, so nothing in the home
	// network can be kept out by mistake.
	if photosAllowed != "" {
		t.Errorf("who may reach photos: %s", photosAllowed)
	}
	if strings.Contains(nasAllowed, "10.86.0.0/24") || strings.Contains(nasAllowed, "10.0.0.0/8") {
		t.Errorf("the tunnel's range is let in as a whole: %s", nasAllowed)
	}
	_ = game

	// A guest past their end date is gone from the VPN.
	past := time.Now().Add(-time.Hour)
	w.people.Update(ctx, "alex", "", guest.ID, people.Input{Name: "Guest", Network: people.NetworkServices, ExpiresAt: &past})
	cfg, _ = w.vpn.Build(ctx)
	if len(cfg.Peers) != 1 {
		t.Errorf("an expired guest's device is still in: %+v", cfg.Peers)
	}

	// The settings file, with the admin's password only.
	if _, _, err := w.vpn.DeviceConfig(ctx, "alex", "", phone.ID, "wrong"); !errors.Is(err, auth.ErrWrongPassword) {
		t.Errorf("without the password: %v", err)
	}
	text, filename, err := w.vpn.DeviceConfig(ctx, "alex", "", phone.ID, "the admin's password")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Address = 10.86.0.2/32", "DNS = 10.86.0.1", "Endpoint = vpn.domain.tld:51820",
		"AllowedIPs = 10.86.0.0/24, 192.168.1.0/24, 192.168.1.50/32", "PersistentKeepalive = 25", "PresharedKey = "} {
		if !strings.Contains(text, want) {
			t.Errorf("the settings lack %q:\n%s", want, text)
		}
	}
	if filename != "Owner-phone.conf" {
		t.Errorf("file name %q", filename)
	}
	tabletText, _, _ := w.vpn.DeviceConfig(ctx, "alex", "", tablet.ID, "the admin's password")
	if !strings.Contains(tabletText, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Errorf("all traffic through home:\n%s", tabletText)
	}
	// The private key in the file belongs to the public key WireGuard gets.
	for _, line := range strings.Split(text, "\n") {
		if key, ok := strings.CutPrefix(line, "PrivateKey = "); ok {
			if public, _ := wireguard.PublicKey(key); public != phone.PublicKey {
				t.Error("the device's keys do not belong together")
			}
		}
	}
}

func TestSettingsThatAreRefused(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	free := func(context.Context, string) (string, error) { return "", nil }
	bad := []Settings{
		{Port: 80, Network: DefaultNetwork, Name: "vpn", EndpointMode: ModeDynamic},
		{Port: 51820, Network: "192.168.1.0/24", Name: "vpn", EndpointMode: ModeDynamic}, // the home network itself
		{Port: 51820, Network: "8.8.8.0/24", Name: "vpn", EndpointMode: ModeDynamic},
		{Port: 51820, Network: DefaultNetwork, Name: "Not a name", EndpointMode: ModeDynamic},
		{Port: 51820, Network: DefaultNetwork, Name: "vpn", EndpointMode: ModeStatic, StaticIP: "192.168.1.1"},
	}
	for _, s := range bad {
		if err := w.vpn.SetSettings(ctx, "alex", "", s, free); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	w.on(t)
	owner, _ := w.people.Add(ctx, "alex", "", people.Input{Name: "Owner", Network: people.NetworkFull})
	w.vpn.AddDevice(ctx, "alex", "", owner.ID, "phone", false)
	if err := w.vpn.SetSettings(ctx, "alex", "", Settings{Enabled: true, Port: 51820, Network: "10.87.0.0/24", Name: "vpn", EndpointMode: ModeDynamic}, free); err == nil {
		t.Error("the range changed with a device in it")
	}
}

func TestSubtract(t *testing.T) {
	got := subtract([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, netip.MustParsePrefix("10.86.0.0/24"))
	if len(got) != 16 {
		t.Fatalf("%d pieces: %v", len(got), got)
	}
	hole := netip.MustParseAddr("10.86.0.7")
	outside := []string{"10.0.0.1", "10.86.1.1", "10.255.255.254", "10.85.255.255"}
	for _, p := range got {
		if p.Contains(hole) {
			t.Errorf("%s contains the hole", p)
		}
	}
	for _, a := range outside {
		addr := netip.MustParseAddr(a)
		found := false
		for _, p := range got {
			found = found || p.Contains(addr)
		}
		if !found {
			t.Errorf("%s was lost", a)
		}
	}
}

func TestThePublicName(t *testing.T) {
	stand := zonetest.New("alex", "a-made-up-key", "domain.tld")
	server := httptest.NewServer(stand)
	defer server.Close()
	w := newWorld(t)
	ctx := context.Background()
	w.on(t)
	address := netip.MustParseAddr("203.0.113.7")
	endpoint := NewEndpoint(EndpointConfig{
		DB: w.vpn.cfg.DB, Audit: w.vpn.cfg.Audit, Log: w.vpn.cfg.Log,
		Settings: w.vpn.Settings,
		Zone: func(context.Context) (*zone.Client, string, bool, error) {
			client, err := zone.NewClient(server.URL+"/v2/", "alex", "a-made-up-key", "sgc/test", &http.Client{Timeout: 5 * time.Second})
			return client, "domain.tld", true, err
		},
		PublicIP: func(context.Context) (netip.Addr, error) { return address, nil },
	})
	state := endpoint.Check(ctx)
	if state.Problem != "" || strings.Join(stand.A("vpn.domain.tld"), ",") != "203.0.113.7" {
		t.Fatalf("first look: %+v, Zone.eu has %v", state, stand.A("vpn.domain.tld"))
	}
	address = netip.MustParseAddr("198.51.100.9")
	endpoint.Check(ctx)
	if got := stand.A("vpn.domain.tld"); len(got) != 1 || got[0] != "198.51.100.9" {
		t.Errorf("after the address changed: %v", got)
	}
	// A record of the owner's own is not touched without their say.
	stand.AddA("domain.tld", "other.domain.tld", "198.51.100.1")
	w.vpn.SetSettings(ctx, "alex", "", Settings{Enabled: true, Port: 51820, Network: DefaultNetwork, Name: "other", EndpointMode: ModeDynamic},
		func(context.Context, string) (string, error) { return "", nil })
	state = endpoint.Check(ctx)
	if !state.Foreign || strings.Join(stand.A("other.domain.tld"), ",") != "198.51.100.1" {
		t.Errorf("an owner's record: %+v, %v", state, stand.A("other.domain.tld"))
	}
	if err := endpoint.TakeOver(ctx); err != nil {
		t.Fatal(err)
	}
	endpoint.Check(ctx)
	if got := stand.A("other.domain.tld"); len(got) != 1 || got[0] != "198.51.100.9" {
		t.Errorf("after taking it over: %v", got)
	}
	// Shared addresses of the provider: said, and nothing written.
	address = netip.MustParseAddr("100.64.3.4")
	if state := endpoint.Check(ctx); !strings.Contains(state.Problem, "carrier-grade NAT") {
		t.Errorf("CGNAT: %+v", state)
	}
}
