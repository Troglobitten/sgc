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
	"sync"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/dnsprovider"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/wireguard"
	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

type fakeHelper struct {
	mu      sync.Mutex
	applied []wireguard.Config
	refuse  bool
	// slow makes a change take a while; overlapped counts changes that
	// arrived while another one was still being put in place.
	slow       time.Duration
	busy       bool
	overlapped int
}

func (f *fakeHelper) VPNStatus(context.Context) (helper.VPNStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return helper.VPNStatus{Installed: true, On: len(f.applied) > 0 && f.applied[len(f.applied)-1].Enabled}, nil
}
func (f *fakeHelper) VPNApply(_ context.Context, cfg wireguard.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	f.mu.Lock()
	if f.busy {
		f.overlapped++
	}
	f.busy = true
	slow, refuse := f.slow, f.refuse
	f.mu.Unlock()
	time.Sleep(slow)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.busy = false
	if refuse {
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

// Switching on while SGC brings the VPN up to date sent two changes at
// once on the test machine; the root side hands them over through one file
// and answered only one. Changes reach it one at a time, and a change that
// is what was just put in place is not sent again.
func TestChangesReachTheRootSideOneAtATime(t *testing.T) {
	w := newWorld(t)
	w.on(t)
	w.helper.mu.Lock()
	w.helper.slow, w.helper.applied = 20*time.Millisecond, nil
	w.helper.mu.Unlock()
	// Every call then has something to send, as when two changes come in.
	w.vpn.mu.Lock()
	w.vpn.applied = [32]byte{}
	w.vpn.mu.Unlock()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.vpn.Apply(context.Background())
		}()
	}
	wg.Wait()
	w.helper.mu.Lock()
	defer w.helper.mu.Unlock()
	if w.helper.overlapped != 0 {
		t.Errorf("%d changes reached the root side while another was being put in place", w.helper.overlapped)
	}
	if len(w.helper.applied) > 1 {
		t.Errorf("the same change was sent %d times", len(w.helper.applied))
	}
}

// Sending everything through home is for people who reach the whole home
// network (the owner's decision of 2026-10-24). A device of someone else
// that has it from before can still be switched on and off, and keeps the
// person from being set to "services only" until it is set to home only.
func TestAllTrafficThroughHome(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.on(t)
	owner, _ := w.people.Add(ctx, "alex", "", people.Input{Name: "Owner", Network: people.NetworkFull})
	guest, _ := w.people.Add(ctx, "alex", "", people.Input{Name: "Guest", Network: people.NetworkServices, AllServices: true})

	laptop, err := w.vpn.AddDevice(ctx, "alex", "", owner.ID, "laptop", true)
	if err != nil {
		t.Fatal(err)
	}
	text, _, _ := w.vpn.DeviceConfig(ctx, "alex", "", laptop.ID, "the admin's password")
	if !strings.Contains(text, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Errorf("all traffic through home:\n%s", text)
	}

	phone, err := w.vpn.AddDevice(ctx, "alex", "", guest.ID, "phone", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.vpn.UpdateDevice(ctx, "alex", "", phone.ID, "phone", true, true); err == nil {
		t.Error("a guest's device was set to send everything home")
	}
	// One from before 0.18.0, when this was not refused.
	if _, err := w.vpn.cfg.DB.ExecContext(ctx, "UPDATE vpn_device SET all_traffic = 1 WHERE id = ?", phone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.vpn.UpdateDevice(ctx, "alex", "", phone.ID, "phone", true, false); err != nil {
		t.Errorf("a device from before could not be switched off: %v", err)
	}
	if names, _ := w.vpn.AllTrafficDevices(ctx, guest.ID); len(names) != 1 || names[0] != "phone" {
		t.Errorf("AllTrafficDevices = %v", names)
	}
	if _, err := w.vpn.UpdateDevice(ctx, "alex", "", phone.ID, "phone", false, true); err != nil {
		t.Fatal(err)
	}
	if names, _ := w.vpn.AllTrafficDevices(ctx, guest.ID); len(names) != 0 {
		t.Errorf("after setting it to home only: %v", names)
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
	// Someone who reaches chosen services only cannot send everything home.
	if _, err := w.vpn.AddDevice(ctx, "alex", "", guest.ID, "tablet", true); err == nil || !strings.Contains(err.Error(), "whole home network") {
		t.Fatalf("a guest's device sending all its traffic home: %v", err)
	}
	tablet, _ := w.vpn.AddDevice(ctx, "alex", "", guest.ID, "tablet", false)
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
	// The guest's tablet keeps its own internet: only what is for home goes
	// through the VPN.
	tabletText, _, _ := w.vpn.DeviceConfig(ctx, "alex", "", tablet.ID, "the admin's password")
	if !strings.Contains(tabletText, "AllowedIPs = 10.86.0.0/24, 192.168.1.0/24, 192.168.1.50/32") {
		t.Errorf("the guest's device, home only:\n%s", tabletText)
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
		DNS: func(context.Context) (dnsprovider.Provider, dnsprovider.Account, bool, error) {
			account := dnsprovider.Account{Domain: "domain.tld", Provider: "zone", Values: map[string]string{"username": "alex", "apiKey": "a-made-up-key"}}
			client, err := dnsprovider.Open(account, dnsprovider.Options{ZoneEndpoint: server.URL + "/v2/", StandIn: true, HTTP: &http.Client{Timeout: 5 * time.Second}})
			return client, account, err == nil, err
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
