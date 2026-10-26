package services

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/store"
)

func catalog(t *testing.T) *Catalog {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(Config{
		DB: db, Audit: audit.New(db), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Domain: func(context.Context) (string, bool, error) { return "domain.tld", true, nil },
		LAN: func() (netinfo.LAN, error) {
			return netinfo.LAN{Address: netip.MustParseAddr("192.168.1.50"), Network: netip.MustParsePrefix("192.168.1.0/24")}, nil
		},
		Reserved:      func(context.Context) (map[string]string, error) { return map[string]string{"sgc": "SGC's page"}, nil },
		ReservedPorts: func(context.Context) []int { return []int{51820} },
	})
}

func TestWhatGoesIn(t *testing.T) {
	c := catalog(t)
	ctx := context.Background()
	bad := map[string]Input{
		"a name with a dot":      {Name: "my.nas", UpstreamIP: "192.168.1.20", UpstreamPort: 80},
		"an upper-case name":     {Name: "NAS", UpstreamIP: "192.168.1.20", UpstreamPort: 80},
		"the gateway's name":     {Name: "sgc", UpstreamIP: "192.168.1.20", UpstreamPort: 80},
		"an address outside":     {Name: "nas", UpstreamIP: "1.1.1.1", UpstreamPort: 80},
		"this device itself":     {Name: "nas", UpstreamIP: "192.168.1.50", UpstreamPort: 80},
		"no port":                {Name: "nas", UpstreamIP: "192.168.1.20"},
		"ftp":                    {Name: "nas", UpstreamIP: "192.168.1.20", UpstreamPort: 80, Scheme: "ftp"},
		"a protected game":       {Name: "mc", Kind: "tcp", UpstreamIP: "192.168.1.20", UpstreamPort: 25565, Protected: true},
		"the gateway's https":    {Name: "mc", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 443},
		"the VPN's port":         {Name: "mc", Kind: "udp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 51820},
		"a title of 200 letters": {Name: "nas", Title: strings.Repeat("x", 200), UpstreamIP: "192.168.1.20", UpstreamPort: 80},
	}
	for what, in := range bad {
		if _, err := c.Add(ctx, "alex", "", in); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	nas, err := c.Add(ctx, "alex", "", Input{Name: "nas", Title: "The NAS", UpstreamIP: "192.168.1.20", UpstreamPort: 5001, Scheme: "https", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if nas.URL != "https://nas.domain.tld" || nas.Kind != "http" {
		t.Errorf("added: %+v", nas)
	}
	game, err := c.Add(ctx, "alex", "", Input{Name: "mc", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.30", UpstreamPort: 25565, Enabled: true})
	if err != nil || game.ListenPort != 25565 || game.URL != "mc.domain.tld:25565" {
		t.Fatalf("a game: %+v, %v", game, err)
	}
	if _, err := c.Add(ctx, "alex", "", Input{Name: "mc2", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.31", UpstreamPort: 25565, Enabled: true}); err == nil {
		t.Error("two services on one port of the gateway")
	}
	direct, _ := c.Add(ctx, "alex", "", Input{Name: "voice", Kind: "udp", UpstreamIP: "192.168.1.32", UpstreamPort: 9987, Enabled: true})
	if direct.Mode != ModeDirect {
		t.Errorf("a game is direct by default: %+v", direct)
	}
	if _, err := c.Add(ctx, "alex", "", Input{Name: "nas", UpstreamIP: "192.168.1.21", UpstreamPort: 80}); err == nil {
		t.Error("a name twice")
	}

	// AdGuard Home: the web service and the proxied game at the gateway, the
	// direct one at its own device. Without the proxy, only the direct one.
	names, _ := c.Names(ctx, true)
	got := map[string]string{}
	for _, n := range names {
		got[n.Domain] = n.Answer
	}
	if got["nas.domain.tld"] != "192.168.1.50" || got["mc.domain.tld"] != "192.168.1.50" || got["voice.domain.tld"] != "192.168.1.32" {
		t.Errorf("names: %v", got)
	}
	if names, _ := c.Names(ctx, false); len(names) != 1 {
		t.Errorf("without the proxy: %+v", names)
	}
	routes, _ := c.ProxyServices(ctx, nil, false)
	if len(routes) != 2 {
		t.Errorf("routes: %+v", routes)
	}

	// Switched off: no name, no route.
	off := Input{Name: "nas", UpstreamIP: "192.168.1.20", UpstreamPort: 5001, Scheme: "https", Enabled: false}
	if _, err := c.Update(ctx, "alex", "", nas.ID, off); err != nil {
		t.Fatal(err)
	}
	if routes, _ := c.ProxyServices(ctx, nil, false); len(routes) != 1 {
		t.Errorf("routes after switching off: %+v", routes)
	}
}

func TestUpAndDown(t *testing.T) {
	c := catalog(t)
	ctx := context.Background()
	answering := true
	c.cfg.Probe = func(context.Context, string) error {
		if answering {
			return nil
		}
		return errors.New("refused")
	}
	clock := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	c.cfg.Now = func() time.Time { return clock }
	c.Add(ctx, "alex", "", Input{Name: "nas", UpstreamIP: "192.168.1.20", UpstreamPort: 80, Enabled: true})
	var seen []Transition
	note := func(tr Transition) { seen = append(seen, tr) }
	c.ProbeAll(ctx, note)
	answering = false
	c.ProbeAll(ctx, note) // one failure is not "down" yet
	if len(seen) != 0 {
		t.Fatalf("down after one failure: %+v", seen)
	}
	c.ProbeAll(ctx, note)
	if len(seen) != 1 || seen[0].Up {
		t.Fatalf("after two failures: %+v", seen)
	}
	clock = clock.Add(15 * 24 * time.Hour)
	list, _ := c.List(ctx)
	if !list[0].Health.Abandoned {
		t.Errorf("not abandoned after 15 days: %+v", list[0].Health)
	}
	answering = true
	c.ProbeAll(ctx, note)
	if len(seen) != 2 || !seen[1].Up {
		t.Errorf("back up: %+v", seen)
	}
}

func pngOf(t *testing.T, w, h int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.NRGBA{R: 200, G: 30, B: 30, A: 255})
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

func TestIconsAreDrawnAnew(t *testing.T) {
	check := func(what string, data []byte) {
		t.Helper()
		out, err := Redraw(data)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		img, err := png.Decode(bytes.NewReader(out))
		if err != nil || img.Bounds().Dx() != 64 || img.Bounds().Dy() != 64 {
			t.Fatalf("%s: not a 64-pixel PNG", what)
		}
		if r, _, _, a := img.At(32, 32).RGBA(); r>>8 < 190 || a == 0 {
			t.Errorf("%s: the colour was lost", what)
		}
	}
	check("a PNG", pngOf(t, 180, 120))

	// An .ico with a PNG inside, and one with a 32-bit bitmap.
	icoWith := func(picture []byte, w, h byte) []byte {
		var b bytes.Buffer
		b.Write([]byte{0, 0, 1, 0, 1, 0})
		b.Write([]byte{w, h, 0, 0, 1, 0, 32, 0})
		binary.Write(&b, binary.LittleEndian, uint32(len(picture)))
		binary.Write(&b, binary.LittleEndian, uint32(22))
		b.Write(picture)
		return b.Bytes()
	}
	check("an icon with a PNG", icoWith(pngOf(t, 32, 32), 32, 32))
	var dib bytes.Buffer
	binary.Write(&dib, binary.LittleEndian, []uint32{40, 16, 32})
	binary.Write(&dib, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&dib, binary.LittleEndian, []uint32{0, 0, 0, 0, 0, 0})
	for range 16 * 16 {
		dib.Write([]byte{30, 30, 200, 255}) // blue, green, red, alpha
	}
	dib.Write(make([]byte, 16*4)) // the mask
	check("an icon with a bitmap", icoWith(dib.Bytes(), 16, 16))

	for what, data := range map[string][]byte{
		"an SVG":     []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"HTML":       []byte("<html>"),
		"a tiny PNG": pngOf(t, 2, 2),
	} {
		if _, err := Redraw(data); err == nil {
			t.Errorf("%s was taken as an icon", what)
		}
	}
}

type fakeCollection map[string][]byte

func (f fakeCollection) Lookup(names ...string) []byte {
	for _, n := range names {
		if data, ok := f[n]; ok {
			return data
		}
	}
	return nil
}

func TestIconsFromTheCollection(t *testing.T) {
	collection := fakeCollection{
		"home-assistant": pngOf(t, 128, 128),
		"evil":           []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
	}
	f := NewIconFetcher(collection)
	// A game server: nothing to ask the service itself, only the collection.
	ha := Service{Name: "ha", Title: "Home Assistant", Kind: "tcp"}
	icon, source := f.find(context.Background(), ha, true)
	if icon == nil || source != SourceCollection {
		t.Fatalf("by its title: %d bytes from %q", len(icon), source)
	}
	if img, err := png.Decode(bytes.NewReader(icon)); err != nil || img.Bounds().Dx() != iconSize {
		t.Errorf("the collection's icon was not drawn anew at %d pixels: %v", iconSize, err)
	}
	if icon, _ := f.find(context.Background(), ha, false); icon != nil {
		t.Error("an icon from the collection with the owner's switch off")
	}
	if icon, _ := f.find(context.Background(), Service{Name: "evil", Kind: "tcp"}, true); icon != nil {
		t.Error("what the collection handed over was used without being an image SGC reads")
	}
}

func TestIconLinksInAPage(t *testing.T) {
	page := `<html><head><link rel="mask-icon" href="/mask.svg"><link rel="icon" href="/x.svg" type="image/svg+xml">
		<link rel="icon" href="/small.png"><link rel="icon" sizes="32x32" href="/32.png"><link rel="apple-touch-icon" href="/touch.png">
		</head><body><link rel="icon" href="/late.png"></body></html>`
	got := strings.Join(iconLinks([]byte(page)), " ")
	if got != "/touch.png /32.png /small.png" {
		t.Errorf("got %q", got)
	}
	if names := catalogueNames(Service{Name: "ha", Title: "Home Assistant"}); strings.Join(names, " ") != "ha home-assistant" {
		t.Errorf("catalogue names: %v", names)
	}
}

// A public service stays public only while the owner keeps it so: switching
// it off, a server announcing it anew with other settings, or that server's
// token being marked as moved or removed closes it, and the owner hears.
func TestSGCClosesAPublicServiceByItself(t *testing.T) {
	ctx := context.Background()
	c := catalog(t)
	var closed []string
	c.cfg.Closed = func(_ context.Context, name, why string) { closed = append(closed, name+": "+why) }
	db := c.cfg.DB
	db.Exec("INSERT INTO announce_token (id, label, token_hash, hint, pinned_ip, created_at) VALUES (7, 'old-gateway', x'00', 'sgc_', '192.168.1.30', 0)")

	isPublic := func(name string) bool {
		var exposure string
		db.QueryRow("SELECT exposure FROM service WHERE name = ?", name).Scan(&exposure)
		return exposure == ExposurePublic
	}
	open := func(name string) {
		var id int64
		db.QueryRow("SELECT id FROM service WHERE name = ?", name).Scan(&id)
		if err := c.SetExposure(ctx, id, ExposurePublic); err != nil {
			t.Fatal(err)
		}
	}

	// Switched off in the page.
	web, err := c.Add(ctx, "alex", "", Input{Name: "media", UpstreamIP: "192.168.1.30", UpstreamPort: 8096, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	open("media")
	if routes, _ := c.ProxyServices(ctx, nil, true); len(routes) != 1 || !routes[0].Public {
		t.Fatalf("a public service is not public at the proxy: %+v", routes)
	}
	if routes, _ := c.ProxyServices(ctx, nil, false); routes[0].Public {
		t.Error("a public service is public while internet access is off")
	}
	in := Input{Name: "media", UpstreamIP: "192.168.1.30", UpstreamPort: 8096, Enabled: false}
	if _, err := c.Update(ctx, "alex", "", web.ID, in); err != nil {
		t.Fatal(err)
	}
	if isPublic("media") {
		t.Error("a public service switched off is still public")
	}

	// Announced anew by its server with another port.
	if _, err := c.Announce(ctx, 7, "old-gateway", "192.168.1.30", []Announcement{{Name: "game", Port: 25565, Kind: "tcp", Mode: "proxied"}}); err != nil {
		t.Fatal(err)
	}
	open("game")
	results, err := c.Announce(ctx, 7, "old-gateway", "192.168.1.30", []Announcement{{Name: "game", Port: 25565, Kind: "tcp", Mode: "proxied"}})
	if err != nil || results[0].Closed || !isPublic("game") {
		t.Errorf("the same announcement again closed it: %+v, %v", results, err)
	}
	results, err = c.Announce(ctx, 7, "old-gateway", "192.168.1.30", []Announcement{{Name: "game", Port: 25566, Kind: "tcp", Mode: "proxied"}})
	if err != nil || !results[0].Closed || isPublic("game") {
		t.Errorf("an announcement with another port left it public: %+v, %v", results, err)
	}

	// The token marked as moved, then removed.
	open("game")
	c.CloseToken(ctx, "alex", "", 7, "its server was marked as moved")
	if isPublic("game") {
		t.Error("a moved server's service is still public")
	}
	open("game")
	if err := c.ReleaseToken(ctx, 7, true); err != nil {
		t.Fatal(err)
	}
	if isPublic("game") {
		t.Error("a removed token's service is still public")
	}
	if len(closed) != 4 {
		t.Errorf("the owner heard of %d closings, want 4: %q", len(closed), closed)
	}
}

func TestTheNewSettingsOfAService(t *testing.T) {
	ctx := context.Background()
	c := catalog(t)
	bad := map[string]Input{
		"PROXY protocol on UDP": {Name: "g", Kind: "udp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 27015, ProxyProtocol: true},
		"PROXY protocol direct": {Name: "g", Kind: "tcp", Mode: "direct", UpstreamIP: "192.168.1.20", UpstreamPort: 25565, ProxyProtocol: true},
		"a quiet time on TCP":   {Name: "g", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 25565, UDPTimeout: 30},
		"a quiet time of hours": {Name: "g", Kind: "udp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 27015, UDPTimeout: 7200},
		"an SRV name of digits": {Name: "g", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 25565, SRVService: "1234"},
		"an SRV name too long":  {Name: "g", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 25565, SRVService: "a-very-long-service"},
		"an SRV name with _":    {Name: "g", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 25565, SRVService: "_minecraft"},
		"the public door":       {Name: "g", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 8446},
	}
	for what, in := range bad {
		if _, err := c.Add(ctx, "alex", "", in); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	s, err := c.Add(ctx, "alex", "", Input{Name: "mc", Kind: "tcp", Mode: "proxied", UpstreamIP: "192.168.1.20", UpstreamPort: 25565,
		ProxyProtocol: true, SRVService: "Minecraft", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !s.ProxyProtocol || s.SRVService != "minecraft" || s.Exposure != ExposureLAN {
		t.Errorf("the service as kept: %+v", s)
	}
	routes, _ := c.ProxyServices(ctx, nil, true)
	if len(routes) != 1 || !routes[0].ProxyProtocol || routes[0].Public {
		t.Errorf("the route: %+v", routes)
	}
}
