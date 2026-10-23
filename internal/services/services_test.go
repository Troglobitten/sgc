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
	routes, _ := c.ProxyServices(ctx, nil)
	if len(routes) != 2 {
		t.Errorf("routes: %+v", routes)
	}

	// Switched off: no name, no route.
	off := Input{Name: "nas", UpstreamIP: "192.168.1.20", UpstreamPort: 5001, Scheme: "https", Enabled: false}
	if _, err := c.Update(ctx, "alex", "", nas.ID, off); err != nil {
		t.Fatal(err)
	}
	if routes, _ := c.ProxyServices(ctx, nil); len(routes) != 1 {
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
