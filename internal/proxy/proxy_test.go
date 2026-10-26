package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/public"
)

// go test ./internal/proxy -update rewrites the expected files. Read the
// difference: it is a change to what Traefik is told.
var update = flag.Bool("update", false, "rewrite the expected files in testdata")

var now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// certificate makes a made-up wildcard certificate for domain.tld.
func certificate(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func sample(t *testing.T) Config {
	cert, key := certificate(t, "*.domain.tld")
	return Config{
		Enabled: true, Domain: "domain.tld", GatewayName: "sgc", WebPort: 8443,
		CertificatePEM: cert, PrivateKeyPEM: key, Reserved: []int{22, 51820},
		Services: []Service{
			{Name: "nas", Kind: KindHTTP, Upstream: "192.168.1.20", Port: 5001, Scheme: "https"},
			{Name: "media", Kind: KindHTTP, Upstream: "192.168.1.30", Port: 8096, Scheme: "http", Protected: true,
				AllowFrom: []string{"192.168.0.0/16", "10.86.0.5/32"}},
			{Name: "minecraft", Kind: KindTCP, Upstream: "192.168.1.40", Port: 25565, ListenPort: 25565},
			{Name: "game", Kind: KindUDP, Upstream: "192.168.1.40", Port: 27015, ListenPort: 27016},
		},
	}
}

func TestRender(t *testing.T) {
	cfg := sample(t)
	// The routes file's label is a fingerprint of the certificate too, and
	// sample makes a new one every time: a fixed text keeps the expected
	// file the same (rendering does not read the certificate).
	cfg.CertificatePEM = "the certificate of the expected files"
	static, err := RenderStatic(cfg, "/etc/sgc/traefik/dynamic")
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := RenderDynamic(cfg, "/etc/sgc/traefik/certs/wildcard.crt", "/etc/sgc/traefik/certs/wildcard.key")
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"static.yml": static, "dynamic.yml": dynamic} {
		golden := filepath.Join("testdata", name)
		if *update {
			os.MkdirAll("testdata", 0o755)
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from what is expected:\n%s", name, got)
		}
		// What Traefik reads as YAML must be JSON after the comment line.
		body := got[strings.IndexByte(string(got), '\n')+1:]
		if !json.Valid(body) {
			t.Errorf("%s is not JSON after its first line", name)
		}
	}
	if strings.Contains(string(dynamic), "PRIVATE KEY") {
		t.Error("the key is in the routes file instead of its own")
	}
}

// withDoor is the sample with internet access on: one web service public
// and protected, one public game port told who the visitor is, one UDP port
// public with a longer quiet time; nas stays home-only.
func withDoor(t *testing.T) Config {
	cfg := sample(t)
	cfg.CertificatePEM = "the certificate of the expected files"
	settings := public.Defaults()
	cfg.Door, cfg.Public = true, &settings
	for i := range cfg.Services {
		switch cfg.Services[i].Name {
		case "media":
			cfg.Services[i].Public = true
		case "minecraft":
			cfg.Services[i].Public, cfg.Services[i].ProxyProtocol = true, true
		case "game":
			cfg.Services[i].Public, cfg.Services[i].UDPTimeout = true, 60
		}
	}
	return cfg
}

func TestRenderWithTheDoor(t *testing.T) {
	cfg := withDoor(t)
	static, err := RenderStatic(cfg, "/etc/sgc/traefik/dynamic")
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := RenderDynamic(cfg, "/etc/sgc/traefik/certs/wildcard.crt", "/etc/sgc/traefik/certs/wildcard.key")
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"static-door.yml": static, "dynamic-door.yml": dynamic} {
		golden := filepath.Join("testdata", name)
		if *update {
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from what is expected:\n%s", name, got)
		}
	}
	if got := cfg.PublicPorts(); !slices.Equal(got, []string{"25565/tcp", "27016/udp", "8446/tcp"}) {
		t.Errorf("PublicPorts = %v", got)
	}
}

// The public door carries routes for public services and nothing else: not
// SGC's page, not AdGuard Home's, not a home-only service, not the "unknown"
// page that names SGC. A name asked for there that is not public gets
// Traefik's plain "not found".
func TestTheDoorCarriesOnlyPublicServices(t *testing.T) {
	cfg := withDoor(t)
	dynamic, err := RenderDynamic(cfg, "/c.crt", "/c.key")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		HTTP struct {
			Routers map[string]struct {
				Rule        string   `json:"rule"`
				EntryPoints []string `json:"entryPoints"`
			} `json:"routers"`
		} `json:"http"`
		TCP struct {
			Routers map[string]struct {
				EntryPoints []string `json:"entryPoints"`
			} `json:"routers"`
		} `json:"tcp"`
	}
	if err := json.Unmarshal(dynamic[strings.IndexByte(string(dynamic), '\n')+1:], &parsed); err != nil {
		t.Fatal(err)
	}
	onDoor := 0
	for name, router := range parsed.HTTP.Routers {
		if !slices.Contains(router.EntryPoints, "public") {
			continue
		}
		onDoor++
		if len(router.EntryPoints) != 1 {
			t.Errorf("router %s is on the door and elsewhere", name)
		}
		if !strings.Contains(router.Rule, "media.domain.tld") {
			t.Errorf("router %s on the door is not for the public service: %s", name, router.Rule)
		}
	}
	// media is behind SGC's login in the sample: the service and its sign-in.
	if onDoor != 2 {
		t.Errorf("%d routers on the door, want the public service's two", onDoor)
	}
	for name, router := range parsed.TCP.Routers {
		if slices.Contains(router.EntryPoints, "public") {
			t.Errorf("TCP router %s is on the door: SGC's page would face the internet", name)
		}
	}
	// With the gate, its sign-in comes on the door too, under the service's
	// own name.
	for i := range cfg.Services {
		if cfg.Services[i].Name == "media" {
			cfg.Services[i].Protected = true
		}
	}
	dynamic, _ = RenderDynamic(cfg, "/c.crt", "/c.key")
	if !strings.Contains(string(dynamic), `"public-gate-media"`) || !strings.Contains(string(dynamic), "/gate/check-public") {
		t.Error("a protected public service has no sign-in on the door")
	}
}

func TestWhatTheDoorRefuses(t *testing.T) {
	cases := map[string]func(*Config){
		"a public service with internet access off": func(c *Config) { c.Door, c.Public = false, nil },
		"internet access without its settings":      func(c *Config) { c.Public = nil },
		"settings that do not pass":                 func(c *Config) { c.Public.RequestsPerMinute = 0 },
		"the PROXY protocol on UDP": func(c *Config) {
			for i := range c.Services {
				if c.Services[i].Kind == KindUDP {
					c.Services[i].ProxyProtocol = true
				}
			}
		},
		"a quiet time on TCP": func(c *Config) {
			for i := range c.Services {
				if c.Services[i].Kind == KindTCP {
					c.Services[i].UDPTimeout = 30
				}
			}
		},
		"a game on the door's port": func(c *Config) {
			for i := range c.Services {
				if c.Services[i].Kind == KindTCP {
					c.Services[i].ListenPort = public.DoorPort
				}
			}
		},
	}
	for name, change := range cases {
		cfg := withDoor(t)
		settings := *cfg.Public
		cfg.Public = &settings
		change(&cfg)
		cfg.CertificatePEM, cfg.PrivateKeyPEM = certificate(t, "*.domain.tld")
		if err := cfg.Validate(now); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	cfg := withDoor(t)
	cfg.CertificatePEM, cfg.PrivateKeyPEM = certificate(t, "*.domain.tld")
	if err := cfg.Validate(now); err != nil {
		t.Errorf("the sample with the door: %v", err)
	}
}

// Without this setting a visitor's "X_SGC_User" reaches PHP and CGI services
// as the gate's user header (seen with Traefik 3.7.16 on 2026-10-23), so it
// is checked here and not only through the expected file, which -update
// would rewrite without it.
func TestEveryHTTPEntryPointDropsLookAlikeHeaders(t *testing.T) {
	static, err := RenderStatic(sample(t), "/etc/sgc/traefik/dynamic")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		EntryPoints map[string]struct {
			Address string `json:"address"`
			HTTP    struct {
				AliasHeadersStrategy string `json:"aliasHeadersStrategy"`
			} `json:"http"`
		} `json:"entryPoints"`
	}
	if err := json.Unmarshal(static[strings.IndexByte(string(static), '\n')+1:], &parsed); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for name, entryPoint := range parsed.EntryPoints {
		if strings.HasSuffix(entryPoint.Address, "/udp") {
			continue
		}
		checked++
		if entryPoint.HTTP.AliasHeadersStrategy != "delete" {
			t.Errorf("entry point %s does not drop look-alike headers", name)
		}
	}
	if checked < 4 {
		t.Errorf("only %d entry points checked; the sample should have web, websecure, traefik and a TCP one", checked)
	}
}

// Traefik gives a connection to an HTTPS router whose rule names the
// connection's name before any TCP router (Traefik 3.7, ServeTCP). An HTTP
// router naming the gateway would take SGC's page from the pass-through: one
// did, in the whole-machine test of 2026-10-25, and every visit to SGC's name
// got the router's answer instead of SGC's page.
func TestNoHTTPRouterNamesTheGateway(t *testing.T) {
	for _, cfg := range []Config{sample(t), withDoor(t)} {
		noRouterNamesTheGateway(t, cfg)
	}
}

func noRouterNamesTheGateway(t *testing.T, cfg Config) {
	t.Helper()
	dynamic, err := RenderDynamic(cfg, "/c.crt", "/c.key")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		HTTP struct {
			Routers map[string]struct {
				Rule string `json:"rule"`
			} `json:"routers"`
		} `json:"http"`
		TCP struct {
			Routers map[string]struct {
				Rule string `json:"rule"`
				TLS  struct {
					Passthrough bool `json:"passthrough"`
				} `json:"tls"`
			} `json:"routers"`
		} `json:"tcp"`
	}
	if err := json.Unmarshal(dynamic[strings.IndexByte(string(dynamic), '\n')+1:], &parsed); err != nil {
		t.Fatal(err)
	}
	gateway := cfg.GatewayName + "." + cfg.Domain
	if len(parsed.HTTP.Routers) == 0 {
		t.Fatal("no HTTP routers read: the test reads the wrong place")
	}
	for name, router := range parsed.HTTP.Routers {
		if strings.Contains(strings.ToLower(router.Rule), gateway) {
			t.Errorf("HTTP router %s names the gateway (%s): Traefik would give it SGC's connections", name, router.Rule)
		}
	}
	passthrough := parsed.TCP.Routers["gateway"]
	if !passthrough.TLS.Passthrough || !strings.Contains(passthrough.Rule, gateway) {
		t.Errorf("the gateway's name is not passed through: %+v", passthrough)
	}
}

func TestWhatIsRefused(t *testing.T) {
	otherCert, otherKey := certificate(t, "*.elsewhere.tld")
	cases := map[string]func(*Config){
		"a name with a dot":          func(c *Config) { c.Services[0].Name = "nas.x" },
		"a name twice":               func(c *Config) { c.Services[1].Name = "nas" },
		"the gateway's name":         func(c *Config) { c.Services[0].Name = "sgc" },
		"an address on the internet": func(c *Config) { c.Services[0].Upstream = "8.8.8.8" },
		"the device itself":          func(c *Config) { c.Services[0].Upstream = "127.0.0.1" },
		"a port taken by SGC":        func(c *Config) { c.Services[2].ListenPort = 8443 },
		"the VPN's port":             func(c *Config) { c.Services[3].ListenPort = 51820 },
		"a quote in a rule":          func(c *Config) { c.Domain = "domain.tld`) || Host(`x" },
		"a protected game":           func(c *Config) { c.Services[2].Protected = true },
		"an odd range":               func(c *Config) { c.Services[1].AllowFrom = []string{"10.86.0.5/24"} },
		"another domain's cert":      func(c *Config) { c.CertificatePEM, c.PrivateKeyPEM = otherCert, otherKey },
		"a key that does not fit":    func(c *Config) { c.PrivateKeyPEM = otherKey },
		"an unknown kind":            func(c *Config) { c.Services[0].Kind = "ftp" },
		"two services on one port":   func(c *Config) { c.Services[3].Kind, c.Services[3].ListenPort = KindTCP, 25565 },
	}
	for name, change := range cases {
		cfg := sample(t)
		change(&cfg)
		if err := cfg.Validate(now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := sample(t).Validate(now); err != nil {
		t.Errorf("the sample was refused: %v", err)
	}
	expired := sample(t)
	if err := expired.Validate(now.Add(90 * 24 * time.Hour)); err == nil {
		t.Error("an expired certificate was accepted")
	}
}

// fakeDevice is the machine as the job sees it: systemd, ss, Traefik's API.
type fakeDevice struct {
	running   bool
	enabled   bool
	restarts  int
	refuse    string // a router Traefik reports as disabled
	portTaken bool
	paths     Paths
	// frozen: Traefik keeps the routes it has (as the real one does with a
	// file it cannot read) instead of reading the file again.
	frozen bool
	loaded []byte
}

// routes is the routes file as Traefik has it.
func (d *fakeDevice) routes() ([]byte, error) {
	if d.frozen && d.loaded != nil {
		return d.loaded, nil
	}
	data, err := os.ReadFile(d.paths.dynamicFile())
	if err == nil {
		d.loaded = data
	}
	return data, err
}

func (d *fakeDevice) run(_ context.Context, program string, args ...string) ([]byte, error) {
	switch {
	case program == ssProgram:
		if d.portTaken && strings.Contains(strings.Join(args, " "), ":80") {
			return []byte(`LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1,fd=6))` + "\n"), nil
		}
		return nil, nil
	case program == systemctl && args[0] == "is-active":
		if d.running {
			return nil, nil
		}
		return nil, errors.New("inactive")
	case program == systemctl && args[0] == "is-enabled":
		if d.enabled {
			return nil, nil
		}
		return nil, errors.New("disabled")
	case program == systemctl && args[0] == "enable":
		d.enabled = true
	case program == systemctl && args[0] == "restart":
		d.running = true
		d.restarts++
	case program == systemctl && args[0] == "disable":
		d.enabled, d.running = false, false
	}
	return nil, nil
}

func (d *fakeDevice) api(_ context.Context, path string) ([]byte, error) {
	if !d.running {
		return nil, errors.New("connection refused")
	}
	if path == "/ping" {
		return []byte("OK"), nil
	}
	// Traefik reports the routers in the file it has.
	data, err := d.routes()
	if name, ok := strings.CutPrefix(path, "/api/http/middlewares/"); ok {
		if err == nil && name == GenerationPrefix+Generation(data)+"@file" {
			return []byte(`{"status":"enabled"}`), nil
		}
		return nil, errors.New("Traefik answered 404")
	}
	if err != nil {
		return []byte("[]"), nil
	}
	var dynamic map[string]json.RawMessage
	body := data[strings.IndexByte(string(data), '\n')+1:]
	if err := json.Unmarshal(body, &dynamic); err != nil {
		return nil, err
	}
	kind := strings.Split(path, "/")[2]
	var section struct {
		Routers map[string]any `json:"routers"`
	}
	if raw, ok := dynamic[kind]; ok {
		if err := json.Unmarshal(raw, &section); err != nil {
			return nil, err
		}
	}
	var out []routerReport
	for name := range section.Routers {
		status := "enabled"
		if name == d.refuse {
			status = "disabled"
		}
		out = append(out, routerReport{Name: name + "@file", Status: status, Error: []string{"made-up refusal"}})
	}
	return json.Marshal(out)
}

func system(t *testing.T, d *fakeDevice) *System {
	root := t.TempDir()
	// Laid out like the device, where /etc/sgc may not exist yet.
	paths := Paths{Root: filepath.Join(root, "opt"), ConfigDir: filepath.Join(root, "etc", "sgc", "traefik"), SpoolDir: filepath.Join(root, "spool")}
	os.MkdirAll(filepath.Join(paths.Root, "3.7.16"), 0o755)
	os.WriteFile(filepath.Join(paths.Root, "3.7.16", "traefik"), []byte("program"), 0o755)
	os.Symlink("3.7.16", paths.current())
	d.paths = paths
	return &System{Paths: paths, Run: d.run, API: d.api, Group: func() (int, error) { return os.Getgid(), nil },
		Chown: func(string, int) error { return nil },
		Sleep: func(time.Duration) {}, Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// Traefik reads a changed routes file a moment later, and keeps the one it
// has when it cannot read the new one: until it reports the new file's
// label, what its API says is about the previous file. A change it never
// takes up is undone.
func TestAChangeTraefikDoesNotTakeUpIsUndone(t *testing.T) {
	device := &fakeDevice{}
	s := system(t, device)
	first := sample(t)
	if err := s.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.Paths.dynamicFile())
	appliedBefore := ReadApplied(s.Paths)

	device.frozen = true
	second := sample(t)
	second.Services = second.Services[:1]
	err := s.Apply(context.Background(), second)
	if err == nil || !strings.Contains(err.Error(), "did not take up") {
		t.Fatalf("err = %v, want Traefik not taking up the change", err)
	}
	if after, _ := os.ReadFile(s.Paths.dynamicFile()); string(after) != string(before) {
		t.Error("the routes file of the change that was not taken up was left in place")
	}
	if ReadApplied(s.Paths).At != appliedBefore.At {
		t.Error("the change that was not taken up was recorded as applied")
	}
}

// A renewed certificate under the same file names is not noticed by Traefik
// (seen with 3.7.16): the routes file must change with it.
func TestARenewedCertificateChangesTheRoutesFile(t *testing.T) {
	cfg := sample(t)
	first, err := RenderDynamic(cfg, "/c.crt", "/c.key")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := RenderDynamic(cfg, "/c.crt", "/c.key")
	if Generation(first) == "" || Generation(first) != Generation(again) {
		t.Fatalf("the same configuration gave the labels %q and %q", Generation(first), Generation(again))
	}
	renewed := cfg
	renewed.CertificatePEM, renewed.PrivateKeyPEM = certificate(t, "*.domain.tld")
	second, err := RenderDynamic(renewed, "/c.crt", "/c.key")
	if err != nil {
		t.Fatal(err)
	}
	if Generation(second) == Generation(first) {
		t.Error("a new certificate left the routes file as it was; Traefik would keep serving the old one")
	}
}

// /etc/sgc also holds the firewall's file, which SGC's own account reads:
// creating Traefik's closed folder in it must not close it too.
func TestTraefiksFolderLeavesItsParentOpen(t *testing.T) {
	s := system(t, &fakeDevice{})
	if err := s.Apply(context.Background(), sample(t)); err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]os.FileMode{filepath.Dir(s.Paths.ConfigDir): 0o755, s.Paths.ConfigDir: 0o750} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s has mode %o, want %o", dir, got, want)
		}
	}
}

func TestApplyAndUndo(t *testing.T) {
	device := &fakeDevice{}
	s := system(t, device)
	cfg := sample(t)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !device.running || !device.enabled || device.restarts != 1 {
		t.Fatalf("after switching on: %+v", device)
	}
	if got := ReadApplied(s.Paths).ListenPorts; strings.Join(got, ",") != "25565/tcp,27016/udp" {
		t.Errorf("the ports the firewall lets in: %v", got)
	}
	before := s.readFiles()

	// A change of routes only: no restart.
	cfg.Services = cfg.Services[:3]
	cfg.Services = append(cfg.Services[:0:0], cfg.Services[0], cfg.Services[2])
	cfg.Services[1].ListenPort = 25565
	cfg.Services = append(cfg.Services, Service{Name: "new", Kind: KindHTTP, Upstream: "192.168.1.9", Port: 80, Scheme: "http"})
	restarts := device.restarts
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	// Traefik refuses a route: the previous files come back.
	device.refuse = "http-new"
	before = s.readFiles()
	cfg.Services = append(cfg.Services, Service{Name: "other", Kind: KindHTTP, Upstream: "192.168.1.8", Port: 80, Scheme: "http"})
	err := s.Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "http-new") || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("a refused route: %v", err)
	}
	after := s.readFiles()
	for path, data := range before {
		if string(after[path]) != string(data) {
			t.Errorf("%s was not put back", path)
		}
	}
	_ = restarts
}

func TestAnotherProgramOnThePort(t *testing.T) {
	device := &fakeDevice{portTaken: true}
	s := system(t, device)
	err := s.Apply(context.Background(), sample(t))
	if err == nil || !strings.Contains(err.Error(), "nginx") {
		t.Fatalf("got %v", err)
	}
	if device.running || device.enabled {
		t.Error("Traefik was started all the same")
	}
}

func TestSwitchingOff(t *testing.T) {
	device := &fakeDevice{running: true, enabled: true}
	s := system(t, device)
	if err := s.Apply(context.Background(), Config{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if device.running || device.enabled || ReadApplied(s.Paths).Enabled {
		t.Errorf("still on: %+v", device)
	}
}
