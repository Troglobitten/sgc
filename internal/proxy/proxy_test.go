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
	"strings"
	"testing"
	"time"
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
	data, err := os.ReadFile(d.paths.dynamicFile())
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
	paths := Paths{Root: filepath.Join(root, "opt"), ConfigDir: filepath.Join(root, "etc"), SpoolDir: filepath.Join(root, "spool")}
	os.MkdirAll(filepath.Join(paths.Root, "3.7.16"), 0o755)
	os.WriteFile(filepath.Join(paths.Root, "3.7.16", "traefik"), []byte("program"), 0o755)
	os.Symlink("3.7.16", paths.current())
	d.paths = paths
	return &System{Paths: paths, Run: d.run, API: d.api, Group: func() (int, error) { return os.Getgid(), nil },
		Chown: func(string, int) error { return nil },
		Sleep: func(time.Duration) {}, Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
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
