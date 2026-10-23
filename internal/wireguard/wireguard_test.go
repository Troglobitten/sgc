package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the expected files in testdata")

func key(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func sample() Config {
	return Config{
		Enabled: true, Port: 51820, Network: "10.86.0.0/24", PrivateKey: key(1),
		Peers: []Peer{
			{PublicKey: key(2), PresharedKey: key(3), Address: "10.86.0.2", Access: AccessFull},
			{PublicKey: key(4), PresharedKey: key(5), Address: "10.86.0.3", Access: AccessServices,
				Direct:       []Endpoint{{IP: "192.168.1.40", Port: 9987, Protocol: "udp"}},
				GatewayPorts: []string{"25565/tcp"}},
			{PublicKey: key(6), PresharedKey: key(7), Address: "10.86.0.4", Access: AccessServices},
		},
	}
}

func TestRender(t *testing.T) {
	for name, got := range map[string]string{
		"wg.conf":   RenderWireGuard(sample()),
		"rules.nft": RenderRules(sample()),
		"off.nft":   RenderRules(Config{}),
	} {
		golden := filepath.Join("testdata", name)
		if *update {
			os.MkdirAll("testdata", 0o755)
			os.WriteFile(golden, []byte(got), 0o644)
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s differs:\n%s", name, got)
		}
	}
}

func TestWhatIsRefused(t *testing.T) {
	cases := map[string]func(*Config){
		"a public range":              func(c *Config) { c.Network = "8.8.8.0/24" },
		"a range too large":           func(c *Config) { c.Network = "10.0.0.0/8" },
		"not a key":                   func(c *Config) { c.PrivateKey = "not-a-key" },
		"a key twice":                 func(c *Config) { c.Peers[1].PublicKey = c.Peers[0].PublicKey },
		"the gateway's address":       func(c *Config) { c.Peers[0].Address = "10.86.0.1" },
		"outside the range":           func(c *Config) { c.Peers[0].Address = "10.87.0.2" },
		"an address twice":            func(c *Config) { c.Peers[1].Address = "10.86.0.2" },
		"a direct service outside":    func(c *Config) { c.Peers[1].Direct[0].IP = "1.1.1.1" },
		"a direct service in the VPN": func(c *Config) { c.Peers[1].Direct[0].IP = "10.86.0.9" },
		"an odd protocol":             func(c *Config) { c.Peers[1].Direct[0].Protocol = "icmp" },
		"a gateway port without kind": func(c *Config) { c.Peers[1].GatewayPorts = []string{"25565"} },
		"a list for a full device":    func(c *Config) { c.Peers[0].GatewayPorts = []string{"80/tcp"} },
		"an unknown access":           func(c *Config) { c.Peers[0].Access = "some" },
		"port 0":                      func(c *Config) { c.Port = 0 },
	}
	for name, change := range cases {
		c := sample()
		change(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := sample().Validate(); err != nil {
		t.Error(err)
	}
}

func TestPublicKey(t *testing.T) {
	// RFC 7748 §6.1: Alice's private key and public key.
	private, _ := base64.StdEncoding.DecodeString("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=")
	got, err := PublicKey(base64.StdEncoding.EncodeToString(private))
	if err != nil || got != "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" {
		t.Errorf("got %s, %v", got, err)
	}
}

// machine is the device as the VPN's program sees it.
type machine struct {
	link    bool
	loaded  string // the last rules loaded
	refuse  string // a command that fails
	forward bool
	wgDump  string
}

func (m *machine) run(_ context.Context, program string, args ...string) ([]byte, error) {
	line := filepath.Base(program) + " " + strings.Join(args, " ")
	if m.refuse != "" && strings.HasPrefix(line, m.refuse) {
		return []byte("refused on purpose"), errors.New("exit status 1")
	}
	switch {
	case line == "ip link show dev sgc-wg":
		if !m.link {
			return []byte("does not exist"), errors.New("exit status 1")
		}
	case strings.HasPrefix(line, "ip link add"):
		m.link = true
	case strings.HasPrefix(line, "ip link delete"):
		m.link = false
	case strings.HasPrefix(line, "nft -f "):
		data, _ := os.ReadFile(args[1])
		m.loaded = string(data)
	case strings.HasPrefix(line, "wg show"):
		if !m.link {
			return []byte("no such device"), errors.New("exit status 1")
		}
		return []byte(m.wgDump), nil
	}
	return nil, nil
}

func newSystem(t *testing.T, m *machine) *System {
	dir := t.TempDir()
	return &System{
		Paths: Paths{StateDir: filepath.Join(dir, "state"), RunDir: filepath.Join(dir, "run"), RequestFile: filepath.Join(dir, "request.json")},
		Run:   m.run,
		Forward: func(set *bool) (bool, error) {
			if set != nil {
				m.forward = *set
			}
			return m.forward, nil
		},
		Now: func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestChangesAndGoingBack(t *testing.T) {
	m := &machine{}
	s := newSystem(t, m)
	ctx := context.Background()
	if msg, ok := s.change(ctx, sample()); !ok {
		t.Fatal(msg)
	}
	if !m.link || !m.forward || !strings.Contains(m.loaded, "table inet sgc_vpn") || !ReadState(s.Paths).Enabled {
		t.Fatalf("after switching on: %+v", m)
	}
	if _, err := os.Stat(s.Paths.onFile()); err != nil {
		t.Error("not marked as on for the next start")
	}
	// A change WireGuard refuses: the previous state stays, also on disk.
	next := sample()
	next.Peers = next.Peers[:1]
	m.refuse = "wg syncconf"
	if msg, ok := s.change(ctx, next); ok || !strings.Contains(msg, "previous state was kept") {
		t.Fatalf("a refused change: %s", msg)
	}
	if len(ReadState(s.Paths).Peers) != 3 {
		t.Error("the refused change was kept as the state")
	}
	m.refuse = ""
	// Off: the interface, the rules, and the passing on of packets go.
	if msg, ok := s.change(ctx, Config{Enabled: false}); !ok {
		t.Fatal(msg)
	}
	if m.link || m.forward || strings.Contains(m.loaded, "table inet sgc_vpn {") {
		t.Errorf("after switching off: %+v", m)
	}
	if _, err := os.Stat(s.Paths.onFile()); err == nil {
		t.Error("still marked as on")
	}
}

func TestStats(t *testing.T) {
	m := &machine{link: true, wgDump: "cHJpdmF0ZQ==\t" + key(9) + "\t51820\toff\n" +
		key(2) + "\t" + key(3) + "\t203.0.113.7:41000\t10.86.0.2/32\t1792500000\t1024\t2048\t25\n" +
		key(4) + "\t" + key(5) + "\t(none)\t10.86.0.3/32\t0\t0\t0\t25\n"}
	stats := newSystem(t, m).ReadStats(context.Background())
	if !stats.Up || stats.Port != 51820 || len(stats.Peers) != 2 {
		t.Fatalf("got %+v", stats)
	}
	if p := stats.Peers[0]; p.Endpoint != "203.0.113.7:41000" || p.LatestHandshake != 1792500000 || p.RX != 1024 || p.TX != 2048 {
		t.Errorf("first: %+v", p)
	}
	if stats.Peers[1].Endpoint != "" {
		t.Errorf("a device that never connected: %+v", stats.Peers[1])
	}
}
