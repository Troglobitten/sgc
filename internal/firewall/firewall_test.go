package firewall

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// go test ./internal/firewall -update rewrites the expected rulesets. Read
// the difference before committing it: it is a change to the firewall.
var update = flag.Bool("update", false, "rewrite the expected rulesets in testdata")

func TestRender(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"on", Config{Enabled: true, SSHPorts: []int{22}, WebPort: 8443}},
		// Ports are sorted and listed once, whatever order they arrive in.
		{"on-moved-ssh", Config{Enabled: true, SSHPorts: []int{2222, 22, 2222}, WebPort: 8443}},
		{"on-no-ssh", Config{Enabled: true, WebPort: 8443}},
		{"on-dns", Config{Enabled: true, SSHPorts: []int{22}, WebPort: 8443, DNS: true}},
		{"on-proxy", Config{Enabled: true, SSHPorts: []int{22}, WebPort: 8443, DNS: true, Proxy: true,
			ProxyPorts: []string{"27015/udp", "25565/tcp", "7777/tcp", "25565/tcp"}}},
		{"on-vpn", Config{Enabled: true, SSHPorts: []int{22}, WebPort: 8443, DNS: true, Proxy: true, VPNPort: 51820}},
		{"off", Config{Enabled: false, SSHPorts: []int{22}, WebPort: 8443}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Render(c.cfg)
			if err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", c.name+".nft")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("ruleset differs from %s:\n%s", golden, got)
			}

			described, err := ParseConfig([]byte(got))
			if err != nil {
				t.Fatalf("the ruleset does not say what it was made from: %v", err)
			}
			if !described.Equal(c.cfg) {
				t.Errorf("described as %+v, made from %+v", described, c.cfg)
			}
		})
	}
}

// Whatever was loaded before, loading a ruleset must leave exactly what it
// describes. That only holds if it starts by removing SGC's table.
func TestRenderAlwaysStartsFromNothing(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		rules, err := Render(Config{Enabled: enabled, SSHPorts: []int{22}, WebPort: 8443})
		if err != nil {
			t.Fatal(err)
		}
		var first string
		for line := range strings.Lines(rules) {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				first = line
				break
			}
		}
		if first != "destroy table inet sgc" {
			t.Errorf("enabled=%v: first statement is %q", enabled, first)
		}
		if strings.Contains(rules, "table inet sgc {") != enabled {
			t.Errorf("enabled=%v: table definition present = %v", enabled, !enabled)
		}
	}
}

func TestRenderRefusesBadPorts(t *testing.T) {
	bad := []Config{
		{Enabled: true, SSHPorts: []int{22}, WebPort: 0},
		{Enabled: true, SSHPorts: []int{22}, WebPort: 70000},
		{Enabled: true, SSHPorts: []int{0}, WebPort: 8443},
		{Enabled: true, SSHPorts: []int{-1}, WebPort: 8443},
		{Enabled: true, SSHPorts: []int{65536}, WebPort: 8443},
		{Enabled: true, SSHPorts: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, WebPort: 8443},
	}
	for _, cfg := range bad {
		if rules, err := Render(cfg); err == nil {
			t.Errorf("%+v was accepted:\n%s", cfg, rules)
		}
	}
}

func TestParseConfigRefusesOtherFiles(t *testing.T) {
	for _, text := range []string{
		"",
		"flush ruleset\n",
		"# sgc-config: not json\n",
		`# sgc-config: {"enabled":true,"surprise":1}` + "\n",
	} {
		if cfg, err := ParseConfig([]byte(text)); err == nil {
			t.Errorf("%q was read as %+v", text, cfg)
		}
	}
}

func TestIsInside(t *testing.T) {
	cases := map[string]bool{
		// Home networks.
		"192.168.1.20": true,
		"192.168.0.1":  true,
		"10.0.0.5":     true,
		"10.255.1.1":   true,
		"172.16.0.9":   true,
		"172.31.255.1": true,
		"169.254.10.1": true,
		// The machine itself.
		"127.0.0.1": true,
		"::1":       true,
		// IPv6 inside a home, and the same IPv4 address in IPv6 clothing.
		"fe80::1":             true,
		"fe80::1%eth0":        true,
		"fd12:3456:789a::1":   true,
		"::ffff:192.168.1.20": true,

		// The internet.
		"8.8.8.8":        false,
		"203.0.113.7":    false,
		"172.15.255.1":   false, // just below the private range
		"172.32.0.1":     false, // just above it
		"192.169.0.1":    false,
		"11.0.0.1":       false,
		"100.64.0.1":     false, // the provider's shared range (carrier-grade NAT), not the home
		"2001:db8::1":    false,
		"2a00:1450::1":   false, // a public IPv6 address, even of a device at home
		"::ffff:8.8.8.8": false,
	}
	for text, want := range cases {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if got := IsInside(addr); got != want {
			t.Errorf("IsInside(%s) = %v, want %v", text, got, want)
		}
	}
}
