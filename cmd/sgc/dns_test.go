package main

import (
	"slices"
	"testing"
)

// What `ss -H -lntup` printed on the test machine with DNS, the proxy and
// the VPN on (2026-10-23): SGC's own parts on the ports SGC needs.
const portsOfSGCsOwnParts = `udp UNCONN 0      0                 0.0.0.0:51820 0.0.0.0:*
udp UNCONN 0      0                       *:53          *:* users:(("AdGuardHome",pid=1908,fd=6))
udp UNCONN 0      0                    [::]:51820    [::]:*
tcp LISTEN 0      4096                    *:80          *:* users:(("traefik",pid=2087,fd=7))
tcp LISTEN 0      4096                    *:53          *:* users:(("AdGuardHome",pid=1908,fd=12))
tcp LISTEN 0      4096                    *:443         *:* users:(("traefik",pid=2087,fd=8))
tcp LISTEN 0      4096                    *:8446        *:* users:(("traefik",pid=2087,fd=9))
`

func TestSGCsOwnPartsAreNotOtherPrograms(t *testing.T) {
	if taken := takenPorts(portsOfSGCsOwnParts); len(taken) != 0 {
		t.Errorf("SGC's own parts reported as other programs: %v", taken)
	}
}

func TestOtherProgramsOnThePortsSGCNeeds(t *testing.T) {
	output := `tcp LISTEN 0      511               0.0.0.0:80    0.0.0.0:* users:(("nginx",pid=1,fd=6))
tcp LISTEN 0      5               127.0.0.1:53    0.0.0.0:* users:(("python3",pid=2,fd=3))
udp UNCONN 0      0                 0.0.0.0:51820 0.0.0.0:* users:(("wg-quick-ish",pid=3,fd=4))
tcp LISTEN 0      5               127.0.0.1:8080  0.0.0.0:* users:(("python3",pid=4,fd=3))
tcp LISTEN 0      5                 0.0.0.0:8446  0.0.0.0:* users:(("caddy",pid=5,fd=3))
`
	taken := takenPorts(output)
	for _, want := range []string{"80 (the proxy) by nginx", "53 (DNS (AdGuard Home)) by python3", "51820 (the VPN) by wg-quick-ish",
		"8446 (the proxy's door for the internet) by caddy"} {
		if !slices.Contains(taken, want) {
			t.Errorf("not pointed out: %s (got %v)", want, taken)
		}
	}
	if len(taken) != 4 {
		t.Errorf("taken = %v, want exactly the four", taken)
	}
}
