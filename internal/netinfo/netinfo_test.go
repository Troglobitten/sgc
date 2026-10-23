package netinfo

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// As /proc/net/route reads on a device with a cable (metric 100) and Wi-Fi
// (metric 600) both connected to a router at 192.168.1.1.
const twoRoutes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
	"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
	"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

func reader(t *testing.T, table string, addrs map[string][]string) Reader {
	t.Helper()
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	return Reader{RouteFile: path, Addrs: func(iface string) ([]net.Addr, error) {
		var out []net.Addr
		for _, cidr := range addrs[iface] {
			ip, network, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			network.IP = ip
			out = append(out, network)
		}
		return out, nil
	}}
}

func TestTheInterfaceTowardsTheRouterWins(t *testing.T) {
	lan, err := reader(t, twoRoutes, map[string][]string{
		"eth0":  {"fe80::1/64", "169.254.3.4/16", "10.0.0.5/8", "192.168.1.50/24"},
		"wlan0": {"192.168.1.51/24"},
	}).Find()
	if err != nil {
		t.Fatal(err)
	}
	if lan.Interface != "eth0" || lan.Address.String() != "192.168.1.50" || lan.Network.String() != "192.168.1.0/24" || lan.Gateway.String() != "192.168.1.1" {
		t.Errorf("found %+v", lan)
	}
}

func TestWithoutADefaultRoute(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	if _, err := reader(t, table, nil).Find(); !errors.Is(err, ErrNoRoute) {
		t.Errorf("got %v", err)
	}
}

func TestAnInterfaceWithoutIPv4(t *testing.T) {
	if _, err := reader(t, twoRoutes, map[string][]string{"eth0": {"fe80::1/64"}}).Find(); err == nil {
		t.Error("an interface with only IPv6 gave an address")
	}
}
