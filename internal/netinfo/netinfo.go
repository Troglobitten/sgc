// Package netinfo finds this device's place in the home network: the IPv4
// address the other devices reach it at, and the network that address is in.
//
// That is the address of the interface the default route goes through: the
// way to the router is the way to the home network. It is read afresh each
// time, because a router can hand out another address after a restart (the
// doctor advises a reservation for that reason).
//
// Standard library only; nothing here needs privileges.
package netinfo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ErrNoRoute means the device has no default route: it is not connected, or
// not yet.
var ErrNoRoute = errors.New("this device has no route to the router (is it connected to the network?)")

// LAN is where this device is in the home network.
type LAN struct {
	Interface string       `json:"interface"`
	Address   netip.Addr   `json:"address"`
	Network   netip.Prefix `json:"network"`
	Gateway   netip.Addr   `json:"gateway"`
}

// Reader reads the routing table and an interface's addresses. Its fields
// are for tests; the zero value reads the real machine.
type Reader struct {
	// RouteFile is the kernel's IPv4 routing table ("" means /proc/net/route).
	RouteFile string
	// Addrs returns an interface's addresses (nil means the real ones).
	Addrs func(iface string) ([]net.Addr, error)
}

// Find returns this device's place in the home network.
func (r Reader) Find() (LAN, error) {
	path := r.RouteFile
	if path == "" {
		path = "/proc/net/route"
	}
	table, err := os.ReadFile(path)
	if err != nil {
		return LAN{}, fmt.Errorf("read the routing table: %w", err)
	}
	iface, gateway, err := defaultRoute(table)
	if err != nil {
		return LAN{}, err
	}
	addrs := r.Addrs
	if addrs == nil {
		addrs = interfaceAddrs
	}
	list, err := addrs(iface)
	if err != nil {
		return LAN{}, fmt.Errorf("read the addresses of %s: %w", iface, err)
	}
	for _, a := range list {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.Is4() || addr.IsLinkLocalUnicast() || addr.IsLoopback() {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		network := netip.PrefixFrom(addr, ones).Masked()
		// The address that shares a network with the router, if there are several.
		if gateway.IsValid() && !network.Contains(gateway) {
			continue
		}
		return LAN{Interface: iface, Address: addr, Network: network, Gateway: gateway}, nil
	}
	return LAN{}, fmt.Errorf("the interface %s, which leads to the router, has no IPv4 address", iface)
}

func interfaceAddrs(name string) ([]net.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface.Addrs()
}

// defaultRoute picks the default route with the lowest metric from the
// kernel's table (/proc/net/route: hexadecimal, in the machine's byte order,
// which is little-endian on every processor SGC runs on).
func defaultRoute(table []byte) (iface string, gateway netip.Addr, err error) {
	bestMetric := -1
	scanner := bufio.NewScanner(bytes.NewReader(table))
	first := true
	for scanner.Scan() {
		if first { // the header
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		destination, mask, flags := fields[1], fields[7], fields[3]
		if destination != "00000000" || mask != "00000000" {
			continue
		}
		flagBits, err := strconv.ParseUint(flags, 16, 32)
		const routeUp = 0x1
		if err != nil || flagBits&routeUp == 0 {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			continue
		}
		if bestMetric >= 0 && metric >= bestMetric {
			continue
		}
		bestMetric = metric
		iface = fields[0]
		gateway = littleEndianIPv4(fields[2])
	}
	if bestMetric < 0 {
		return "", netip.Addr{}, ErrNoRoute
	}
	return iface, gateway, nil
}

func littleEndianIPv4(hex string) netip.Addr {
	value, err := strconv.ParseUint(hex, 16, 32)
	if err != nil || value == 0 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte{byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)})
}
