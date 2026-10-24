// Package vpncontrol is the web process's side of the VPN: its settings,
// people's devices and their keys, what each device may reach, the public
// name phones connect to, and what the devices used. The VPN itself is put
// in place by the root side (internal/wireguard), which checks everything
// again.
//
// Web process only.
package vpncontrol

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsnames"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/wireguard"
)

// Settings (exported unless said otherwise).
const (
	SettingEnabled      = "vpn.enabled"
	SettingPort         = "vpn.port"
	SettingNetwork      = "vpn.network"
	SettingName         = "vpn.name"
	SettingEndpointMode = "vpn.endpoint_mode"
	SettingStaticIP     = "vpn.static_ip"
	SettingServerKey    = "vpn.server_key"
	// SettingRecord is the A record SGC made for the public name.
	SettingRecord = "vpn.record"
	// Not exported: how the last change and the last look at the public
	// address went.
	SettingLastApply = "vpn.last_apply"
	SettingEndpoint  = "vpn.endpoint_state"

	DefaultPort    = 51820
	DefaultNetwork = "10.86.0.0/24"
	DefaultName    = "vpn"

	ModeDynamic = "dynamic"
	ModeStatic  = "static"

	// A device counts as connected while its last handshake is this recent
	// (WireGuard shakes hands every two minutes while traffic flows; phones
	// keep it alive every 25 seconds).
	activeWithin = 3 * time.Minute
	maxDevices   = 250
)

// Helper is what the root side does for the VPN.
type Helper interface {
	VPNStatus(ctx context.Context) (helper.VPNStatus, error)
	VPNApply(ctx context.Context, cfg wireguard.Config) error
	InstallPackages(ctx context.Context, feature string) error
}

type Config struct {
	DB       *sql.DB
	Helper   Helper
	Audit    *audit.Log
	People   *people.Service
	Services *services.Catalog
	// Domain returns the owner's domain, if one is set up.
	Domain func(ctx context.Context) (string, bool, error)
	LAN    func() (netinfo.LAN, error)
	// VerifyAdmin checks the admin's password again (for showing a key).
	VerifyAdmin func(ctx context.Context, password, remote string) error
	// Endpoint keeps the public name at Zone.eu (endpoint.go); nil in tests.
	Endpoint *Endpoint
	// Changed is called after the VPN changed (names, the proxy's allow
	// lists, the firewall's port).
	Changed func()
	Now     func() time.Time
	Log     *slog.Logger
}

type Service struct {
	cfg  Config
	kick chan struct{}

	mu        sync.Mutex
	applied   [32]byte
	applying  bool
	lastUsage time.Time
	// changes keeps Apply one at a time, from building the configuration to
	// the answer, so that what is sent last is what the database says last.
	changes sync.Mutex
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Changed == nil {
		cfg.Changed = func() {}
	}
	return &Service{cfg: cfg, kick: make(chan struct{}, 1)}
}

func (s *Service) setting(ctx context.Context, key, fallback string) string {
	value, found, err := store.Setting(ctx, s.cfg.DB, key)
	if err != nil || !found || value == "" {
		return fallback
	}
	return value
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

// Settings are the VPN's settings as the page shows and sets them.
type Settings struct {
	Enabled      bool   `json:"enabled"`
	Port         int    `json:"port"`
	Network      string `json:"network"`
	Name         string `json:"name"`
	EndpointMode string `json:"endpointMode"`
	StaticIP     string `json:"staticIp"`
}

func (s *Service) Settings(ctx context.Context) Settings {
	port, _ := strconv.Atoi(s.setting(ctx, SettingPort, strconv.Itoa(DefaultPort)))
	return Settings{
		Enabled:      s.setting(ctx, SettingEnabled, "false") == "true",
		Port:         port,
		Network:      s.setting(ctx, SettingNetwork, DefaultNetwork),
		Name:         s.setting(ctx, SettingName, DefaultName),
		EndpointMode: s.setting(ctx, SettingEndpointMode, ModeDynamic),
		StaticIP:     s.setting(ctx, SettingStaticIP, ""),
	}
}

// On reports whether the owner has the VPN on.
func (s *Service) On(ctx context.Context) bool { return s.Settings(ctx).Enabled }

// Label is the VPN's public name's label, for the other parts' checks.
func (s *Service) Label(ctx context.Context) string { return s.Settings(ctx).Name }

func (s *Service) deviceCount(ctx context.Context) int {
	var n int
	s.cfg.DB.QueryRowContext(ctx, "SELECT count(*) FROM vpn_device").Scan(&n)
	return n
}

// SetSettings changes the settings. The tunnel's range cannot change while
// there are devices: each has an address in it, written into its QR code.
func (s *Service) SetSettings(ctx context.Context, actor, remote string, in Settings, taken func(context.Context, string) (string, error)) error {
	before := s.Settings(ctx)
	if in.Port < 1024 || in.Port > 65535 {
		return problem.New("The VPN's port is a number from 1024 to 65535 (51820 is WireGuard's usual one).")
	}
	network, err := netip.ParsePrefix(in.Network)
	if err != nil || !network.Addr().Is4() || network.Masked() != network || network.Bits() < 16 || network.Bits() > 28 || !network.Addr().IsPrivate() {
		return problem.New("The tunnel's range is a private IPv4 range like 10.86.0.0/24, from /16 to /28.")
	}
	if in.Network != before.Network && s.deviceCount(ctx) > 0 {
		return problem.New("The tunnel's range cannot change while there are devices: their QR codes have an address in it.")
	}
	if lan, err := s.cfg.LAN(); err == nil && (network.Contains(lan.Address) || lan.Network.Overlaps(network)) {
		return problem.Newf("The tunnel's range overlaps the home network (%s). Choose another one.", lan.Network)
	}
	if !gateway.ValidLabel(in.Name) {
		return problem.New("The VPN's name is one label: lower-case letters, digits and hyphens.")
	}
	if in.Name != before.Name {
		if holder, err := taken(ctx, in.Name); err != nil {
			return err
		} else if holder != "" {
			return problem.Newf("%q is already used by %s.", in.Name, holder)
		}
	}
	switch in.EndpointMode {
	case ModeDynamic:
		in.StaticIP = ""
	case ModeStatic:
		addr, err := netip.ParseAddr(in.StaticIP)
		if err != nil || !addr.Is4() || addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() {
			return problem.New("A fixed public address is the IPv4 address your provider gave you, not one from the home network.")
		}
	default:
		return problem.New("The public address is found by SGC (dynamic) or given (fixed).")
	}
	if in.Enabled {
		if err := s.cfg.Helper.InstallPackages(ctx, helper.PackagesVPN); err != nil {
			return problem.Newf("WireGuard's tools could not be installed from Debian: %v", err)
		}
		if _, err := s.serverKey(ctx); err != nil {
			return err
		}
	}
	values := map[string]string{
		SettingEnabled: strconv.FormatBool(in.Enabled), SettingPort: strconv.Itoa(in.Port), SettingNetwork: in.Network,
		SettingName: in.Name, SettingEndpointMode: in.EndpointMode, SettingStaticIP: in.StaticIP,
	}
	for key, value := range values {
		if err := store.SetSetting(ctx, s.cfg.DB, key, value); err != nil {
			return err
		}
	}
	switch {
	case in.Enabled && !before.Enabled:
		s.record(ctx, actor, audit.ActionVPNSwitchedOn, fmt.Sprintf("port %d, %s", in.Port, in.Network), remote)
	case !in.Enabled && before.Enabled:
		s.record(ctx, actor, audit.ActionVPNSwitchedOff, "", remote)
	default:
		s.record(ctx, actor, audit.ActionVPNSettingsChanged, fmt.Sprintf("port %d, name %s, %s address", in.Port, in.Name, in.EndpointMode), remote)
	}
	if err := s.Apply(ctx); err != nil {
		return err
	}
	if s.cfg.Endpoint != nil {
		s.cfg.Endpoint.Kick()
	}
	return nil
}

// --- Keys -----------------------------------------------------------------------

// newKey makes a WireGuard private key the way `wg genkey` does: 32 random
// bytes, clamped as Curve25519 wants them.
func newKey() (private, public string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func newPresharedKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// serverKey returns the gateway's private key, making it the first time.
func (s *Service) serverKey(ctx context.Context) (string, error) {
	if key := s.setting(ctx, SettingServerKey, ""); key != "" {
		return key, nil
	}
	private, _, err := newKey()
	if err != nil {
		return "", err
	}
	return private, store.SetSetting(ctx, s.cfg.DB, SettingServerKey, private)
}

func (s *Service) serverPublicKey(ctx context.Context) (string, error) {
	private, err := s.serverKey(ctx)
	if err != nil {
		return "", err
	}
	return wireguard.PublicKey(private)
}

// --- Devices ---------------------------------------------------------------------

// Device is one device as the page shows it: never its private key.
type Device struct {
	ID         int64      `json:"id"`
	PersonID   int64      `json:"personId"`
	PersonName string     `json:"personName"`
	Name       string     `json:"name"`
	Address    string     `json:"address"`
	PublicKey  string     `json:"publicKey"`
	AllTraffic bool       `json:"allTraffic"`
	Enabled    bool       `json:"enabled"`
	CreatedAt  time.Time  `json:"createdAt"`
	Connected  bool       `json:"connected"`
	LastSeen   *time.Time `json:"lastSeen"`
	Endpoint   string     `json:"endpoint"`
	RX         int64      `json:"rx"`
	TX         int64      `json:"tx"`
}

type deviceRow struct {
	Device
	privateKey, presharedKey string
}

func (s *Service) devices(ctx context.Context) ([]deviceRow, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, `SELECT d.id, d.person_id, p.name, d.name, d.address, d.public_key, d.private_key,
		d.preshared_key, d.all_traffic, d.enabled, d.created_at, COALESCE(st.last_handshake, 0), COALESCE(st.endpoint, '')
		FROM vpn_device d JOIN person p ON p.id = d.person_id LEFT JOIN vpn_peer_state st ON st.device_id = d.id
		ORDER BY p.name COLLATE NOCASE, d.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deviceRow
	for rows.Next() {
		var d deviceRow
		var created, handshake int64
		if err := rows.Scan(&d.ID, &d.PersonID, &d.PersonName, &d.Name, &d.Address, &d.PublicKey, &d.privateKey,
			&d.presharedKey, &d.AllTraffic, &d.Enabled, &created, &handshake, &d.Endpoint); err != nil {
			return nil, err
		}
		d.CreatedAt = time.Unix(created, 0).UTC()
		if handshake > 0 {
			at := time.Unix(handshake, 0).UTC()
			d.LastSeen = &at
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Devices lists the devices with what WireGuard says about them now.
func (s *Service) Devices(ctx context.Context) ([]Device, error) {
	rows, err := s.devices(ctx)
	if err != nil {
		return nil, err
	}
	live := map[string]wireguard.PeerStats{}
	if status, err := s.cfg.Helper.VPNStatus(ctx); err == nil {
		for _, p := range status.Stats.Peers {
			live[p.PublicKey] = p
		}
	}
	now := s.cfg.Now()
	out := make([]Device, 0, len(rows))
	for _, r := range rows {
		d := r.Device
		if p, ok := live[d.PublicKey]; ok {
			d.RX, d.TX = p.RX, p.TX
			if p.Endpoint != "" {
				d.Endpoint = p.Endpoint
			}
			if p.LatestHandshake > 0 {
				at := time.Unix(p.LatestHandshake, 0).UTC()
				d.LastSeen = &at
				d.Connected = now.Sub(at) < activeWithin
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func validDeviceName(name string) bool {
	return name != "" && len([]rune(name)) <= 40 && !strings.ContainsAny(name, "\n\r\t")
}

// nextAddress is the first free device address in the tunnel's range.
func (s *Service) nextAddress(ctx context.Context) (string, error) {
	network := netip.MustParsePrefix(s.Settings(ctx).Network)
	used := map[string]bool{}
	rows, err := s.cfg.DB.QueryContext(ctx, "SELECT address FROM vpn_device")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		rows.Scan(&a)
		used[a] = true
	}
	gw := wireguard.GatewayAddress(network)
	for addr := gw.Next(); network.Contains(addr); addr = addr.Next() {
		if !network.Contains(addr.Next()) {
			break // the last address is the range's broadcast
		}
		if !used[addr.String()] {
			return addr.String(), nil
		}
	}
	return "", problem.New("The tunnel's range is full. A larger range needs all devices made again.")
}

// AddDevice makes a device for a person, with its own keys.
func (s *Service) AddDevice(ctx context.Context, actor, remote string, personID int64, name string, allTraffic bool) (Device, error) {
	name = strings.TrimSpace(name)
	if !validDeviceName(name) {
		return Device{}, problem.New("Give the device a name of 1 to 40 characters (\"phone\", \"laptop\").")
	}
	person, err := s.cfg.People.Get(ctx, personID)
	if err != nil {
		return Device{}, err
	}
	if s.deviceCount(ctx) >= maxDevices {
		return Device{}, problem.Newf("SGC keeps at most %d devices.", maxDevices)
	}
	if _, err := s.serverKey(ctx); err != nil {
		return Device{}, err
	}
	address, err := s.nextAddress(ctx)
	if err != nil {
		return Device{}, err
	}
	private, public, err := newKey()
	if err != nil {
		return Device{}, err
	}
	psk, err := newPresharedKey()
	if err != nil {
		return Device{}, err
	}
	result, err := s.cfg.DB.ExecContext(ctx, `INSERT INTO vpn_device (person_id, name, address, private_key, public_key,
		preshared_key, all_traffic, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
		personID, name, address, private, public, psk, allTraffic, s.cfg.Now().Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Device{}, problem.New("This person already has a device with that name.")
		}
		return Device{}, err
	}
	id, _ := result.LastInsertId()
	s.record(ctx, actor, audit.ActionDeviceAdded, person.Name+": "+name+" ("+address+")", remote)
	s.Kick()
	return s.device(ctx, id)
}

func (s *Service) device(ctx context.Context, id int64) (Device, error) {
	all, err := s.Devices(ctx)
	if err != nil {
		return Device{}, err
	}
	for _, d := range all {
		if d.ID == id {
			return d, nil
		}
	}
	return Device{}, problem.New("That device does not exist (any more).")
}

// UpdateDevice renames a device, switches it on or off, or changes what
// it sends through home. (The last needs its QR code scanned again.)
func (s *Service) UpdateDevice(ctx context.Context, actor, remote string, id int64, name string, allTraffic, enabled bool) (Device, error) {
	before, err := s.device(ctx, id)
	if err != nil {
		return Device{}, err
	}
	name = strings.TrimSpace(name)
	if !validDeviceName(name) {
		return Device{}, problem.New("Give the device a name of 1 to 40 characters.")
	}
	if _, err := s.cfg.DB.ExecContext(ctx, "UPDATE vpn_device SET name = ?, all_traffic = ?, enabled = ? WHERE id = ?", name, allTraffic, enabled, id); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Device{}, problem.New("This person already has a device with that name.")
		}
		return Device{}, err
	}
	detail := before.PersonName + ": " + name
	if !enabled {
		detail += " (switched off)"
	}
	s.record(ctx, actor, audit.ActionDeviceChanged, detail, remote)
	s.Kick()
	return s.device(ctx, id)
}

// RemoveDevice takes a device away; its key stops working at once.
func (s *Service) RemoveDevice(ctx context.Context, actor, remote string, id int64) error {
	d, err := s.device(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.cfg.DB.ExecContext(ctx, "DELETE FROM vpn_device WHERE id = ?", id); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDeviceRemoved, d.PersonName+": "+d.Name, remote)
	s.Kick()
	return nil
}

// DeviceConfig is the settings file of a device (what its QR code holds).
// It has the device's private key: asked for with the admin's password,
// and recorded.
func (s *Service) DeviceConfig(ctx context.Context, actor, remote string, id int64, password string) (string, string, error) {
	if err := s.cfg.VerifyAdmin(ctx, password, remote); err != nil {
		return "", "", err
	}
	rows, err := s.devices(ctx)
	if err != nil {
		return "", "", err
	}
	idx := slices.IndexFunc(rows, func(r deviceRow) bool { return r.ID == id })
	if idx < 0 {
		return "", "", problem.New("That device does not exist (any more).")
	}
	d := rows[idx]
	text, err := s.configText(ctx, d)
	if err != nil {
		return "", "", err
	}
	s.record(ctx, actor, audit.ActionDeviceRevealed, d.PersonName+": "+d.Name, remote)
	file := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, d.PersonName+"-"+d.Name)
	return text, file + ".conf", nil
}

func (s *Service) configText(ctx context.Context, d deviceRow) (string, error) {
	settings := s.Settings(ctx)
	serverPublic, err := s.serverPublicKey(ctx)
	if err != nil {
		return "", err
	}
	network := netip.MustParsePrefix(settings.Network)
	host, err := s.endpointHost(ctx)
	if err != nil {
		return "", err
	}
	allowed := []string{"0.0.0.0/0", "::/0"}
	if !d.AllTraffic {
		allowed = []string{network.String()}
		if lan, err := s.cfg.LAN(); err == nil {
			// The gateway's own address as a single address as well: on a
			// network away from home that uses the same range, this one
			// still goes through the tunnel (docs/design.md §2.2 F).
			allowed = append(allowed, lan.Network.String(), lan.Address.String()+"/32")
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\n\n", d.privateKey, d.Address, wireguard.GatewayAddress(network))
	fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s:%d\nAllowedIPs = %s\nPersistentKeepalive = 25\n",
		serverPublic, d.presharedKey, host, settings.Port, strings.Join(allowed, ", "))
	return b.String(), nil
}

// endpointHost is what devices connect to: the public name if there is a
// domain, otherwise the fixed public address.
func (s *Service) endpointHost(ctx context.Context) (string, error) {
	settings := s.Settings(ctx)
	if domain, configured, err := s.cfg.Domain(ctx); err != nil {
		return "", err
	} else if configured {
		return settings.Name + "." + domain, nil
	}
	if settings.StaticIP != "" {
		return settings.StaticIP, nil
	}
	return "", problem.New("Devices need an address to connect to: set up your domain (System), or give a fixed public address.")
}

// --- What each device may reach ---------------------------------------------------

// Build gathers the configuration for the root side.
func (s *Service) Build(ctx context.Context) (wireguard.Config, error) {
	settings := s.Settings(ctx)
	if !settings.Enabled {
		return wireguard.Config{Enabled: false}, nil
	}
	key, err := s.serverKey(ctx)
	if err != nil {
		return wireguard.Config{}, err
	}
	cfg := wireguard.Config{Enabled: true, Port: settings.Port, Network: settings.Network, PrivateKey: key, Peers: []wireguard.Peer{}}
	rows, err := s.devices(ctx)
	if err != nil {
		return wireguard.Config{}, err
	}
	everyone, err := s.cfg.People.List(ctx)
	if err != nil {
		return wireguard.Config{}, err
	}
	personByID := map[int64]people.Person{}
	for _, p := range everyone {
		personByID[p.ID] = p
	}
	svcs, err := s.cfg.Services.List(ctx)
	if err != nil {
		return wireguard.Config{}, err
	}
	for _, d := range rows {
		person := personByID[d.PersonID]
		if !d.Enabled || !person.Active {
			continue
		}
		peer := wireguard.Peer{PublicKey: d.PublicKey, PresharedKey: d.presharedKey, Address: d.Address, Access: wireguard.AccessFull}
		if person.Network != people.NetworkFull {
			peer.Access = wireguard.AccessServices
			for _, svc := range svcs {
				if !svc.Enabled || svc.Pending || svc.Kind == "http" || !person.Reaches(svc.ID) {
					continue
				}
				if svc.Mode == services.ModeDirect {
					peer.Direct = append(peer.Direct, wireguard.Endpoint{IP: svc.UpstreamIP, Port: svc.UpstreamPort, Protocol: svc.Kind})
				} else {
					peer.GatewayPorts = append(peer.GatewayPorts, strconv.Itoa(svc.ListenPort)+"/"+svc.Kind)
				}
			}
		}
		cfg.Peers = append(cfg.Peers, peer)
	}
	return cfg, nil
}

// AllowFor is, for the proxy, who may reach a service: everyone in the
// home network, and of the VPN's devices those whose person has it. nil
// means everyone inside (no device is kept out).
func (s *Service) AllowFor(ctx context.Context) func(serviceID int64) []string {
	settings := s.Settings(ctx)
	if !settings.Enabled {
		return nil
	}
	rows, err := s.devices(ctx)
	if err != nil {
		return nil
	}
	everyone, err := s.cfg.People.List(ctx)
	if err != nil {
		return nil
	}
	personByID := map[int64]people.Person{}
	for _, p := range everyone {
		personByID[p.ID] = p
	}
	network := netip.MustParsePrefix(settings.Network)
	base := subtract(privateRanges, network)
	return func(serviceID int64) []string {
		allowed := []string{}
		keptOut := false
		for _, d := range rows {
			person, ok := personByID[d.PersonID]
			if !ok {
				continue
			}
			if d.Enabled && person.Reaches(serviceID) {
				allowed = append(allowed, d.Address+"/32")
			} else {
				keptOut = true
			}
		}
		if !keptOut {
			return nil
		}
		out := make([]string, 0, len(base)+len(allowed))
		for _, p := range base {
			out = append(out, p.String())
		}
		return append(out, allowed...)
	}
}

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
}

// subtract returns the ranges with hole cut out of them, as a list of
// ranges (an allow list cannot say "except").
func subtract(ranges []netip.Prefix, hole netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range ranges {
		out = append(out, cut(r, hole)...)
	}
	return out
}

func cut(r, hole netip.Prefix) []netip.Prefix {
	if !r.Overlaps(hole) {
		return []netip.Prefix{r}
	}
	if hole.Bits() <= r.Bits() {
		return nil // the hole covers all of it
	}
	// Split r in two halves and keep cutting the half with the hole.
	low := netip.PrefixFrom(r.Addr(), r.Bits()+1)
	high := netip.PrefixFrom(lastOf(low).Next(), r.Bits()+1)
	return append(cut(low, hole), cut(high, hole)...)
}

func lastOf(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= uint32(1)<<(32-p.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// --- Putting it in place --------------------------------------------------------

// ApplyResult is how the last change went.
type ApplyResult struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
}

// Kick asks for the configuration to be sent soon.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Apply sends the configuration now (unless it is what was last sent and
// the VPN is up).
func (s *Service) Apply(ctx context.Context) error {
	s.changes.Lock()
	defer s.changes.Unlock()
	cfg, err := s.Build(ctx)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(cfg)
	hash := sha256.Sum256(data)
	s.mu.Lock()
	if hash == s.applied {
		s.mu.Unlock()
		return nil
	}
	s.applying = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.applying = false
		s.mu.Unlock()
	}()
	if !cfg.Enabled {
		status, err := s.cfg.Helper.VPNStatus(ctx)
		if err != nil {
			// Off, and the root side cannot be asked right now: tried again
			// at the next round, without an entry in the owner's history for
			// what is most likely a moment at start-up.
			return problem.Newf("The VPN's state could not be read: %v", err)
		}
		// Nothing to take down on a device where the VPN never ran.
		if !status.On && !status.Running {
			s.mu.Lock()
			s.applied = hash
			s.mu.Unlock()
			return nil
		}
	} else if status, err := s.cfg.Helper.VPNStatus(ctx); err == nil && !status.Installed {
		// A device restored from an export of one with the VPN on: it
		// gets WireGuard's tools, as switching on would have.
		if err := s.cfg.Helper.InstallPackages(ctx, helper.PackagesVPN); err != nil {
			return problem.Newf("WireGuard's tools could not be installed from Debian: %v", err)
		}
	}
	err = s.cfg.Helper.VPNApply(context.WithoutCancel(ctx), cfg)
	result := ApplyResult{At: s.cfg.Now().UTC(), OK: err == nil}
	if err != nil {
		result.Message = err.Error()
		s.record(ctx, audit.ActorSystem, audit.ActionVPNApplyFailed, err.Error(), "")
	}
	if raw, jsonErr := json.Marshal(result); jsonErr == nil {
		store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingLastApply, string(raw))
	}
	if err != nil {
		return problem.Newf("The VPN could not be changed: %v", err)
	}
	s.mu.Lock()
	s.applied = hash
	s.mu.Unlock()
	s.cfg.Changed()
	return nil
}

// Run keeps the VPN in step, takes stock of what the devices used every
// minute, and keeps the public name current, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	if s.cfg.Endpoint != nil {
		go s.cfg.Endpoint.Run(ctx)
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	first := time.NewTimer(4 * time.Second)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-ticker.C:
			s.sampleUsage(ctx)
		case <-s.kick:
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		if err := s.Apply(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Log.Error("bring the VPN up to date", "error", err)
		}
	}
}

// --- The page ---------------------------------------------------------------------

// Status is the VPN as the page shows it.
type Status struct {
	Settings
	// Installed: WireGuard's tools are on the device.
	Installed bool `json:"installed"`
	Running   bool `json:"running"`
	// Up: the interface is there and WireGuard reports it.
	Up          bool           `json:"up"`
	Problem     string         `json:"problem"`
	ServerKey   string         `json:"serverKey"`
	Endpoint    string         `json:"endpoint"`
	LastApply   *ApplyResult   `json:"lastApply"`
	Applying    bool           `json:"applying"`
	PublicName  string         `json:"publicName"`
	PublicState *EndpointState `json:"publicState"`
	Devices     []Device       `json:"devices"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	status := Status{Settings: s.Settings(ctx)}
	if root, err := s.cfg.Helper.VPNStatus(ctx); err == nil {
		status.Installed, status.Running, status.Up, status.Problem = root.Installed, root.Running, root.Stats.Up, root.Stats.Problem
	}
	if status.Enabled {
		status.ServerKey, _ = s.serverPublicKey(ctx)
	}
	if host, err := s.endpointHost(ctx); err == nil {
		status.Endpoint = host + ":" + strconv.Itoa(status.Port)
	}
	if domain, configured, err := s.cfg.Domain(ctx); err == nil && configured {
		status.PublicName = status.Name + "." + domain
	}
	var last ApplyResult
	if raw, found, err := store.Setting(ctx, s.cfg.DB, SettingLastApply); err == nil && found && json.Unmarshal([]byte(raw), &last) == nil {
		status.LastApply = &last
	}
	if s.cfg.Endpoint != nil {
		state := s.cfg.Endpoint.State(ctx)
		status.PublicState = &state
	}
	s.mu.Lock()
	status.Applying = s.applying
	s.mu.Unlock()
	devices, err := s.Devices(ctx)
	if err != nil {
		return Status{}, err
	}
	status.Devices = devices
	if status.Devices == nil {
		status.Devices = []Device{}
	}
	return status, nil
}

// Names is the VPN's part of the names in AdGuard Home: inside the home
// network its public name points at the gateway, so that a phone that is
// always connected also connects at home.
func (s *Service) Names(ctx context.Context) ([]dnsnames.Name, error) {
	settings := s.Settings(ctx)
	if !settings.Enabled {
		return nil, nil
	}
	domain, configured, err := s.cfg.Domain(ctx)
	if err != nil || !configured {
		return nil, err
	}
	lan, err := s.cfg.LAN()
	if err != nil {
		return nil, err
	}
	return []dnsnames.Name{{Domain: settings.Name + "." + domain, Answer: lan.Address.String(), For: "the VPN, inside the home network"}}, nil
}
