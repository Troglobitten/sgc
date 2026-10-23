package wireguard

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// ServiceUnit is the VPN's program (installer/sgc-wireguard.service).
	ServiceUnit = "sgc-wireguard.service"
	// WG is WireGuard's own tool (Debian's wireguard-tools).
	WG  = "/usr/bin/wg"
	ip  = "ip"
	nft = "/usr/sbin/nft"

	forwardFile = "/proc/sys/net/ipv4/ip_forward"
	maxRequest  = 1 << 20
	// StatsEvery is how often the counters are written for the page.
	StatsEvery = 30 * time.Second
)

// Paths are where the VPN's state lives.
type Paths struct {
	// StateDir holds the last state that worked (state.json), the mark
	// that it is on, and what the forwarding of packets was before SGC.
	StateDir string
	// RunDir holds the files of the moment: the counters, the outcome of
	// the last request, the rendered settings.
	RunDir string
	// RequestFile is where the helper puts a new configuration.
	RequestFile string
}

func DefaultPaths() Paths {
	return Paths{StateDir: "/var/lib/sgc-wireguard", RunDir: "/run/sgc-wireguard", RequestFile: "/run/sgc-requests/wireguard.json"}
}

func (p Paths) stateFile() string   { return filepath.Join(p.StateDir, "state.json") }
func (p Paths) onFile() string      { return filepath.Join(p.StateDir, "on") }
func (p Paths) forwardWas() string  { return filepath.Join(p.StateDir, "forward-was") }
func (p Paths) StatsFile() string   { return filepath.Join(p.RunDir, "stats.json") }
func (p Paths) OutcomeFile() string { return filepath.Join(p.RunDir, "outcome.json") }
func (p Paths) wgFile() string      { return filepath.Join(p.RunDir, "wg.conf") }
func (p Paths) rulesFile() string   { return filepath.Join(p.RunDir, "rules.nft") }

// Request is what the helper hands over: a configuration and a number to
// find its outcome by.
type Request struct {
	ID     int64  `json:"id"`
	Config Config `json:"config"`
}

// Outcome is how a request went.
type Outcome struct {
	ID      int64     `json:"id"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// PeerStats are one device's counters, as WireGuard reports them.
type PeerStats struct {
	PublicKey string `json:"publicKey"`
	Endpoint  string `json:"endpoint"`
	// LatestHandshake is 0 if there never was one.
	LatestHandshake int64 `json:"latestHandshake"`
	RX              int64 `json:"rx"`
	TX              int64 `json:"tx"`
}

// Stats is what the page shows of the VPN.
type Stats struct {
	At      time.Time   `json:"at"`
	Up      bool        `json:"up"`
	Port    int         `json:"port"`
	Peers   []PeerStats `json:"peers"`
	Problem string      `json:"problem,omitempty"`
}

// ReadState returns the last configuration that worked (Enabled false if
// there is none). The firewall reads it for the VPN's port.
func ReadState(paths Paths) Config {
	var cfg Config
	if data, err := os.ReadFile(paths.stateFile()); err == nil {
		json.Unmarshal(data, &cfg)
	}
	return cfg
}

// PublicKey derives a WireGuard public key from a private one.
func PublicKey(private string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(private)
	if err != nil || len(raw) != 32 {
		return "", errors.New("not a WireGuard key")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// System does the work, as root with one privilege (CAP_NET_ADMIN).
type System struct {
	Paths Paths
	Run   func(ctx context.Context, program string, args ...string) ([]byte, error)
	// Forward reads and writes whether the kernel passes packets on;
	// nil means /proc/sys/net/ipv4/ip_forward.
	Forward func(on *bool) (bool, error)
	Now     func() time.Time
	Log     *slog.Logger
}

func (s *System) forward(set *bool) (bool, error) {
	if s.Forward != nil {
		return s.Forward(set)
	}
	if set != nil {
		value := "0\n"
		if *set {
			value = "1\n"
		}
		if err := os.WriteFile(forwardFile, []byte(value), 0o644); err != nil {
			return false, err
		}
	}
	data, err := os.ReadFile(forwardFile)
	return strings.TrimSpace(string(data)) == "1", err
}

// Serve is the VPN's program: it puts the last state that worked in place,
// takes up requests when told (reload: SIGHUP on reload), and writes the
// counters, until ctx ends. Ending it leaves the tunnel as it is.
func (s *System) Serve(ctx context.Context, reload <-chan os.Signal) error {
	if err := os.MkdirAll(s.Paths.RunDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Paths.StateDir, 0o700); err != nil {
		return err
	}
	if state := ReadState(s.Paths); state.Enabled {
		if err := state.Validate(); err != nil {
			s.Log.Error("the kept state of the VPN is not usable", "error", err)
		} else if err := s.apply(ctx, state); err != nil {
			s.Log.Error("the VPN could not be set up", "error", err)
		} else {
			s.Log.Info("the VPN is up", "devices", len(state.Peers))
		}
	}
	s.takeRequest(ctx)
	s.writeStats(ctx)
	ticker := time.NewTicker(StatsEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-reload:
			s.takeRequest(ctx)
			s.writeStats(ctx)
		case <-ticker.C:
			s.writeStats(ctx)
		}
	}
}

// takeRequest applies a waiting request, if there is one, and records how
// it went. A configuration that cannot be put in place leaves the previous
// one in place.
func (s *System) takeRequest(ctx context.Context) {
	f, err := os.OpenFile(s.Paths.RequestFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	var req Request
	decoder := json.NewDecoder(io.LimitReader(f, maxRequest))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&req)
	f.Close()
	os.Remove(s.Paths.RequestFile)
	outcome := Outcome{ID: req.ID, At: s.Now().UTC()}
	switch {
	case err != nil:
		outcome.Message = "the request could not be read: " + err.Error()
	default:
		outcome.Message, outcome.OK = s.change(ctx, req.Config)
	}
	data, _ := json.Marshal(outcome)
	writeAtomic(s.Paths.OutcomeFile(), data, 0o600)
}

func (s *System) change(ctx context.Context, cfg Config) (string, bool) {
	if err := cfg.Validate(); err != nil {
		return "the configuration was refused: " + err.Error(), false
	}
	previous := ReadState(s.Paths)
	if err := s.apply(ctx, cfg); err != nil {
		if previous.Enabled {
			if back := s.apply(ctx, previous); back != nil {
				s.Log.Error("the previous state of the VPN could not be put back either", "error", back)
			}
		} else {
			s.teardown(ctx)
		}
		return err.Error() + "; the previous state was kept", false
	}
	data, err := json.Marshal(cfg)
	if err == nil {
		err = writeAtomic(s.Paths.stateFile(), data, 0o600)
	}
	if err != nil {
		return "the VPN changed but its state could not be kept for the next start: " + err.Error(), false
	}
	if cfg.Enabled {
		os.WriteFile(s.Paths.onFile(), []byte("The owner switched the VPN on in SGC's page.\n"), 0o644)
	} else {
		os.Remove(s.Paths.onFile())
	}
	return "", true
}

func (s *System) run(ctx context.Context, program string, args ...string) error {
	output, err := s.Run(ctx, program, args...)
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text == "" {
			text = err.Error()
		}
		return fmt.Errorf("%s %s: %s", filepath.Base(program), strings.Join(args, " "), text)
	}
	return nil
}

// apply puts a configuration in place, or takes the VPN down if it is off.
func (s *System) apply(ctx context.Context, cfg Config) error {
	if !cfg.Enabled {
		return s.teardown(ctx)
	}
	rules := RenderRules(cfg)
	if err := writeAtomic(s.Paths.rulesFile(), []byte(rules), 0o600); err != nil {
		return err
	}
	if err := s.run(ctx, nft, "-c", "-f", s.Paths.rulesFile()); err != nil {
		return fmt.Errorf("nftables did not accept the VPN's rules: %w", err)
	}
	if err := writeAtomic(s.Paths.wgFile(), []byte(RenderWireGuard(cfg)), 0o600); err != nil {
		return err
	}
	if _, err := s.Run(ctx, ip, "link", "show", "dev", Interface); err != nil {
		if err := s.run(ctx, ip, "link", "add", "dev", Interface, "type", "wireguard"); err != nil {
			return fmt.Errorf("the WireGuard interface could not be made (does the kernel have WireGuard?): %w", err)
		}
	}
	if err := s.run(ctx, WG, "syncconf", Interface, s.Paths.wgFile()); err != nil {
		return err
	}
	network := netip.MustParsePrefix(cfg.Network)
	gateway := netip.PrefixFrom(GatewayAddress(network), network.Bits())
	if err := s.run(ctx, ip, "address", "replace", gateway.String(), "dev", Interface); err != nil {
		return err
	}
	if err := s.run(ctx, ip, "link", "set", "dev", Interface, "mtu", "1420", "up"); err != nil {
		return err
	}
	// The kernel has to pass the VPN's packets on. What it did before is
	// kept, to be put back when the VPN is switched off.
	if was, err := s.forward(nil); err == nil && !was {
		if _, err := os.Stat(s.Paths.forwardWas()); err != nil {
			if err := writeAtomic(s.Paths.forwardWas(), []byte("0"), 0o600); err != nil {
				return fmt.Errorf("what the kernel did before could not be noted: %w", err)
			}
		}
		on := true
		if _, err := s.forward(&on); err != nil {
			return fmt.Errorf("the kernel could not be told to pass packets on: %w", err)
		}
	}
	if err := s.run(ctx, nft, "-f", s.Paths.rulesFile()); err != nil {
		return fmt.Errorf("the VPN's rules could not be loaded: %w", err)
	}
	return nil
}

// teardown takes the VPN away: the interface, its rules, and the passing
// on of packets if SGC switched that on.
func (s *System) teardown(ctx context.Context) error {
	var problems []string
	if _, err := s.Run(ctx, ip, "link", "show", "dev", Interface); err == nil {
		if err := s.run(ctx, ip, "link", "delete", "dev", Interface); err != nil {
			problems = append(problems, err.Error())
		}
	}
	writeAtomic(s.Paths.rulesFile(), []byte(RenderRules(Config{})), 0o600)
	if err := s.run(ctx, nft, "-f", s.Paths.rulesFile()); err != nil {
		problems = append(problems, err.Error())
	}
	if _, err := os.Stat(s.Paths.forwardWas()); err == nil {
		off := false
		if _, err := s.forward(&off); err == nil {
			os.Remove(s.Paths.forwardWas())
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// ReadStats reads WireGuard's counters for the interface.
func (s *System) ReadStats(ctx context.Context) Stats {
	stats := Stats{At: s.Now().UTC(), Peers: []PeerStats{}}
	output, err := s.Run(ctx, WG, "show", Interface, "dump")
	if err != nil {
		if ReadState(s.Paths).Enabled {
			stats.Problem = "WireGuard does not report the interface: " + strings.TrimSpace(string(output))
		}
		return stats
	}
	stats.Up = true
	for i, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, "\t")
		if i == 0 {
			// private-key public-key listen-port fwmark
			if len(fields) >= 3 {
				stats.Port, _ = strconv.Atoi(fields[2])
			}
			continue
		}
		// public-key preshared-key endpoint allowed-ips latest-handshake rx tx keepalive
		if len(fields) < 7 {
			continue
		}
		peer := PeerStats{PublicKey: fields[0], Endpoint: fields[2]}
		if peer.Endpoint == "(none)" {
			peer.Endpoint = ""
		}
		peer.LatestHandshake, _ = strconv.ParseInt(fields[4], 10, 64)
		peer.RX, _ = strconv.ParseInt(fields[5], 10, 64)
		peer.TX, _ = strconv.ParseInt(fields[6], 10, 64)
		stats.Peers = append(stats.Peers, peer)
	}
	return stats
}

func (s *System) writeStats(ctx context.Context) {
	data, err := json.Marshal(s.ReadStats(ctx))
	if err == nil {
		writeAtomic(s.Paths.StatsFile(), data, 0o600)
	}
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
