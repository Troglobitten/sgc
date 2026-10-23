package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/wireguard"
)

func wireguardSystem() *wireguard.System {
	return &wireguard.System{
		Paths: wireguard.DefaultPaths(),
		Run:   runProgram,
		Now:   time.Now,
		Log:   slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// VPNStatus is what the helper reports about the VPN.
type VPNStatus struct {
	// Installed: WireGuard's tool is on the device.
	Installed bool `json:"installed"`
	// On: the last change that worked switched it on.
	On      bool            `json:"on"`
	Running bool            `json:"running"`
	Port    int             `json:"port"`
	Stats   wireguard.Stats `json:"stats"`
}

func vpnStatus() (any, error) {
	paths := wireguard.DefaultPaths()
	state := wireguard.ReadState(paths)
	status := VPNStatus{Installed: programExists(wireguard.WG), On: state.Enabled, Port: state.Port}
	ctx, cancel := context.WithTimeout(context.Background(), programTimeout)
	defer cancel()
	if _, err := runProgram(ctx, systemctl, "is-active", "--quiet", wireguard.ServiceUnit); err == nil {
		status.Running = true
	}
	if data, err := os.ReadFile(paths.StatsFile()); err == nil {
		json.Unmarshal(data, &status.Stats)
	}
	if status.Stats.Peers == nil {
		status.Stats.Peers = []wireguard.PeerStats{}
	}
	return status, nil
}

// applyVPN hands a configuration to the VPN's program and waits for how it
// went. The program checks it again.
// vpnChanges keeps changes to the VPN one at a time: they share the request
// file, and the VPN's program answers the one it finds there. Two at once
// (seen on the test machine, switching on while SGC brought the VPN up to
// date) left the first waiting for an answer that never came.
var vpnChanges sync.Mutex

func applyVPN(cfg wireguard.Config) error {
	vpnChanges.Lock()
	defer vpnChanges.Unlock()
	paths := wireguard.DefaultPaths()
	id := time.Now().UnixNano()
	data, err := json.Marshal(wireguard.Request{ID: id, Config: cfg})
	if err != nil {
		return err
	}
	if err := os.WriteFile(paths.RequestFile, data, 0o600); err != nil {
		return fmt.Errorf("hand over the request: %w", err)
	}
	if cfg.Enabled {
		if err := runSystemctl("enable", wireguard.ServiceUnit); err != nil {
			return err
		}
	}
	// Running: it takes the request when told; not running: when it starts.
	if err := runSystemctl("reload-or-restart", wireguard.ServiceUnit); err != nil {
		os.Remove(paths.RequestFile)
		return fmt.Errorf("the VPN's program could not be started: %w", err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		var outcome wireguard.Outcome
		if data, err := os.ReadFile(paths.OutcomeFile()); err == nil && json.Unmarshal(data, &outcome) == nil && outcome.ID == id {
			if !outcome.OK {
				return errors.New(outcome.Message)
			}
			if !cfg.Enabled {
				runSystemctl("disable", "--now", wireguard.ServiceUnit)
			}
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("the VPN's program did not answer (its log: sudo journalctl -u sgc-wireguard --no-pager -n 30)")
}

// runWireGuard is "sgc-helper wireguard run": the VPN's own program.
func runWireGuard(args []string) error {
	if len(args) != 1 || args[0] != "run" {
		return errors.New("usage: sgc-helper wireguard run")
	}
	if os.Geteuid() != 0 {
		return errors.New("the VPN needs root")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	return wireguardSystem().Serve(ctx, reload)
}
