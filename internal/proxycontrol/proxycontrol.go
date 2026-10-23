// Package proxycontrol is the web process's side of the proxy: the owner's
// choice of on or off, downloading Traefik, and keeping Traefik's
// configuration in step with SGC's database. The configuration is put in
// place by the root side (internal/proxy), which checks it again.
//
// It is applied when something changes (Kick), and once a minute if what
// SGC would send differs from what it last sent, which is how a renewed
// certificate reaches Traefik.
package proxycontrol

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/components"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// SettingEnabled is the owner's choice (exported).
	SettingEnabled = "proxy.enabled"
	// SettingLastApply is how the last change went (not exported).
	SettingLastApply = "proxy.last_apply"
)

// Helper is what the root side does for the proxy.
type Helper interface {
	ProxyStatus(ctx context.Context) (proxy.Status, error)
	ProxyInstall(ctx context.Context) error
	ProxyApply(ctx context.Context, cfg proxy.Config) error
}

type Config struct {
	DB     *sql.DB
	Helper Helper
	Audit  *audit.Log
	HTTP   *http.Client
	// SpoolDir is where downloads wait for the root side.
	SpoolDir string
	Arch     string
	// Build gathers the configuration (all but Enabled). A problem error
	// says what is missing for the proxy to be on.
	Build func(ctx context.Context) (proxy.Config, error)
	// Applied is called after a change was put in place.
	Applied func()
	Now     func() time.Time
	Log     *slog.Logger
}

// ApplyResult is how a change to Traefik's configuration went.
type ApplyResult struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
}

type Status struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	Running   bool   `json:"running"`
	// Wanted is the owner's choice.
	Wanted bool `json:"wanted"`
	// NotReady says what is missing before the proxy can be on, "" if nothing.
	NotReady    string       `json:"notReady"`
	LastApply   *ApplyResult `json:"lastApply"`
	ListenPorts []string     `json:"listenPorts"`
	Applying    bool         `json:"applying"`
	// PinnedVersion is the version this SGC installs.
	PinnedVersion string `json:"pinnedVersion"`
}

type Service struct {
	cfg  Config
	kick chan struct{}

	mu          sync.Mutex
	applying    bool
	appliedHash [32]byte
	// changes keeps switching and bringing up to date one at a time, from
	// deciding what to send to the answer. Otherwise a look that began
	// before the owner switched the proxy off could send its "on" after the
	// "off", or an older configuration after a newer one.
	changes sync.Mutex
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Applied == nil {
		cfg.Applied = func() {}
	}
	return &Service{cfg: cfg, kick: make(chan struct{}, 1)}
}

func (s *Service) wanted(ctx context.Context) (bool, error) {
	raw, _, err := store.Setting(ctx, s.cfg.DB, SettingEnabled)
	return raw == "true", err
}

// On reports whether the owner wants the proxy on (for other parts: names
// only point at the gateway while it is).
func (s *Service) On(ctx context.Context) bool {
	on, err := s.wanted(ctx)
	return err == nil && on
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	wanted, err := s.wanted(ctx)
	if err != nil {
		return Status{}, err
	}
	status := Status{Wanted: wanted, ListenPorts: []string{}, PinnedVersion: components.Traefik.Version}
	if root, err := s.cfg.Helper.ProxyStatus(ctx); err == nil {
		status.Installed, status.Version, status.Running, status.ListenPorts = root.Installed, root.Version, root.Running, root.ListenPorts
	}
	if _, err := s.cfg.Build(ctx); err != nil {
		if words, ok := problem.Message(err); ok {
			status.NotReady = words
		} else {
			return Status{}, err
		}
	}
	var last ApplyResult
	if raw, found, err := store.Setting(ctx, s.cfg.DB, SettingLastApply); err == nil && found && json.Unmarshal([]byte(raw), &last) == nil {
		status.LastApply = &last
	}
	s.mu.Lock()
	status.Applying = s.applying
	s.mu.Unlock()
	return status, nil
}

// SetEnabled switches the proxy on (downloading and installing Traefik
// first where it is missing) or off. Switching on fails, and stays off, if
// Traefik does not take the configuration.
func (s *Service) SetEnabled(ctx context.Context, actor, remote string, enabled bool) error {
	s.changes.Lock()
	defer s.changes.Unlock()
	if !enabled {
		if err := store.SetSetting(ctx, s.cfg.DB, SettingEnabled, "false"); err != nil {
			return err
		}
		s.record(ctx, actor, audit.ActionProxySwitchedOff, "", remote)
		return s.apply(ctx, proxy.Config{Enabled: false}, true)
	}
	cfg, err := s.cfg.Build(ctx)
	if err != nil {
		return err
	}
	if err := s.EnsureInstalled(ctx); err != nil {
		return err
	}
	cfg.Enabled = true
	if err := s.apply(ctx, cfg, true); err != nil {
		return err
	}
	if err := store.SetSetting(ctx, s.cfg.DB, SettingEnabled, "true"); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionProxySwitchedOn, "Traefik "+components.Traefik.Version, remote)
	return nil
}

// EnsureInstalled downloads and installs the pinned Traefik if the device
// does not have it. It stays off.
func (s *Service) EnsureInstalled(ctx context.Context) error {
	if status, err := s.cfg.Helper.ProxyStatus(ctx); err == nil && status.Installed && status.Version == components.Traefik.Version {
		return nil
	}
	file, err := components.Traefik.File(s.cfg.Arch)
	if err != nil {
		return err
	}
	dest := filepath.Join(s.cfg.SpoolDir, components.Traefik.SpoolName(s.cfg.Arch))
	if err := download(ctx, s.cfg.HTTP, file, dest); err != nil {
		return problem.Newf("Traefik could not be downloaded: %v. Check that this device can reach github.com, then try again.", err)
	}
	if err := s.cfg.Helper.ProxyInstall(ctx); err != nil {
		os.Remove(dest)
		return problem.Newf("Traefik could not be installed: %v", err)
	}
	return nil
}

// Kick asks for the configuration to be brought up to date soon.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run keeps Traefik's configuration in step until ctx ends.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	first := time.NewTimer(5 * time.Second)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-ticker.C:
		case <-s.kick:
			// Changes often come in a burst.
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
		s.Sync(ctx)
	}
}

// Sync sends the configuration if it differs from what was last sent.
func (s *Service) Sync(ctx context.Context) {
	s.changes.Lock()
	defer s.changes.Unlock()
	wanted, err := s.wanted(ctx)
	if err != nil || !wanted {
		return
	}
	cfg, err := s.cfg.Build(ctx)
	if err != nil {
		// Nothing to send without a domain or a certificate; what was sent
		// last stays in place.
		return
	}
	cfg.Enabled = true
	if err := s.apply(ctx, cfg, false); err != nil && ctx.Err() == nil {
		s.cfg.Log.Error("bring the proxy's configuration up to date", "error", err)
	}
}

func hashOf(cfg proxy.Config) [32]byte {
	data, _ := json.Marshal(cfg)
	return sha256.Sum256(data)
}

// apply sends a configuration unless it is what was last sent (force sends
// it anyway).
func (s *Service) apply(ctx context.Context, cfg proxy.Config, force bool) error {
	hash := hashOf(cfg)
	s.mu.Lock()
	if !force && hash == s.appliedHash {
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

	err := s.cfg.Helper.ProxyApply(context.WithoutCancel(ctx), cfg)
	result := ApplyResult{At: s.cfg.Now().UTC(), OK: err == nil}
	if err != nil {
		result.Message = err.Error()
		s.record(ctx, "system", audit.ActionProxyApplyFailed, err.Error(), "")
	}
	if data, jsonErr := json.Marshal(result); jsonErr == nil {
		store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingLastApply, string(data))
	}
	if err != nil {
		return problem.Newf("The proxy's configuration was not put in place: %v", err)
	}
	s.mu.Lock()
	s.appliedHash = hash
	s.mu.Unlock()
	s.cfg.Applied()
	return nil
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

// download fetches a pinned file and checks it.
func download(ctx context.Context, client *http.Client, file components.File, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, file.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the download answered with status %d", resp.StatusCode)
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(resp.Body, file.Size+1))
	if err := out.Close(); copyErr == nil {
		copyErr = err
	}
	if copyErr != nil {
		os.Remove(dest)
		return copyErr
	}
	if err := components.Verify(dest, file); err != nil {
		os.Remove(dest)
		return err
	}
	return nil
}
