package proxy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/components"
)

const (
	// ServiceUnit is Traefik itself (installer/sgc-traefik.service).
	ServiceUnit = "sgc-traefik.service"
	// ServiceUser is the account it runs as.
	ServiceUser = "sgc-traefik"

	systemctl    = "/usr/bin/systemctl"
	useradd      = "/usr/sbin/useradd"
	ssProgram    = "/usr/bin/ss"
	archiveEntry = "traefik"
	maxProgram   = 300 << 20
	maxRequest   = 1 << 20
)

// Paths are where the proxy's parts live.
type Paths struct {
	// Root holds one folder per version and "current".
	Root string
	// ConfigDir holds what Traefik reads: traefik.yml, dynamic/, certs/.
	ConfigDir string
	// SpoolDir is where the web process puts the downloaded release.
	SpoolDir string
	// RequestFile is where the helper puts the web process's Config for
	// the job that applies it.
	RequestFile string
}

func DefaultPaths() Paths {
	return Paths{
		Root:        "/opt/sgc/components/traefik",
		ConfigDir:   "/etc/sgc/traefik",
		SpoolDir:    "/var/lib/sgc/components",
		RequestFile: "/run/sgc-requests/proxy.json",
	}
}

func (p Paths) current() string     { return filepath.Join(p.Root, "current") }
func (p Paths) Program() string     { return filepath.Join(p.current(), "traefik") }
func (p Paths) staticFile() string  { return filepath.Join(p.ConfigDir, "traefik.yml") }
func (p Paths) dynamicDir() string  { return filepath.Join(p.ConfigDir, "dynamic") }
func (p Paths) dynamicFile() string { return filepath.Join(p.dynamicDir(), "sgc.yml") }
func (p Paths) certDir() string     { return filepath.Join(p.ConfigDir, "certs") }
func (p Paths) certFile() string    { return filepath.Join(p.certDir(), "wildcard.crt") }
func (p Paths) keyFile() string     { return filepath.Join(p.certDir(), "wildcard.key") }
func (p Paths) appliedFile() string { return filepath.Join(p.ConfigDir, "applied.json") }

// onFile is what lets sgc-traefik.service start: present only while the
// owner has the proxy on (see the unit's conditions).
func (p Paths) onFile() string { return filepath.Join(p.ConfigDir, "on") }

// Installed reports whether Traefik is installed.
func Installed(paths Paths) bool {
	info, err := os.Stat(paths.Program())
	return err == nil && info.Mode().IsRegular()
}

// InstalledVersion is the version "current" points at, "" if none.
func InstalledVersion(paths Paths) string {
	target, err := os.Readlink(paths.current())
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// Applied is what is in place, as the firewall and the page need it (no
// key, no routes).
type Applied struct {
	Enabled     bool      `json:"enabled"`
	ListenPorts []string  `json:"listenPorts"`
	At          time.Time `json:"at"`
}

// ReadApplied returns what the last successful change put in place.
func ReadApplied(paths Paths) Applied {
	var applied Applied
	data, err := os.ReadFile(paths.appliedFile())
	if err == nil {
		json.Unmarshal(data, &applied)
	}
	if applied.ListenPorts == nil {
		applied.ListenPorts = []string{}
	}
	return applied
}

// System does the work, as root.
type System struct {
	Paths     Paths
	Component components.Component
	Arch      string
	Run       func(ctx context.Context, program string, args ...string) ([]byte, error)
	// Group returns the numeric ID of Traefik's group (its account's).
	Group func() (int, error)
	// Chown gives a path to root and Traefik's group; nil means os.Chown.
	Chown func(path string, gid int) error
	// API asks Traefik's own API; nil means over HTTP on TraefikAPI.
	API   func(ctx context.Context, path string) ([]byte, error)
	Sleep func(time.Duration)
	Now   func() time.Time
	Log   *slog.Logger
}

// Status is what the root side knows.
type Status struct {
	// On: the last change switched it on (what the firewall goes by).
	On          bool     `json:"on"`
	Installed   bool     `json:"installed"`
	Version     string   `json:"version"`
	Enabled     bool     `json:"enabled"`
	Running     bool     `json:"running"`
	ListenPorts []string `json:"listenPorts"`
}

func (s *System) Status(ctx context.Context) Status {
	applied := ReadApplied(s.Paths)
	status := Status{Installed: Installed(s.Paths), Version: InstalledVersion(s.Paths), ListenPorts: applied.ListenPorts}
	status.On = applied.Enabled && status.Installed
	if status.Installed {
		_, err := s.Run(ctx, systemctl, "is-active", "--quiet", ServiceUnit)
		status.Running = err == nil
		_, err = s.Run(ctx, systemctl, "is-enabled", "--quiet", ServiceUnit)
		status.Enabled = err == nil
	}
	return status
}

// ReadRequest reads the configuration the helper put down, and checks it.
func (s *System) ReadRequest() (Config, error) {
	f, err := os.OpenFile(s.Paths.RequestFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Config{}, fmt.Errorf("read the request: %w", err)
	}
	defer f.Close()
	var cfg Config
	decoder := json.NewDecoder(io.LimitReader(f, maxRequest))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("read the request: %w", err)
	}
	if err := cfg.Validate(s.Now()); err != nil {
		return Config{}, fmt.Errorf("the request was refused: %w", err)
	}
	return cfg, nil
}

// Install installs the pinned Traefik from the downloaded file, or replaces
// an older one. It is not switched on: that is the owner's step (or, on a
// device where it was on, it is restarted on the new version and checked).
func (s *System) Install(ctx context.Context) error {
	file, err := s.Component.File(s.Arch)
	if err != nil {
		return err
	}
	spooled := filepath.Join(s.Paths.SpoolDir, s.Component.SpoolName(s.Arch))
	if err := components.Verify(spooled, file); err != nil {
		return fmt.Errorf("the downloaded release was refused: %w", err)
	}
	previous := InstalledVersion(s.Paths)
	versionDir := filepath.Join(s.Paths.Root, s.Component.Version)
	if err := unpackOne(spooled, archiveEntry, filepath.Join(versionDir, "traefik")); err != nil {
		return fmt.Errorf("unpack the release: %w", err)
	}
	if err := s.prepareAccount(ctx); err != nil {
		return err
	}
	if err := s.prepareConfigDir(); err != nil {
		return err
	}
	if _, err := os.Stat(s.Paths.staticFile()); err != nil {
		// Something to start on before the first change: no routes yet.
		static, _ := RenderStatic(Config{}, s.Paths.dynamicDir())
		if err := s.writeFile(s.Paths.staticFile(), static, 0o640); err != nil {
			return err
		}
	}
	if err := switchLink(s.Paths.current(), s.Component.Version); err != nil {
		return err
	}
	if ReadApplied(s.Paths).Enabled {
		if output, err := s.Run(ctx, systemctl, "restart", ServiceUnit); err != nil || s.waitReady(ctx) != nil {
			s.Log.Error("Traefik did not come up on the new version; going back", "output", string(output))
			if previous != "" {
				switchLink(s.Paths.current(), previous)
				s.Run(ctx, systemctl, "restart", ServiceUnit)
			}
			os.RemoveAll(versionDir)
			return errors.New("Traefik did not start on the new version; the previous one was put back")
		}
	}
	if previous != "" && previous != s.Component.Version {
		os.RemoveAll(filepath.Join(s.Paths.Root, previous))
	}
	os.Remove(spooled)
	s.Log.Info("Traefik installed", "version", s.Component.Version, "replaced", previous)
	return nil
}

func (s *System) prepareAccount(ctx context.Context) error {
	if _, err := s.Run(ctx, "/usr/bin/id", "-u", ServiceUser); err == nil {
		return nil
	}
	if output, err := s.Run(ctx, useradd, "--system", "--home-dir", "/nonexistent", "--no-create-home",
		"--shell", "/usr/sbin/nologin", ServiceUser); err != nil {
		return fmt.Errorf("create the account for Traefik: %s", lastLine(output, err))
	}
	return nil
}

// prepareConfigDir makes the folders Traefik reads: root's, readable by
// Traefik's group only (the key of the certificate is in there).
func (s *System) prepareConfigDir() error {
	gid, err := s.Group()
	if err != nil {
		return err
	}
	for _, dir := range []string{s.Paths.ConfigDir, s.Paths.dynamicDir(), s.Paths.certDir()} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		if err := s.chown(dir, gid); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o750); err != nil {
			return err
		}
	}
	return nil
}

// writeFile replaces a file in one step, owned by root and readable by
// Traefik's group.
func (s *System) writeFile(path string, data []byte, mode os.FileMode) error {
	gid, err := s.Group()
	if err != nil {
		return err
	}
	temporary := path + ".new"
	os.Remove(temporary)
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := s.chown(temporary, gid); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}

func (s *System) chown(path string, gid int) error {
	if s.Chown != nil {
		return s.Chown(path, gid)
	}
	return os.Chown(path, 0, gid)
}

// files are the four files a configuration consists of.
type files map[string][]byte

func (s *System) readFiles() files {
	out := files{}
	for _, path := range []string{s.Paths.staticFile(), s.Paths.dynamicFile(), s.Paths.certFile(), s.Paths.keyFile()} {
		if data, err := os.ReadFile(path); err == nil {
			out[path] = data
		}
	}
	return out
}

func (s *System) writeFiles(f files) error {
	for _, path := range []string{s.Paths.certFile(), s.Paths.keyFile(), s.Paths.staticFile(), s.Paths.dynamicFile()} {
		data, ok := f[path]
		if !ok {
			os.Remove(path)
			continue
		}
		if err := s.writeFile(path, data, 0o640); err != nil {
			return err
		}
	}
	return nil
}

// Apply puts a configuration in place: validate, write, (re)start, check,
// and put the previous files back if Traefik does not take it.
func (s *System) Apply(ctx context.Context, cfg Config) error {
	if !Installed(s.Paths) {
		return errors.New("Traefik is not installed on this device")
	}
	if err := cfg.Validate(s.Now()); err != nil {
		return err
	}
	if !cfg.Enabled {
		os.Remove(s.Paths.onFile())
		if output, err := s.Run(ctx, systemctl, "disable", "--now", ServiceUnit); err != nil {
			return fmt.Errorf("Traefik could not be stopped: %s", lastLine(output, err))
		}
		return s.recordApplied(cfg)
	}
	if err := s.prepareConfigDir(); err != nil {
		return err
	}
	static, err := RenderStatic(cfg, s.Paths.dynamicDir())
	if err != nil {
		return err
	}
	dynamic, err := RenderDynamic(cfg, s.Paths.certFile(), s.Paths.keyFile())
	if err != nil {
		return err
	}
	next := files{
		s.Paths.staticFile():  static,
		s.Paths.dynamicFile(): dynamic,
		s.Paths.certFile():    []byte(cfg.CertificatePEM),
		s.Paths.keyFile():     []byte(cfg.PrivateKeyPEM),
	}
	before := s.readFiles()
	wasRunning := s.Status(ctx).Running
	restart := !wasRunning || !bytes.Equal(before[s.Paths.staticFile()], static)
	if !wasRunning {
		// Something else on the proxy's ports would keep Traefik from
		// starting; say who, in words, instead of a failed start.
		ports := append([]string{"80/tcp", "443/tcp"}, cfg.ListenPorts()...)
		if holder := s.portHolder(ctx, ports); holder != "" {
			return fmt.Errorf("another program on this device already uses a port the proxy needs: %s. It has to be switched off first", holder)
		}
	} else if restart {
		// Ports that are new now must be free too.
		var added []string
		for _, port := range cfg.ListenPorts() {
			if !slices.Contains(ReadApplied(s.Paths).ListenPorts, port) {
				added = append(added, port)
			}
		}
		if holder := s.portHolder(ctx, added); holder != "" {
			return fmt.Errorf("a port for a proxied service is already used by another program on this device: %s", holder)
		}
	}

	undo := func(reason error) error {
		s.writeFiles(before)
		switch {
		case !wasRunning:
			os.Remove(s.Paths.onFile())
			s.Run(ctx, systemctl, "disable", "--now", ServiceUnit)
		case restart:
			s.Run(ctx, systemctl, "restart", ServiceUnit)
		}
		return fmt.Errorf("%w; the previous configuration was put back", reason)
	}
	if err := s.writeFiles(next); err != nil {
		return undo(fmt.Errorf("the configuration could not be written: %w", err))
	}
	if err := os.WriteFile(s.Paths.onFile(), []byte("The owner switched the proxy on in SGC's page.\n"), 0o644); err != nil {
		return undo(fmt.Errorf("the proxy could not be marked as on: %w", err))
	}
	if output, err := s.Run(ctx, systemctl, "enable", ServiceUnit); err != nil {
		return undo(fmt.Errorf("Traefik could not be made part of start-up: %s", lastLine(output, err)))
	}
	if restart {
		if output, err := s.Run(ctx, systemctl, "restart", ServiceUnit); err != nil {
			return undo(fmt.Errorf("Traefik could not be started: %s", lastLine(output, err)))
		}
	}
	if err := s.waitReady(ctx); err != nil {
		return undo(err)
	}
	if err := s.checkRouters(ctx, cfg); err != nil {
		return undo(err)
	}
	return s.recordApplied(cfg)
}

func (s *System) recordApplied(cfg Config) error {
	data, err := json.Marshal(Applied{Enabled: cfg.Enabled, ListenPorts: cfg.ListenPorts(), At: s.Now().UTC()})
	if err != nil {
		return err
	}
	temporary := s.Paths.appliedFile() + ".new"
	if err := os.MkdirAll(s.Paths.ConfigDir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(temporary, data, 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, s.Paths.appliedFile())
}

func (s *System) api(ctx context.Context, path string) ([]byte, error) {
	if s.API != nil {
		return s.API(ctx, path)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+TraefikAPI+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Traefik answered %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// waitReady waits for Traefik to answer its health check, and checks that
// it stays up.
func (s *System) waitReady(ctx context.Context) error {
	for range 40 {
		if body, err := s.api(ctx, "/ping"); err == nil && strings.TrimSpace(string(body)) == "OK" {
			return nil
		}
		s.Sleep(500 * time.Millisecond)
	}
	return errors.New("Traefik did not come up (its log: sudo journalctl -u sgc-traefik --no-pager -n 30)")
}

type routerReport struct {
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Error  []string `json:"error"`
}

// checkRouters waits until Traefik reports every router of the
// configuration as enabled. Traefik reads a changed file within a second or
// two; a router it cannot use it reports with its reason.
func (s *System) checkRouters(ctx context.Context, cfg Config) error {
	expected := ExpectedRouters(cfg)
	var last error
	for range 30 {
		last = nil
		for kind, names := range expected {
			body, err := s.api(ctx, "/api/"+kind+"/routers?per_page=10000")
			if err != nil {
				last = fmt.Errorf("Traefik's API did not answer: %w", err)
				break
			}
			var reports []routerReport
			if err := json.Unmarshal(body, &reports); err != nil {
				last = fmt.Errorf("Traefik's API gave an answer SGC cannot read: %w", err)
				break
			}
			byName := map[string]routerReport{}
			for _, r := range reports {
				byName[r.Name] = r
			}
			for _, name := range names {
				report, ok := byName[name]
				switch {
				case !ok:
					last = fmt.Errorf("Traefik has not taken up the route %s", name)
				case report.Status != "enabled":
					last = fmt.Errorf("Traefik does not use the route %s: %s", name, strings.Join(report.Error, "; "))
					// A refusal does not go away by waiting.
					return last
				}
			}
		}
		if last == nil {
			return nil
		}
		s.Sleep(500 * time.Millisecond)
	}
	return last
}

// portHolder names the program that listens on one of the ports
// ("443/tcp"), "" if none does.
func (s *System) portHolder(ctx context.Context, ports []string) string {
	for _, port := range ports {
		number, protocol, _ := strings.Cut(port, "/")
		flag := "-lntp"
		if protocol == "udp" {
			flag = "-lnup"
		}
		output, err := s.Run(ctx, ssProgram, "-H", flag, "sport", "=", ":"+number)
		if err != nil {
			continue
		}
		for line := range strings.Lines(string(output)) {
			if strings.TrimSpace(line) == "" {
				continue
			}
			name := "an unnamed program"
			if _, process, ok := strings.Cut(line, `users:(("`); ok {
				name, _, _ = strings.Cut(process, `"`)
			}
			if name == "traefik" {
				continue
			}
			return name + " (port " + port + ")"
		}
	}
	return ""
}

// unpackOne takes one file out of a .tar.gz, and nothing else.
func unpackOne(archivePath, entry, target string) error {
	f, err := os.OpenFile(archivePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	unzipped, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	archive := tar.NewReader(unzipped)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("the release does not contain the program")
		}
		if err != nil {
			return err
		}
		if header.Name != entry || header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size <= 0 || header.Size > maxProgram {
			return errors.New("the program in the release has an impossible size")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		temporary := target + ".new"
		out, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o755)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(archive, header.Size))
		if err := out.Chmod(0o755); copyErr == nil {
			copyErr = err
		}
		if err := out.Close(); copyErr == nil {
			copyErr = err
		}
		if copyErr != nil {
			os.Remove(temporary)
			return copyErr
		}
		return os.Rename(temporary, target)
	}
}

func switchLink(link, version string) error {
	temporary := link + ".new"
	os.Remove(temporary)
	if err := os.Symlink(version, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, link)
}

func lastLine(output []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		if runes := []rune(last); len(runes) > 240 {
			last = string(runes[:240]) + "…"
		}
		return last
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// GroupID looks up the group of Traefik's account.
func GroupID(lookup func(name string) (string, error)) func() (int, error) {
	return func() (int, error) {
		gid, err := lookup(ServiceUser)
		if err != nil {
			return 0, fmt.Errorf("look up Traefik's account: %w", err)
		}
		return strconv.Atoi(gid)
	}
}
