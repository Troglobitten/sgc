// Package adguard is the root side of AdGuard Home: installing the pinned
// release, giving it its first settings file, starting and removing it.
//
// SGC does not answer DNS. AdGuard Home does, as a service of its own under
// an account of its own (installer/sgc-adguard.service), and it keeps
// running when SGC does not. Its settings are the owner's: SGC writes the
// file once, when AdGuard Home is first installed, and never again.
//
// The file to install is downloaded by the web process. This side checks it
// against the checksum compiled into it before unpacking anything, so a
// compromised web process cannot have something else installed.
package adguard

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/components"
)

const (
	// ServiceUnit runs AdGuard Home. ServiceUser is the account it runs as,
	// created at the first installation.
	ServiceUnit = "sgc-adguard.service"
	ServiceUser = "sgc-adguard"
	// WebAddress is where AdGuard Home's own page listens: on this device
	// only. It has no login of its own; the way in from outside is SGC's
	// page, behind SGC's login. The unit file pins this address on the
	// command line, whatever a settings file says.
	WebAddress = "127.0.0.1:3000"
	DNSPort    = 53

	systemctl = "/usr/bin/systemctl"
	useradd   = "/usr/sbin/useradd"
	ssProgram = "/usr/bin/ss"
	getent    = "/usr/bin/getent"

	// systemd-resolved, as "ss" names it, its unit, and the two lists of name
	// servers it keeps: one that points programs at its own listener on
	// port 53, one that names the real servers.
	resolvedProcess = "systemd-resolve"
	resolvedUnit    = "systemd-resolved.service"
	resolvedStub    = "stub-resolv.conf"
	resolvedDirect  = "/run/systemd/resolve/resolv.conf"
	// A name the device must be able to look up for itself.
	lookupProbe = "deb.debian.org"
	// The program inside the release archive, and the most it can weigh.
	archiveEntry = "./AdGuardHome/AdGuardHome"
	maxProgram   = 200 * 1024 * 1024
	maxSettings  = 4 * 1024 * 1024
)

// Paths says where everything is.
type Paths struct {
	// Root holds one folder per installed version and the link "current".
	Root string
	// DataDir is AdGuard Home's own folder: its settings file and its data.
	DataDir string
	// SpoolDir is where the web process puts the downloaded release and, on
	// a restored device, the settings from the export.
	SpoolDir string
	// ResolvedDropIn is SGC's file among systemd-resolved's settings, and
	// ResolvConf the device's own list of name servers (see freeDNSPort).
	ResolvedDropIn string
	ResolvConf     string
}

func DefaultPaths() Paths {
	return Paths{
		Root:           "/opt/sgc/components/adguardhome",
		DataDir:        "/var/lib/sgc-adguard",
		SpoolDir:       "/var/lib/sgc/components",
		ResolvedDropIn: "/etc/systemd/resolved.conf.d/60-sgc-adguard.conf",
		ResolvConf:     "/etc/resolv.conf",
	}
}

func (p Paths) current() string { return filepath.Join(p.Root, "current") }

// Program is the installed program, through the link the service uses.
func (p Paths) Program() string { return filepath.Join(p.current(), "AdGuardHome") }

// SettingsFile is AdGuard Home's settings file.
func (p Paths) SettingsFile() string { return filepath.Join(p.DataDir, "AdGuardHome.yaml") }

// RestoredSettings is where the web process puts the settings file from an
// export, to be used as the first settings on this device.
func (p Paths) RestoredSettings() string { return filepath.Join(p.SpoolDir, "adguardhome.yaml") }

// Installed reports whether AdGuard Home is installed. It needs no privileges.
func Installed(paths Paths) bool {
	info, err := os.Stat(paths.Program())
	return err == nil && info.Mode().IsRegular()
}

// InstalledVersion is the version the link points at, or "".
func InstalledVersion(paths Paths) string {
	target, err := os.Readlink(paths.current())
	if err != nil || !Installed(paths) {
		return ""
	}
	return filepath.Base(target)
}

// InitialSettings is the settings file SGC gives a new AdGuard Home, in the
// layout of the pinned version (schema_version). What is not in it gets
// AdGuard Home's own defaults. From then on the file is the owner's.
//
//   - No login of its own, and its page on this device only: SGC's login is
//     the one login.
//   - DNS on every address of the device. Who may reach it is the firewall's
//     business, which lets DNS in from the home network only.
//   - Upstream: Quad9 over HTTPS (the owner's choice): does not log who asks,
//     refuses known malware sites, and the internet provider cannot read
//     the questions. DNSSEC on.
//   - The query log is kept for 7 days (the owner's choice).
//   - One blocklist, AdGuard's own.
const InitialSettings = `http:
  address: ` + WebAddress + `
  session_ttl: 720h
users: []
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  upstream_dns:
    - https://dns.quad9.net/dns-query
  bootstrap_dns:
    - 9.9.9.9
    - 149.112.112.112
  enable_dnssec: true
querylog:
  interval: 7d
  enabled: true
  file_enabled: true
statistics:
  interval: 1d
  enabled: true
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
schema_version: 34
`

// System carries out the root side's work, in units of its own
// (installer/sgc-adguard-*.service).
type System struct {
	Paths     Paths
	Component components.Component
	Arch      string

	// Run runs a program and returns what it printed. Injected so that the
	// tests need neither root nor systemd.
	Run func(ctx context.Context, program string, args ...string) ([]byte, error)
	// Chown gives a path to the service account. Injected for the same reason.
	Chown func(path string) error
	Sleep func(time.Duration)
	Log   *slog.Logger
}

// Status is what the root side knows about the service.
type Status struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	Running   bool   `json:"running"`
}

func (s *System) Status(ctx context.Context) Status {
	status := Status{Installed: Installed(s.Paths), Version: InstalledVersion(s.Paths)}
	if status.Installed {
		status.Running = s.active(ctx)
	}
	return status
}

func (s *System) active(ctx context.Context) bool {
	_, err := s.Run(ctx, systemctl, "is-active", "--quiet", ServiceUnit)
	return err == nil
}

// ReadSettings returns AdGuard Home's settings file, for an export.
func (s *System) ReadSettings() ([]byte, error) {
	return readLimited(s.Paths.SettingsFile(), maxSettings)
}

// Install installs the pinned version from the downloaded file, or replaces
// an older version with it, and starts it.
//
// An error means the device is as it was: a new installation is taken out
// again, a replaced version is put back and started.
func (s *System) Install(ctx context.Context) error {
	file, err := s.Component.File(s.Arch)
	if err != nil {
		return err
	}
	spooled := filepath.Join(s.Paths.SpoolDir, s.Component.SpoolName(s.Arch))
	// The web process downloaded it; this is the check that counts.
	if err := components.Verify(spooled, file); err != nil {
		return fmt.Errorf("the downloaded release was refused: %w", err)
	}

	previous := InstalledVersion(s.Paths)
	giveBackPort := func() {}
	if previous == "" {
		// Something else on the DNS port would keep AdGuard Home from
		// starting. systemd-resolved is asked to step aside; anything else
		// is said now, in words, instead of as a failed start.
		switch holder := s.portHolder(ctx); holder {
		case "":
		case resolvedProcess:
			if giveBackPort, err = s.freeDNSPort(ctx); err != nil {
				return err
			}
		default:
			return fmt.Errorf("another program on this device already answers DNS (port %d): %s. It has to be switched off first", DNSPort, holder)
		}
	}

	versionDir := filepath.Join(s.Paths.Root, s.Component.Version)
	if err := s.unpack(spooled, versionDir); err != nil {
		giveBackPort()
		return fmt.Errorf("unpack the release: %w", err)
	}
	if err := s.prepareAccountAndData(ctx); err != nil {
		giveBackPort()
		return err
	}

	if err := switchLink(s.Paths.current(), s.Component.Version); err != nil {
		giveBackPort()
		return err
	}
	undo := func() {
		defer giveBackPort()
		if previous == "" {
			s.Run(ctx, systemctl, "disable", "--now", ServiceUnit)
			os.Remove(s.Paths.current())
		} else {
			switchLink(s.Paths.current(), previous)
			s.Run(ctx, systemctl, "restart", ServiceUnit)
		}
		if previous != s.Component.Version {
			os.RemoveAll(versionDir)
		}
	}

	// The program's own reading of its settings, before it is started on them.
	if output, err := s.Run(ctx, s.Paths.Program(), "--check-config", "--no-permcheck", "-c", s.Paths.SettingsFile(), "-w", s.Paths.DataDir); err != nil {
		undo()
		return fmt.Errorf("AdGuard Home does not accept its settings file: %s", lastLine(output, err))
	}
	// Whatever that check wrote as root (it brings an older settings file up
	// to date) belongs to the service's account.
	if err := s.chownAll(); err != nil {
		undo()
		return err
	}
	if output, err := s.Run(ctx, systemctl, "enable", ServiceUnit); err != nil {
		undo()
		return fmt.Errorf("AdGuard Home could not be made part of start-up: %s", lastLine(output, err))
	}
	if output, err := s.Run(ctx, systemctl, "restart", ServiceUnit); err != nil {
		undo()
		return fmt.Errorf("AdGuard Home could not be started: %s", lastLine(output, err))
	}
	// A service that starts and falls over is "active" for a moment.
	for range 5 {
		s.Sleep(time.Second)
		if !s.active(ctx) {
			undo()
			return errors.New("AdGuard Home started and stopped again (its log: sudo journalctl -u sgc-adguard --no-pager -n 30)")
		}
	}
	if previous != "" && previous != s.Component.Version {
		os.RemoveAll(filepath.Join(s.Paths.Root, previous))
	}
	os.Remove(s.Paths.RestoredSettings())
	s.Log.Info("AdGuard Home installed", "version", s.Component.Version, "replaced", previous)
	return nil
}

// Remove stops AdGuard Home and takes the program away. Its settings and
// data stay, so that installing it again continues where it left off.
func (s *System) Remove(ctx context.Context) error {
	if output, err := s.Run(ctx, systemctl, "disable", "--now", ServiceUnit); err != nil && Installed(s.Paths) {
		return fmt.Errorf("AdGuard Home could not be stopped: %s", lastLine(output, err))
	}
	os.Remove(s.Paths.current())
	entries, _ := os.ReadDir(s.Paths.Root)
	for _, entry := range entries {
		os.RemoveAll(filepath.Join(s.Paths.Root, entry.Name()))
	}
	s.returnDNSPort(ctx)
	s.Log.Info("AdGuard Home removed")
	return nil
}

// freeDNSPort makes systemd-resolved give up its listener on port 53.
//
// Debian's cloud images run systemd-resolved, which keeps a small DNS
// listener of its own on 127.0.0.53 and points the device's programs at it
// through /etc/resolv.conf. AdGuard Home cannot take port 53 on every
// address while that listener is there. (A Raspberry Pi OS does not run
// systemd-resolved, and none of this happens.)
//
// Two changes, both undone by the returned function and by Remove:
//
//   - one settings file of SGC's switches the listener off;
//   - /etc/resolv.conf, if it points at the list that names that listener,
//     is pointed at systemd-resolved's other list, which names the real
//     servers. The device itself goes on asking those, not AdGuard Home, so
//     that it can still look up names when AdGuard Home is down.
//
// Afterwards the device must still be able to look up a name. If it cannot,
// both changes are undone and the installation is refused.
func (s *System) freeDNSPort(ctx context.Context) (undo func(), err error) {
	linkWas, _ := os.Readlink(s.Paths.ResolvConf)
	repoint := strings.HasSuffix(linkWas, resolvedStub)
	undo = func() {
		os.Remove(s.Paths.ResolvedDropIn)
		if repoint {
			switchLink(s.Paths.ResolvConf, linkWas)
		}
		s.Run(ctx, systemctl, "restart", resolvedUnit)
	}

	if err := os.MkdirAll(filepath.Dir(s.Paths.ResolvedDropIn), 0o755); err != nil {
		return nil, err
	}
	// The second line is read back by returnDNSPort.
	content := "# Written by SGC: AdGuard Home answers DNS on this device.\n" + resolvWasPrefix + linkWas + "\n[Resolve]\nDNSStubListener=no\n"
	if err := os.WriteFile(s.Paths.ResolvedDropIn, []byte(content), 0o644); err != nil {
		return nil, err
	}
	if repoint {
		if err := switchLink(s.Paths.ResolvConf, resolvedDirect); err != nil {
			undo()
			return nil, err
		}
	}
	if output, err := s.Run(ctx, systemctl, "restart", resolvedUnit); err != nil {
		undo()
		return nil, fmt.Errorf("systemd-resolved did not take up its new settings: %s", lastLine(output, err))
	}
	if !s.canLookUp(ctx) {
		undo()
		return nil, errors.New("with port 53 taken from systemd-resolved, this device could no longer look up names itself, so that was put back and nothing was installed")
	}
	s.Log.Info("systemd-resolved gave up its listener on port 53", "resolv.conf repointed", repoint)
	return undo, nil
}

const resolvWasPrefix = "# resolv.conf pointed at: "

// returnDNSPort gives systemd-resolved its listener back, if SGC took it.
func (s *System) returnDNSPort(ctx context.Context) {
	data, err := readLimited(s.Paths.ResolvedDropIn, 64*1024)
	if err != nil {
		return
	}
	os.Remove(s.Paths.ResolvedDropIn)
	for line := range strings.Lines(string(data)) {
		if was, ok := strings.CutPrefix(strings.TrimSpace(line), strings.TrimSpace(resolvWasPrefix)); ok {
			if was = strings.TrimSpace(was); strings.HasSuffix(was, resolvedStub) {
				switchLink(s.Paths.ResolvConf, was)
			}
		}
	}
	s.Run(ctx, systemctl, "restart", resolvedUnit)
}

// canLookUp reports whether the device itself can look up a name, given a
// few seconds for systemd-resolved to be back.
func (s *System) canLookUp(ctx context.Context) bool {
	for range 6 {
		if _, err := s.Run(ctx, getent, "ahosts", lookupProbe); err == nil {
			return true
		}
		s.Sleep(time.Second)
	}
	return false
}

// portHolder names what is listening on the DNS port, or returns "".
func (s *System) portHolder(ctx context.Context) string {
	output, err := s.Run(ctx, ssProgram, "-H", "-lntup", "sport", "=", fmt.Sprint(DNSPort))
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(output)) {
		if _, process, ok := strings.Cut(line, `users:(("`); ok {
			name, _, _ := strings.Cut(process, `"`)
			return name
		}
		if strings.TrimSpace(line) != "" {
			return "an unnamed program"
		}
	}
	return ""
}

// unpack takes the one program out of the release archive. Nothing else in
// the archive is looked at, and nothing is written outside dir.
func (s *System) unpack(archivePath, dir string) error {
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
		if header.Name != archiveEntry || header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size <= 0 || header.Size > maxProgram {
			return errors.New("the program in the release has an impossible size")
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		target := filepath.Join(dir, "AdGuardHome")
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

// prepareAccountAndData makes sure the service's account and folder exist
// and that there is a settings file: the one from a restored export if the
// web process handed one over, otherwise SGC's initial one. An existing
// settings file is never touched.
func (s *System) prepareAccountAndData(ctx context.Context) error {
	if _, err := s.Run(ctx, "/usr/bin/id", "-u", ServiceUser); err != nil {
		if output, err := s.Run(ctx, useradd, "--system", "--home-dir", s.Paths.DataDir, "--no-create-home",
			"--shell", "/usr/sbin/nologin", ServiceUser); err != nil {
			return fmt.Errorf("create the account for AdGuard Home: %s", lastLine(output, err))
		}
	}
	if err := os.MkdirAll(s.Paths.DataDir, 0o700); err != nil {
		return err
	}
	if err := s.Chown(s.Paths.DataDir); err != nil {
		return err
	}
	settings := s.Paths.SettingsFile()
	if _, err := os.Lstat(settings); err == nil {
		return nil
	}
	content := []byte(InitialSettings)
	if restored, err := readLimited(s.Paths.RestoredSettings(), maxSettings); err == nil && len(restored) > 0 {
		content = restored
		s.Log.Info("using the settings from the restored export")
	}
	if err := os.WriteFile(settings, content, 0o600); err != nil {
		return err
	}
	return s.Chown(settings)
}

// chownAll gives the data folder and everything in it to the service's account.
func (s *System) chownAll() error {
	return filepath.WalkDir(s.Paths.DataDir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return s.Chown(path)
	})
}

// switchLink points "current" at a version, in one step.
func switchLink(link, version string) error {
	temporary := link + ".new"
	os.Remove(temporary)
	if err := os.Symlink(version, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, link)
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than expected", path)
	}
	return data, nil
}

func lastLine(output []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		if runes := []rune(last); len(runes) > 240 {
			last = string(runes[:240]) + "…"
		}
		return last
	}
	return err.Error()
}
