package adguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/components"
)

// release builds an archive laid out like AdGuard Home's, holding a stand-in
// for the program.
func release(t *testing.T, program string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zipped := gzip.NewWriter(&buf)
	archive := tar.NewWriter(zipped)
	for name, content := range map[string]string{
		"./AdGuardHome/README.md":   "read me",
		"./AdGuardHome/AdGuardHome": program,
		// Something an archive must not be able to place anywhere.
		"../../etc/cron.d/evil": "* * * * * root true",
	} {
		archive.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
		archive.Write([]byte(content))
	}
	archive.Close()
	zipped.Close()
	return buf.Bytes()
}

// device stands in for the machine: systemd, the account, the DNS port.
type device struct {
	t      *testing.T
	system *System
	calls  []string
	dir    string

	hasAccount bool
	running    bool
	// The service stops again right after starting.
	fallsOver bool
	// Who listens on port 53, in the words of "ss".
	portHolder string
	// The program refuses its settings file.
	badSettings bool
	// The device runs systemd-resolved, with its listener on port 53 unless
	// it has been switched off (stubOff).
	resolvedRuns bool
	stubOff      bool
	// Without that listener the device cannot look up names any more.
	lookupsBroken bool
}

func newDevice(t *testing.T, version string) *device {
	t.Helper()
	dir := t.TempDir()
	d := &device{t: t, dir: dir}
	d.system = &System{
		Paths: Paths{
			Root: filepath.Join(dir, "opt"), DataDir: filepath.Join(dir, "data"), SpoolDir: filepath.Join(dir, "spool"),
			ResolvedDropIn: filepath.Join(dir, "etc", "resolved.conf.d", "60-sgc-adguard.conf"), ResolvConf: filepath.Join(dir, "etc", "resolv.conf"),
		},
		Arch:  "arm64",
		Run:   d.run,
		Chown: func(path string) error { return nil },
		Sleep: func(time.Duration) {},
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	os.MkdirAll(d.system.Paths.SpoolDir, 0o700)
	d.offer(version, "program "+version)
	return d
}

// offer makes a release the pinned one and puts its file in the spool, as
// the web process would after downloading it.
func (d *device) offer(version, program string) {
	d.t.Helper()
	data := release(d.t, program)
	sum := sha256.Sum256(data)
	d.system.Component = components.Component{Name: "adguardhome", Version: version, Files: map[string]components.File{
		"arm64": {URL: "https://domain.tld/release.tar.gz", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))},
	}}
	path := filepath.Join(d.system.Paths.SpoolDir, d.system.Component.SpoolName("arm64"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		d.t.Fatal(err)
	}
}

func (d *device) run(_ context.Context, program string, args ...string) ([]byte, error) {
	call := filepath.Base(program) + " " + strings.Join(args, " ")
	switch {
	case program == "/usr/bin/id":
		if d.hasAccount {
			return []byte("999\n"), nil
		}
		return nil, errors.New("exit status 1")
	case program == useradd:
		d.calls = append(d.calls, "useradd "+args[len(args)-1])
		d.hasAccount = true
		return nil, nil
	case program == ssProgram:
		// systemd-resolved holds the port until it has been told not to
		// and restarted.
		if d.resolvedRuns && !d.stubOff {
			return []byte(`udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=400,fd=14))` + "\n"), nil
		}
		return []byte(d.portHolder), nil
	case program == getent:
		if d.lookupsBroken && d.stubOff {
			return nil, errors.New("exit status 2")
		}
		return []byte("192.0.2.10 STREAM deb.debian.org\n"), nil
	case program == systemctl && args[0] == "restart" && args[1] == resolvedUnit:
		d.calls = append(d.calls, "restart systemd-resolved")
		_, err := os.Stat(d.system.Paths.ResolvedDropIn)
		d.stubOff = err == nil
		return nil, nil
	case program == d.system.Paths.Program():
		d.calls = append(d.calls, "check-config")
		if d.badSettings {
			return []byte("[fatal] parsing configuration file: yaml: line 3: did not find expected key\n"), errors.New("exit status 1")
		}
		return nil, nil
	case program == systemctl && args[0] == "is-active":
		if d.running {
			return nil, nil
		}
		return nil, errors.New("exit status 3")
	case program == systemctl:
		d.calls = append(d.calls, "systemctl "+args[0])
		switch args[0] {
		case "restart":
			d.running = !d.fallsOver
		case "disable":
			d.running = false
		}
		return nil, nil
	}
	d.t.Errorf("unexpected program: %s", call)
	return nil, errors.New("unexpected")
}

func (d *device) programOnDisk() string {
	data, _ := os.ReadFile(d.system.Paths.Program())
	return string(data)
}

func (d *device) settingsOnDisk() string {
	data, _ := os.ReadFile(d.system.Paths.SettingsFile())
	return string(data)
}

func TestInstall(t *testing.T) {
	d := newDevice(t, "0.107.79")
	if Installed(d.system.Paths) || d.system.Status(context.Background()).Installed {
		t.Fatal("installed before anything was done")
	}
	if err := d.system.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := d.system.Status(context.Background())
	if !status.Installed || status.Version != "0.107.79" || !status.Running {
		t.Fatalf("status: %+v", status)
	}
	if d.programOnDisk() != "program 0.107.79" {
		t.Errorf("the program on disk: %q", d.programOnDisk())
	}
	if info, _ := os.Stat(d.system.Paths.Program()); info.Mode().Perm() != 0o755 {
		t.Errorf("the program's permissions: %v", info.Mode().Perm())
	}
	// Only the program came out of the archive.
	var files []string
	filepath.WalkDir(d.dir, func(path string, entry os.DirEntry, _ error) error {
		if !entry.IsDir() {
			rel, _ := filepath.Rel(d.dir, path)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	want := "data/AdGuardHome.yaml opt/0.107.79/AdGuardHome opt/current spool/adguardhome-0.107.79-arm64.tar.gz"
	if got := strings.Join(files, " "); got != want {
		t.Errorf("files on the device: %s", got)
	}
	if d.settingsOnDisk() != InitialSettings {
		t.Errorf("the settings file:\n%s", d.settingsOnDisk())
	}
	if got := strings.Join(d.calls, ", "); got != "useradd sgc-adguard, check-config, systemctl enable, systemctl restart" {
		t.Errorf("what was run: %s", got)
	}
	// The owner's decisions are in the first settings.
	for _, line := range []string{"address: 127.0.0.1:3000", "users: []", "https://dns.quad9.net/dns-query", "enable_dnssec: true", "interval: 7d", "filter_1.txt"} {
		if !strings.Contains(InitialSettings, line) {
			t.Errorf("the initial settings lack %q", line)
		}
	}
}

func TestInstallRefusesAnythingButThePinnedFile(t *testing.T) {
	d := newDevice(t, "0.107.79")
	spooled := filepath.Join(d.system.Paths.SpoolDir, d.system.Component.SpoolName("arm64"))
	// The web process hands over something else.
	os.WriteFile(spooled, release(t, "another program"), 0o600)
	err := d.system.Install(context.Background())
	if !errors.Is(err, components.ErrWrongFile) {
		t.Fatalf("a different file: %v", err)
	}
	os.Remove(spooled)
	if err := d.system.Install(context.Background()); err == nil {
		t.Fatal("installed without a file")
	}
	d.system.Arch = "riscv64"
	if err := d.system.Install(context.Background()); !errors.Is(err, components.ErrNoFile) {
		t.Fatalf("an unknown processor type: %v", err)
	}
	if Installed(d.system.Paths) || len(d.calls) != 0 {
		t.Errorf("something was done: installed %v, calls %v", Installed(d.system.Paths), d.calls)
	}
}

func TestInstallLeavesTheDeviceAsItWasWhenItFails(t *testing.T) {
	ctx := context.Background()

	// Something else answers DNS already.
	d := newDevice(t, "0.107.79")
	d.portHolder = `udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=400,fd=14))` + "\n"
	err := d.system.Install(ctx)
	if err == nil || !strings.Contains(err.Error(), "dnsmasq") || Installed(d.system.Paths) {
		t.Fatalf("with port 53 taken: %v, installed %v", err, Installed(d.system.Paths))
	}

	// It starts and falls over.
	d = newDevice(t, "0.107.79")
	d.fallsOver = true
	if err := d.system.Install(ctx); err == nil || !strings.Contains(err.Error(), "stopped again") {
		t.Fatalf("a service that falls over: %v", err)
	}
	if Installed(d.system.Paths) {
		t.Error("a failed first installation was left in place")
	}
	if !strings.Contains(strings.Join(d.calls, ", "), "systemctl disable") {
		t.Errorf("it was not switched off again: %v", d.calls)
	}

	// The program refuses its settings.
	d = newDevice(t, "0.107.79")
	d.badSettings = true
	if err := d.system.Install(ctx); err == nil || !strings.Contains(err.Error(), "does not accept its settings") || Installed(d.system.Paths) {
		t.Fatalf("refused settings: %v, installed %v", err, Installed(d.system.Paths))
	}
}

// A Debian with systemd-resolved: its listener on port 53 has to go, the
// device must still be able to look up names afterwards, and removing
// AdGuard Home puts everything back.
func TestSystemdResolvedStepsAside(t *testing.T) {
	ctx := context.Background()
	d := newDevice(t, "0.107.79")
	d.resolvedRuns = true
	resolv := d.system.Paths.ResolvConf
	os.MkdirAll(filepath.Dir(resolv), 0o755)
	os.Symlink("../run/systemd/resolve/stub-resolv.conf", resolv)
	link := func() string { target, _ := os.Readlink(resolv); return target }

	if err := d.system.Install(ctx); err != nil {
		t.Fatal(err)
	}
	dropIn, _ := os.ReadFile(d.system.Paths.ResolvedDropIn)
	if !strings.Contains(string(dropIn), "[Resolve]\nDNSStubListener=no\n") {
		t.Errorf("systemd-resolved's settings file:\n%s", dropIn)
	}
	if link() != resolvedDirect {
		t.Errorf("resolv.conf points at %q", link())
	}
	if !strings.HasPrefix(strings.Join(d.calls, ", "), "restart systemd-resolved, useradd") {
		t.Errorf("what was run: %v", d.calls)
	}

	if err := d.system.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.system.Paths.ResolvedDropIn); !errors.Is(err, os.ErrNotExist) {
		t.Error("systemd-resolved's settings file was left behind")
	}
	if link() != "../run/systemd/resolve/stub-resolv.conf" || d.stubOff {
		t.Errorf("after removal: resolv.conf points at %q, listener off: %v", link(), d.stubOff)
	}

	// The device cannot look up names without the listener: nothing is
	// installed and everything is as before.
	d = newDevice(t, "0.107.79")
	d.resolvedRuns, d.lookupsBroken = true, true
	resolv = d.system.Paths.ResolvConf
	os.MkdirAll(filepath.Dir(resolv), 0o755)
	os.Symlink("../run/systemd/resolve/stub-resolv.conf", resolv)
	err := d.system.Install(ctx)
	if err == nil || !strings.Contains(err.Error(), "could no longer look up names") {
		t.Fatalf("with lookups broken: %v", err)
	}
	if Installed(d.system.Paths) || d.stubOff || link() != "../run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("not put back: installed %v, listener off %v, resolv.conf -> %q", Installed(d.system.Paths), d.stubOff, link())
	}
	if _, statErr := os.Stat(d.system.Paths.ResolvedDropIn); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("systemd-resolved's settings file was left behind")
	}

	// An installation that fails later gives the port back as well.
	d = newDevice(t, "0.107.79")
	d.resolvedRuns, d.fallsOver = true, true
	if err := d.system.Install(ctx); err == nil {
		t.Fatal("a service that falls over was installed")
	}
	if d.stubOff {
		t.Error("systemd-resolved did not get its listener back after a failed installation")
	}
}

func TestANewerReleaseReplacesTheInstalledOne(t *testing.T) {
	ctx := context.Background()
	d := newDevice(t, "0.107.79")
	if err := d.system.Install(ctx); err != nil {
		t.Fatal(err)
	}
	// The owner's settings, made in AdGuard Home's page since.
	os.WriteFile(d.system.Paths.SettingsFile(), []byte("the owner's settings\n"), 0o600)
	// With AdGuard Home on the port, the port is of course taken.
	d.portHolder = `udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("AdGuardHome",pid=500,fd=9))` + "\n"

	// A newer one that does not stay up: back to the old one.
	d.offer("0.107.80", "program 0.107.80")
	d.fallsOver = true
	if err := d.system.Install(ctx); err == nil {
		t.Fatal("a release that falls over was installed")
	}
	if InstalledVersion(d.system.Paths) != "0.107.79" || d.programOnDisk() != "program 0.107.79" {
		t.Fatalf("after the failed replacement: version %q, program %q", InstalledVersion(d.system.Paths), d.programOnDisk())
	}
	if last := d.calls[len(d.calls)-1]; last != "systemctl restart" {
		t.Errorf("the old version was not started again: %v", d.calls)
	}

	d.fallsOver = false
	if err := d.system.Install(ctx); err != nil {
		t.Fatal(err)
	}
	if InstalledVersion(d.system.Paths) != "0.107.80" || d.programOnDisk() != "program 0.107.80" {
		t.Errorf("after the replacement: version %q, program %q", InstalledVersion(d.system.Paths), d.programOnDisk())
	}
	if _, err := os.Stat(filepath.Join(d.system.Paths.Root, "0.107.79")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the replaced version was left behind")
	}
	if d.settingsOnDisk() != "the owner's settings\n" {
		t.Errorf("the owner's settings were touched: %q", d.settingsOnDisk())
	}
}

func TestSettingsFromARestoredExportAndRemoval(t *testing.T) {
	ctx := context.Background()
	d := newDevice(t, "0.107.79")
	os.WriteFile(d.system.Paths.RestoredSettings(), []byte("settings from the old device\n"), 0o600)
	if err := d.system.Install(ctx); err != nil {
		t.Fatal(err)
	}
	if d.settingsOnDisk() != "settings from the old device\n" {
		t.Errorf("the settings in use: %q", d.settingsOnDisk())
	}
	if _, err := os.Stat(d.system.Paths.RestoredSettings()); !errors.Is(err, os.ErrNotExist) {
		t.Error("the handed-over settings were left in the spool")
	}
	if got, err := d.system.ReadSettings(); err != nil || string(got) != "settings from the old device\n" {
		t.Errorf("ReadSettings: %q, %v", got, err)
	}

	// Removed: the program goes, the settings stay for a next time.
	if err := d.system.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if Installed(d.system.Paths) || d.system.Status(ctx).Running {
		t.Error("still installed or running after removal")
	}
	if d.settingsOnDisk() != "settings from the old device\n" {
		t.Error("the settings were removed with the program")
	}
	// Installed again, with settings handed over once more: the ones on the
	// device win.
	os.WriteFile(d.system.Paths.RestoredSettings(), []byte("other settings\n"), 0o600)
	d.offer("0.107.79", "program 0.107.79")
	if err := d.system.Install(ctx); err != nil {
		t.Fatal(err)
	}
	if d.settingsOnDisk() != "settings from the old device\n" {
		t.Errorf("existing settings were replaced: %q", d.settingsOnDisk())
	}
}
