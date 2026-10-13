package helper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/log2ram"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/sshd"
	"github.com/Troglobitten/sgc/internal/sshkeys"
)

// startHelper runs a helper on a socket in a temporary folder and returns a
// client connected to it.
func startHelper(t *testing.T, s *Server) *Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: s.Handler(), ConnContext: ConnContext}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return NewClient(socket)
}

func TestAllowedUserCanPingAndRestart(t *testing.T) {
	restarts := 0
	client := startHelper(t, &Server{
		AllowedUID: uint32(os.Getuid()),
		Version:    "1.2.3",
		Restart:    func() error { restarts++; return nil },
	})
	ctx := context.Background()

	version, err := client.Ping(ctx)
	if err != nil || version != "1.2.3" {
		t.Errorf("Ping = %q, %v", version, err)
	}
	if err := client.RestartDevice(ctx); err != nil {
		t.Errorf("RestartDevice: %v", err)
	}
	if restarts != 1 {
		t.Errorf("restart ran %d times, want 1", restarts)
	}
}

func TestOtherUsersAreRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always allowed; this test needs an ordinary user")
	}
	restarts := 0
	client := startHelper(t, &Server{
		AllowedUID: uint32(os.Getuid()) + 1, // somebody else
		Version:    "1.2.3",
		Restart:    func() error { restarts++; return nil },
	})
	ctx := context.Background()

	if _, err := client.Ping(ctx); err == nil || !strings.Contains(err.Error(), "may not use") {
		t.Errorf("Ping: err = %v, want a refusal", err)
	}
	if err := client.RestartDevice(ctx); err == nil {
		t.Error("RestartDevice was accepted from a user who is not allowed")
	}
	if restarts != 0 {
		t.Errorf("restart ran %d times for a refused user", restarts)
	}
}

func TestRestartFailureIsReported(t *testing.T) {
	client := startHelper(t, &Server{
		AllowedUID: uint32(os.Getuid()),
		Restart:    func() error { return errors.New("systemctl said no") },
	})

	err := client.RestartDevice(context.Background())
	if err == nil || !strings.Contains(err.Error(), "systemctl said no") {
		t.Errorf("err = %v, want the underlying reason", err)
	}
}

func TestOnlyListedOperationsExist(t *testing.T) {
	client := startHelper(t, &Server{AllowedUID: uint32(os.Getuid()), Restart: func() error { return nil }})

	// There must be no way to run arbitrary commands, and the restart must
	// not be reachable with a method that browsers send without asking.
	for _, probe := range []struct{ method, path string }{
		{http.MethodPost, "/v1/exec"},
		{http.MethodGet, "/v1/restart-device"},
		{http.MethodGet, "/v1/install-packages"},
		{http.MethodGet, "/v1/firewall/change"},
		{http.MethodGet, "/v1/firewall/confirm"},
		{http.MethodGet, "/v1/firewall/undo"},
		{http.MethodPost, "/v1/firewall/off"},
		{http.MethodGet, "/v1/ssh/change"},
		{http.MethodGet, "/v1/ssh/undo"},
		{http.MethodPost, "/v1/ssh/status"},
		{http.MethodPost, "/v1/ssh/keys"},
		{http.MethodGet, "/"},
	} {
		if err := client.call(context.Background(), defaultTimeout, probe.method, probe.path, nil, nil); err == nil {
			t.Errorf("%s %s was accepted", probe.method, probe.path)
		}
	}
}

func TestStartUpdatePassesOnlyPlainVersions(t *testing.T) {
	var started []string
	client := startHelper(t, &Server{
		AllowedUID:  uint32(os.Getuid()),
		StartUpdate: func(version string) error { started = append(started, version); return nil },
	})
	ctx := context.Background()

	if err := client.StartUpdate(ctx, "0.5.1"); err != nil {
		t.Fatalf("a plain version was refused: %v", err)
	}
	if len(started) != 1 || started[0] != "0.5.1" {
		t.Fatalf("started = %v", started)
	}

	// The version ends up in a systemd unit name. Nothing but a version may
	// reach the function that builds that name.
	for _, bad := range []string{"", "latest", "0.5.1 --now", "0.5.1; reboot", "../../etc/passwd", "0.5.1\n0.5.2", "v0.5.1", "0.5.1-beta"} {
		if err := client.StartUpdate(ctx, bad); err == nil {
			t.Errorf("%q was accepted as a version", bad)
		}
	}
	if len(started) != 1 {
		t.Errorf("an update was started for a refused version: %v", started)
	}
}

func TestStartUpdateFailureIsReported(t *testing.T) {
	client := startHelper(t, &Server{
		AllowedUID:  uint32(os.Getuid()),
		StartUpdate: func(string) error { return errors.New("unit not found") },
	})

	err := client.StartUpdate(context.Background(), "0.5.1")
	if err == nil || !strings.Contains(err.Error(), "unit not found") {
		t.Errorf("err = %v, want the underlying reason", err)
	}
}

func TestFirewallOperations(t *testing.T) {
	var calls []string
	client := startHelper(t, &Server{
		AllowedUID:      uint32(os.Getuid()),
		InstallPackages: func(feature string) error { calls = append(calls, "packages for "+feature); return nil },
		FirewallChange: func(request firewall.Request) error {
			calls = append(calls, fmt.Sprintf("change enabled=%v", request.Enabled))
			return nil
		},
		FirewallConfirm: func() error { calls = append(calls, "confirm"); return nil },
		FirewallUndo:    func() error { calls = append(calls, "undo"); return errors.New("nothing was waiting") },
	})
	ctx := context.Background()

	if err := client.InstallPackages(ctx, PackagesFirewall); err != nil {
		t.Errorf("InstallPackages: %v", err)
	}
	if err := client.FirewallChange(ctx, firewall.Request{Enabled: true}); err != nil {
		t.Errorf("FirewallChange: %v", err)
	}
	if err := client.FirewallChange(ctx, firewall.Request{Enabled: false}); err != nil {
		t.Errorf("FirewallChange: %v", err)
	}
	if err := client.FirewallConfirm(ctx); err != nil {
		t.Errorf("FirewallConfirm: %v", err)
	}
	if err := client.FirewallUndo(ctx); err == nil || !strings.Contains(err.Error(), "nothing was waiting") {
		t.Errorf("FirewallUndo: err = %v, want the underlying reason", err)
	}
	want := "packages for firewall, change enabled=true, change enabled=false, confirm, undo"
	if got := strings.Join(calls, ", "); got != want {
		t.Errorf("calls = %s\nwant    %s", got, want)
	}
}

// A firewall request is one yes-or-no value. Anything else in it would be an
// attempt to say more than the web process is allowed to, and is refused.
func TestFirewallChangeAcceptsNothingButOnOrOff(t *testing.T) {
	changes := 0
	client := startHelper(t, &Server{
		AllowedUID:     uint32(os.Getuid()),
		FirewallChange: func(firewall.Request) error { changes++; return nil },
	})
	for _, body := range []any{
		map[string]any{"enabled": true, "sshPorts": []int{1}},
		map[string]any{"enabled": true, "rules": "accept"},
		map[string]any{"enabled": "yes"},
		[]bool{true},
		"on",
	} {
		if err := client.call(context.Background(), defaultTimeout, http.MethodPost, "/v1/firewall/change", body, nil); err == nil {
			t.Errorf("%v was accepted", body)
		}
	}
	if changes != 0 {
		t.Errorf("the firewall was changed %d times by refused requests", changes)
	}
}

func TestFirewallIsRefusedForOtherUsers(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always allowed; this test needs an ordinary user")
	}
	touched := false
	touch := func() error { touched = true; return nil }
	client := startHelper(t, &Server{
		AllowedUID:      uint32(os.Getuid()) + 1, // somebody else
		InstallPackages: func(string) error { return touch() },
		FirewallChange:  func(firewall.Request) error { return touch() },
		FirewallConfirm: touch,
		FirewallUndo:    touch,
	})
	ctx := context.Background()
	for name, err := range map[string]error{
		"InstallPackages": client.InstallPackages(ctx, PackagesFirewall),
		"FirewallChange":  client.FirewallChange(ctx, firewall.Request{Enabled: false}),
		"FirewallConfirm": client.FirewallConfirm(ctx),
		"FirewallUndo":    client.FirewallUndo(ctx),
	} {
		if err == nil {
			t.Errorf("%s was accepted from a user who is not allowed", name)
		}
	}
	if touched {
		t.Error("an operation ran for a refused user")
	}
}

// What the web process can cause to be installed is two fixed lists, named
// by the feature they are for. There is no way to name a package.
func TestInstallPackagesTakesAFeatureAndNothingElse(t *testing.T) {
	var asked []string
	client := startHelper(t, &Server{
		AllowedUID:      uint32(os.Getuid()),
		InstallPackages: func(feature string) error { asked = append(asked, feature); return nil },
	})
	ctx := context.Background()
	for _, feature := range []string{PackagesFirewall, PackagesUpdates} {
		if err := client.InstallPackages(ctx, feature); err != nil {
			t.Errorf("%s: %v", feature, err)
		}
	}
	for _, body := range []any{
		nil,
		map[string]any{},
		map[string]any{"for": "netcat"},
		map[string]any{"for": ""},
		map[string]any{"for": "firewall", "packages": []string{"netcat"}},
		map[string]any{"for": []string{"firewall"}},
		map[string]any{"packages": []string{"netcat"}},
		"firewall",
	} {
		if err := client.call(ctx, defaultTimeout, http.MethodPost, "/v1/install-packages", body, nil); err == nil {
			t.Errorf("%v was accepted", body)
		}
	}
	if got := strings.Join(asked, ","); got != "firewall,updates" {
		t.Errorf("installations asked for: %s", got)
	}
}

func TestOSUpdateOperations(t *testing.T) {
	var calls []string
	lastRun := time.Date(2026, 10, 12, 6, 30, 0, 0, time.UTC)
	client := startHelper(t, &Server{
		AllowedUID: uint32(os.Getuid()),
		OSUpdateSettings: func() (osupdate.Settings, error) {
			return osupdate.Settings{ToolInstalled: true, Periodic: true, Timers: true, LastRun: &lastRun}, nil
		},
		OSUpdateSetMode: func(request osupdate.ModeRequest) error {
			calls = append(calls, fmt.Sprintf("mode automatic=%v", request.Automatic))
			return nil
		},
		OSUpdateStart: func(job string) (int64, error) {
			calls = append(calls, "start "+job)
			if job == osupdate.JobInstall {
				return 0, errors.New("a look for updates or an installation is already running")
			}
			return 1234, nil
		},
	})
	ctx := context.Background()

	settings, err := client.OSUpdateSettings(ctx)
	if err != nil || !settings.Daily() || settings.LastRun == nil || !settings.LastRun.Equal(lastRun) {
		t.Errorf("OSUpdateSettings = %+v, %v", settings, err)
	}
	if err := client.OSUpdateSetMode(ctx, osupdate.ModeRequest{Automatic: true}); err != nil {
		t.Errorf("OSUpdateSetMode: %v", err)
	}
	if id, err := client.OSUpdateStart(ctx, osupdate.JobCheck); err != nil || id != 1234 {
		t.Errorf("OSUpdateStart: %d, %v", id, err)
	}
	if _, err := client.OSUpdateStart(ctx, osupdate.JobInstall); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("OSUpdateStart while busy: %v, want the underlying reason", err)
	}

	// Neither request has room for a package, an archive or a command.
	for path, bodies := range map[string][]any{
		"/v1/os-updates/mode": {
			map[string]any{"automatic": true, "origins": []string{"origin=*"}},
			map[string]any{"automatic": "yes"},
			map[string]any{"mode": "automatic"},
			"automatic",
		},
		"/v1/os-updates/start": {
			nil,
			map[string]any{"job": "remove"},
			map[string]any{"job": ""},
			map[string]any{"job": "install", "packages": []string{"bash"}},
			map[string]any{"job": "install", "id": 7},
			map[string]any{"job": []string{"install"}},
			"install",
		},
	} {
		for _, body := range bodies {
			if err := client.call(ctx, defaultTimeout, http.MethodPost, path, body, nil); err == nil {
				t.Errorf("%s: %v was accepted", path, body)
			}
		}
	}
	want := "mode automatic=true, start check, start install"
	if got := strings.Join(calls, ", "); got != want {
		t.Errorf("calls = %s\nwant    %s", got, want)
	}
}

func TestOSUpdatesAreRefusedForOtherUsers(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always allowed; this test needs an ordinary user")
	}
	touched := false
	client := startHelper(t, &Server{
		AllowedUID:       uint32(os.Getuid()) + 1, // somebody else
		OSUpdateSettings: func() (osupdate.Settings, error) { touched = true; return osupdate.Settings{}, nil },
		OSUpdateSetMode:  func(osupdate.ModeRequest) error { touched = true; return nil },
		OSUpdateStart:    func(string) (int64, error) { touched = true; return 1, nil },
	})
	ctx := context.Background()
	_, settingsErr := client.OSUpdateSettings(ctx)
	_, startErr := client.OSUpdateStart(ctx, osupdate.JobInstall)
	for name, err := range map[string]error{
		"OSUpdateSettings": settingsErr,
		"OSUpdateSetMode":  client.OSUpdateSetMode(ctx, osupdate.ModeRequest{Automatic: false}),
		"OSUpdateStart":    startErr,
	} {
		if err == nil {
			t.Errorf("%s was accepted from a user who is not allowed", name)
		}
	}
	if touched {
		t.Error("an operation ran for a refused user")
	}
}

func TestSSHOperations(t *testing.T) {
	var changes []sshd.Config
	undone := 0
	client := startHelper(t, &Server{
		AllowedUID: uint32(os.Getuid()),
		SSHStatus: func() (sshd.Status, error) {
			return sshd.Status{Installed: true, Running: true, Accounts: []string{"alex"}, Logins: []sshd.Login{{Account: "alex", Kind: "ED25519"}}}, nil
		},
		SSHChange: func(cfg sshd.Config) error { changes = append(changes, cfg); return nil },
		SSHUndo:   func() error { undone++; return errors.New("nothing was waiting") },
	})
	ctx := context.Background()

	status, err := client.SSHStatus(ctx)
	if err != nil || !status.Installed || len(status.Accounts) != 1 || len(status.Logins) != 1 {
		t.Errorf("SSHStatus = %+v, %v", status, err)
	}
	key := sshkeys.Key{Type: "ssh-ed25519", Blob: "AAAAC3NzaC1lZDI1NTE5AAAAID25i1+d/VGOmeRQ2ZPpnryBGMe/B28pdc623ONJVCV1"}
	if err := client.SSHChange(ctx, sshd.Config{Account: "alex", Keys: []sshkeys.Key{key}, KeysOnly: true}); err != nil {
		t.Errorf("SSHChange: %v", err)
	}
	if len(changes) != 1 || changes[0].Account != "alex" || !changes[0].KeysOnly || len(changes[0].Keys) != 1 || changes[0].Keys[0].Blob != key.Blob {
		t.Errorf("changes = %+v", changes)
	}
	if err := client.SSHUndo(ctx); err == nil || !strings.Contains(err.Error(), "nothing was waiting") || undone != 1 {
		t.Errorf("SSHUndo: err = %v, called %d times", err, undone)
	}

	// The shape of a request is fixed: an account, keys, one switch. There
	// is no place in it for an option, a command or a file name.
	for _, body := range []any{
		map[string]any{"account": "alex", "keysOnly": true, "options": "command=x"},
		map[string]any{"account": "alex", "keys": []map[string]any{{"type": "ssh-ed25519", "blob": key.Blob, "options": "command=x"}}},
		map[string]any{"account": "alex", "keysFile": "/root/.ssh/authorized_keys"},
		map[string]any{"account": []string{"alex"}},
		map[string]any{"keysOnly": "yes"},
		"keys only",
	} {
		if err := client.call(ctx, defaultTimeout, http.MethodPost, "/v1/ssh/change", body, nil); err == nil {
			t.Errorf("%v was accepted", body)
		}
	}
	// A request far larger than any list of keys is cut off, not read.
	huge := map[string]any{"account": "alex", "keys": []map[string]any{{"type": "ssh-ed25519", "blob": strings.Repeat("A", 2*maxSSHRequest)}}}
	if err := client.call(ctx, defaultTimeout, http.MethodPost, "/v1/ssh/change", huge, nil); err == nil {
		t.Error("an oversized request was accepted")
	}
	if len(changes) != 1 {
		t.Errorf("refused requests reached the SSH change: %+v", changes[1:])
	}
}

func TestSSHIsRefusedForOtherUsers(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always allowed; this test needs an ordinary user")
	}
	touched := false
	client := startHelper(t, &Server{
		AllowedUID: uint32(os.Getuid()) + 1, // somebody else
		SSHStatus:  func() (sshd.Status, error) { touched = true; return sshd.Status{}, nil },
		SSHChange:  func(sshd.Config) error { touched = true; return nil },
		SSHUndo:    func() error { touched = true; return nil },
	})
	ctx := context.Background()
	if _, err := client.SSHStatus(ctx); err == nil {
		t.Error("SSHStatus was answered for a user who is not allowed")
	}
	if err := client.SSHChange(ctx, sshd.Config{}); err == nil {
		t.Error("SSHChange was accepted from a user who is not allowed")
	}
	if err := client.SSHUndo(ctx); err == nil {
		t.Error("SSHUndo was accepted from a user who is not allowed")
	}
	if touched {
		t.Error("an operation ran for a refused user")
	}
}

func TestLog2ramOperations(t *testing.T) {
	var asked []bool
	var installed []string
	client := startHelper(t, &Server{
		AllowedUID:    uint32(os.Getuid()),
		Log2ramStatus: func() log2ram.Status { return log2ram.Status{Installed: true, Enabled: true, SizeBytes: 128 << 20} },
		Log2ramSetEnabled: func(enabled bool) error {
			asked = append(asked, enabled)
			if !enabled {
				return errors.New("log2ram could not be taken out of start-up: it did not work")
			}
			return nil
		},
		InstallPackages: func(feature string) error { installed = append(installed, feature); return nil },
	})
	ctx := context.Background()
	status, err := client.Log2ramStatus(ctx)
	if err != nil || !status.Installed || !status.Enabled || status.Active || status.SizeBytes != 128<<20 {
		t.Errorf("status: %+v, %v", status, err)
	}
	if err := client.Log2ramSetEnabled(ctx, true); err != nil {
		t.Errorf("switching on: %v", err)
	}
	// The root side's reason reaches the caller in its own words.
	if err := client.Log2ramSetEnabled(ctx, false); err == nil || !strings.Contains(err.Error(), "it did not work") {
		t.Errorf("a refusal: %v", err)
	}
	if fmt.Sprint(asked) != "[true false]" {
		t.Errorf("asked of the root side: %v", asked)
	}
	// Its packages are one of the features that can be installed, by name.
	if err := client.InstallPackages(ctx, PackagesLog2ram); err != nil || fmt.Sprint(installed) != "[log2ram]" {
		t.Errorf("installing its packages: %v, %v", err, installed)
	}
}

func TestHelperNotRunningGivesAClearError(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "no-such.sock"))
	if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "reach the SGC helper") {
		t.Errorf("err = %v, want a message that the helper cannot be reached", err)
	}
}
