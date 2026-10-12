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

	"github.com/Troglobitten/sgc/internal/firewall"
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
		InstallPackages: func() error { calls = append(calls, "packages"); return nil },
		FirewallChange: func(request firewall.Request) error {
			calls = append(calls, fmt.Sprintf("change enabled=%v", request.Enabled))
			return nil
		},
		FirewallConfirm: func() error { calls = append(calls, "confirm"); return nil },
		FirewallUndo:    func() error { calls = append(calls, "undo"); return errors.New("nothing was waiting") },
	})
	ctx := context.Background()

	if err := client.InstallPackages(ctx); err != nil {
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
	want := "packages, change enabled=true, change enabled=false, confirm, undo"
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
		InstallPackages: touch,
		FirewallChange:  func(firewall.Request) error { return touch() },
		FirewallConfirm: touch,
		FirewallUndo:    touch,
	})
	ctx := context.Background()
	for name, err := range map[string]error{
		"InstallPackages": client.InstallPackages(ctx),
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

func TestHelperNotRunningGivesAClearError(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "no-such.sock"))
	if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "reach the SGC helper") {
		t.Errorf("err = %v, want a message that the helper cannot be reached", err)
	}
}
