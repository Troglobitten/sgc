package helper

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		{http.MethodGet, "/"},
	} {
		if err := client.call(context.Background(), probe.method, probe.path, nil); err == nil {
			t.Errorf("%s %s was accepted", probe.method, probe.path)
		}
	}
}

func TestHelperNotRunningGivesAClearError(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "no-such.sock"))
	if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "reach the SGC helper") {
		t.Errorf("err = %v, want a message that the helper cannot be reached", err)
	}
}
