package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/layout"
)

// syncBuffer lets the test read output while the server is still writing to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startServe runs `sgc serve` on a free port and returns the address it
// reports, plus a function that stops it and returns the exit code.
func startServe(t *testing.T, extraArgs ...string) (address string, out *syncBuffer, stop func() int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out = &syncBuffer{}
	done := make(chan int, 1)
	args := append([]string{"serve", "--listen", "127.0.0.1:0", "--state-dir", t.TempDir()}, extraArgs...)
	go func() { done <- run(ctx, args, out, out) }()

	// Safe to call more than once: tests stop the server themselves to look
	// at the result, and the cleanup below stops it again in any case.
	var once sync.Once
	exitCode := -1
	stop = func() int {
		once.Do(func() {
			cancel()
			select {
			case exitCode = <-done:
			case <-time.After(10 * time.Second):
				t.Error("serve did not stop after being asked to")
			}
		})
		return exitCode
	}
	t.Cleanup(func() { stop() })

	listening := regexp.MustCompile(`listening on (\S+)`)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m := listening.FindStringSubmatch(out.String()); m != nil {
			return m[1], out, stop
		}
		select {
		case code := <-done:
			t.Fatalf("serve exited early with code %d:\n%s", code, out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("serve did not start listening:\n%s", out.String())
	return "", nil, nil
}

func TestServeAnswersOverTLSAndStopsCleanly(t *testing.T) {
	address, out, stop := startServe(t)

	// The certificate is self-signed, which is exactly what this test expects.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get("https://" + address + "/api/state")
	if err != nil {
		t.Fatalf("request over TLS: %v", err)
	}
	var state struct{ SetupRequired bool }
	json.NewDecoder(resp.Body).Decode(&state)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !state.SetupRequired {
		t.Errorf("status %d, setupRequired %v; a fresh install should ask for setup", resp.StatusCode, state.SetupRequired)
	}

	// Plain http must not be answered on the same port.
	plain, err := http.Get("http://" + address + "/api/state")
	if err == nil {
		plain.Body.Close()
		if plain.StatusCode == http.StatusOK {
			t.Error("the API answered over plain http")
		}
	}

	if code := stop(); code != exitOK {
		t.Errorf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(out.String(), "sgc stopping") {
		t.Errorf("output %q does not mention stopping", out.String())
	}
}

func TestServeKeepsItsFilesPrivate(t *testing.T) {
	stateDir := t.TempDir()
	_, _, stop := startServe(t, "--state-dir", stateDir)
	stop()

	for _, name := range []string{layout.DatabaseFile, filepath.Join("tls", "selfsigned-key.pem")} {
		info, err := os.Stat(filepath.Join(stateDir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has permissions %o; it must not be readable by other users", name, perm)
		}
	}
}

func TestDevelopmentModeOnlyListensOnThisMachine(t *testing.T) {
	// Asked to listen everywhere, development mode must still bind to loopback.
	address, _, _ := startServe(t, "--dev-insecure-http", "--listen", "0.0.0.0:0")

	if !strings.HasPrefix(address, "127.0.0.1:") {
		t.Fatalf("development mode is listening on %s, want 127.0.0.1 only", address)
	}
	resp, err := http.Get("http://" + address + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}
