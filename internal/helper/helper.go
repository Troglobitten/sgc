// Package helper is the narrow bridge between SGC's unprivileged web process
// and the few things that need root.
//
// The web process is the part exposed to browsers, so it runs without any
// privileges (design principle 6). When something needs root, it asks the
// helper, a separate small program, over a Unix socket. The helper offers a
// fixed list of operations, each with typed, validated parameters. There is
// deliberately no "run this command" operation: a bug in the web process can
// then do no more than the operations listed here.
//
// Operations so far:
//
//	GET  /v1/ping            is the helper there, and which version?
//	POST /v1/restart-device  restart the machine cleanly
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// SocketPath is where systemd creates the helper's socket (sgc-helper.socket).
const SocketPath = "/run/sgc-helper/helper.sock"

type pingResponse struct {
	Version string `json:"version"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- Client (used by the web process) ---------------------------------------

type Client struct {
	http *http.Client
}

func NewClient(socketPath string) *Client {
	return &Client{http: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}}
}

// Ping returns the helper's version.
func (c *Client) Ping(ctx context.Context) (string, error) {
	var resp pingResponse
	if err := c.call(ctx, http.MethodGet, "/v1/ping", &resp); err != nil {
		return "", err
	}
	return resp.Version, nil
}

// RestartDevice asks for a clean restart of the machine. It returns once the
// restart has been scheduled, shortly before the machine goes down.
func (c *Client) RestartDevice(ctx context.Context) error {
	return c.call(ctx, http.MethodPost, "/v1/restart-device", nil)
}

func (c *Client) call(ctx context.Context, method, path string, out any) error {
	// The host part is ignored: the transport always dials the socket.
	req, err := http.NewRequestWithContext(ctx, method, "http://helper"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reach the SGC helper: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var e errorResponse
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return fmt.Errorf("SGC helper: %s", e.Error)
		}
		return fmt.Errorf("SGC helper answered with status %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("read the SGC helper's answer: %w", err)
		}
	}
	return nil
}

// --- Server (the helper itself) ---------------------------------------------

type Server struct {
	// AllowedUID is the service user's ID. Besides root, it is the only user
	// whose requests are accepted.
	AllowedUID uint32
	Version    string
	// Restart performs the restart. Injected so tests do not reboot anything.
	Restart func() error
}

type peerUIDKey struct{}

// ConnContext records who is on the other end of each connection. Set it as
// the http.Server's ConnContext.
//
// The kernel reports the peer's user ID for a Unix socket; the caller cannot
// fake it. File permissions on the socket already keep other users out, and
// this check means a mistake in those permissions is not enough to get in.
func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	uid, err := peerUID(conn)
	if err != nil {
		return ctx // no UID recorded: every request on this connection is refused
	}
	return context.WithValue(ctx, peerUIDKey{}, uid)
}

func peerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ping", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, pingResponse{Version: s.Version})
	})
	mux.HandleFunc("POST /v1/restart-device", func(w http.ResponseWriter, _ *http.Request) {
		if err := s.Restart(); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not restart the device: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, struct{}{})
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(peerUIDKey{}).(uint32)
		if !ok || (uid != 0 && uid != s.AllowedUID) {
			writeJSON(w, http.StatusForbidden, errorResponse{Error: "this user may not use the SGC helper"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
