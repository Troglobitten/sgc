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
//	POST /v1/start-update    install an already downloaded SGC version
package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/release"
)

type pingResponse struct {
	Version string `json:"version"`
}

type startUpdateRequest struct {
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
	if err := c.call(ctx, http.MethodGet, "/v1/ping", nil, &resp); err != nil {
		return "", err
	}
	return resp.Version, nil
}

// RestartDevice asks for a clean restart of the machine. It returns once the
// restart has been scheduled, shortly before the machine goes down.
func (c *Client) RestartDevice(ctx context.Context) error {
	return c.call(ctx, http.MethodPost, "/v1/restart-device", nil, nil)
}

// StartUpdate asks for the given, already downloaded, version to be
// installed. It returns once the update has been started; the update then
// runs on its own and restarts SGC.
func (c *Client) StartUpdate(ctx context.Context, version string) error {
	return c.call(ctx, http.MethodPost, "/v1/start-update", startUpdateRequest{Version: version}, nil)
}

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body *bytes.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	} else {
		body = bytes.NewReader(nil)
	}
	// The host part is ignored: the transport always dials the socket.
	req, err := http.NewRequestWithContext(ctx, method, "http://helper"+path, body)
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
	// StartUpdate starts the installation of a version. It is only ever
	// called with a string that is a plain version number.
	StartUpdate func(version string) error
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
	mux.HandleFunc("POST /v1/start-update", func(w http.ResponseWriter, r *http.Request) {
		var req startUpdateRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "the request could not be read"})
			return
		}
		// The version becomes part of a systemd unit name. Only a plain
		// version number gets through, written back in canonical form.
		version, err := release.ParseVersion(req.Version)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
			return
		}
		if err := s.StartUpdate(version.String()); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not start the update: " + err.Error()})
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
