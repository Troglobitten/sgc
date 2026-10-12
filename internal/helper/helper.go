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
//	GET  /v1/ping              is the helper there, and which version?
//	POST /v1/restart-device    restart the machine cleanly
//	POST /v1/start-update      install an already downloaded SGC version
//	POST /v1/install-packages  install the Debian packages SGC needs (a fixed list)
//	POST /v1/firewall/change   put firewall rules into effect, pending confirmation
//	POST /v1/firewall/confirm  keep the pending firewall rules
//	POST /v1/firewall/undo     go back to the confirmed firewall rules now
//	GET  /v1/ssh/status        the SSH server's settings, accounts and recent key logins
//	POST /v1/ssh/change        put SSH keys and settings into effect
//	POST /v1/ssh/undo          go back to the confirmed SSH keys and settings now
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

	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/release"
	"github.com/Troglobitten/sgc/internal/sshd"
)

// How long each kind of request may take. Most are answered at once; a few
// wait for real work to finish.
const (
	defaultTimeout = 10 * time.Second
	// A firewall change is answered once the new rules are in effect.
	firewallTimeout = 45 * time.Second
	// An SSH change is answered once the SSH server has taken it up.
	sshTimeout = 75 * time.Second
	// The largest SSH request: a few dozen public keys.
	maxSSHRequest = 64 * 1024
	// Installing a package includes downloading it, on any line and any disk.
	// (Shorter than the web server allows such a request, longer than the
	// unit that does the work may run, so each layer reports its own limit.)
	packagesTimeout = 14 * time.Minute
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
	// No time limit here: each request sets its own (see call).
	return &Client{http: &http.Client{
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
	if err := c.call(ctx, defaultTimeout, http.MethodGet, "/v1/ping", nil, &resp); err != nil {
		return "", err
	}
	return resp.Version, nil
}

// RestartDevice asks for a clean restart of the machine. It returns once the
// restart has been scheduled, shortly before the machine goes down.
func (c *Client) RestartDevice(ctx context.Context) error {
	return c.call(ctx, defaultTimeout, http.MethodPost, "/v1/restart-device", nil, nil)
}

// StartUpdate asks for the given, already downloaded, version to be
// installed. It returns once the update has been started; the update then
// runs on its own and restarts SGC.
func (c *Client) StartUpdate(ctx context.Context, version string) error {
	return c.call(ctx, defaultTimeout, http.MethodPost, "/v1/start-update", startUpdateRequest{Version: version}, nil)
}

// InstallPackages installs the Debian packages SGC needs and that a clean
// machine does not have. Which ones is the helper's business; the caller
// cannot name any. It returns when they are installed.
func (c *Client) InstallPackages(ctx context.Context) error {
	return c.call(ctx, packagesTimeout, http.MethodPost, "/v1/install-packages", nil, nil)
}

// FirewallChange puts the requested firewall rules into effect. It returns
// once they are; from then on they wait for FirewallConfirm and are undone
// without it (see internal/firewall).
func (c *Client) FirewallChange(ctx context.Context, request firewall.Request) error {
	return c.call(ctx, firewallTimeout, http.MethodPost, "/v1/firewall/change", request, nil)
}

// FirewallConfirm keeps the pending firewall rules.
func (c *Client) FirewallConfirm(ctx context.Context) error {
	return c.call(ctx, firewallTimeout, http.MethodPost, "/v1/firewall/confirm", nil, nil)
}

// FirewallUndo goes back to the confirmed firewall rules without waiting
// for the confirmation time to run out.
func (c *Client) FirewallUndo(ctx context.Context) error {
	return c.call(ctx, firewallTimeout, http.MethodPost, "/v1/firewall/undo", nil, nil)
}

// SSHStatus asks what the SSH server's settings amount to, which accounts
// can log in, and which of them logged in with a key lately.
func (c *Client) SSHStatus(ctx context.Context) (sshd.Status, error) {
	var status sshd.Status
	err := c.call(ctx, firewallTimeout, http.MethodGet, "/v1/ssh/status", nil, &status)
	return status, err
}

// SSHChange puts keys and settings for the SSH server into effect. It
// returns once they are. A change that takes away a way of logging in then
// waits for a login with a key and is undone without one (internal/sshd).
func (c *Client) SSHChange(ctx context.Context, cfg sshd.Config) error {
	return c.call(ctx, sshTimeout, http.MethodPost, "/v1/ssh/change", cfg, nil)
}

// SSHUndo goes back to the confirmed SSH keys and settings without waiting
// for the time to run out.
func (c *Client) SSHUndo(ctx context.Context) error {
	return c.call(ctx, sshTimeout, http.MethodPost, "/v1/ssh/undo", nil, nil)
}

func (c *Client) call(ctx context.Context, timeout time.Duration, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

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
	// InstallPackages installs SGC's fixed list of Debian packages.
	InstallPackages func() error
	// The firewall operations; see internal/firewall for what they mean.
	FirewallChange  func(request firewall.Request) error
	FirewallConfirm func() error
	FirewallUndo    func() error
	// The SSH operations; see internal/sshd.
	SSHStatus func() (sshd.Status, error)
	SSHChange func(cfg sshd.Config) error
	SSHUndo   func() error
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
	mux.HandleFunc("POST /v1/install-packages", func(w http.ResponseWriter, _ *http.Request) {
		allow(w, packagesTimeout)
		if err := s.InstallPackages(); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not install the packages: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, struct{}{})
	})
	mux.HandleFunc("POST /v1/firewall/change", func(w http.ResponseWriter, r *http.Request) {
		// The request has one yes-or-no field and nothing else gets through,
		// so there is nothing in it that could be turned into a firewall rule.
		var req firewall.Request
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "the request could not be read"})
			return
		}
		allow(w, firewallTimeout)
		if err := s.FirewallChange(req); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not change the firewall: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, struct{}{})
	})
	mux.HandleFunc("POST /v1/firewall/confirm", func(w http.ResponseWriter, _ *http.Request) {
		allow(w, firewallTimeout)
		if err := s.FirewallConfirm(); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not confirm the firewall change: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, struct{}{})
	})
	mux.HandleFunc("POST /v1/firewall/undo", func(w http.ResponseWriter, _ *http.Request) {
		allow(w, firewallTimeout)
		if err := s.FirewallUndo(); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not undo the firewall change: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, struct{}{})
	})

	mux.HandleFunc("GET /v1/ssh/status", func(w http.ResponseWriter, _ *http.Request) {
		status, err := s.SSHStatus()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not read the SSH server's state: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, status)
	})
	mux.HandleFunc("POST /v1/ssh/change", func(w http.ResponseWriter, r *http.Request) {
		// Only the shape is checked here: an account name, a list of keys
		// and one switch, nothing else. Whether the account exists and the
		// keys are keys is checked by the unit that uses them, which is the
		// one that has to be sure.
		var cfg sshd.Config
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSSHRequest))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "the request could not be read"})
			return
		}
		allow(w, sshTimeout)
		if err := s.SSHChange(cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not change SSH: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, struct{}{})
	})
	mux.HandleFunc("POST /v1/ssh/undo", func(w http.ResponseWriter, _ *http.Request) {
		allow(w, sshTimeout)
		if err := s.SSHUndo(); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not undo the SSH change: " + err.Error()})
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

// allow gives a request that waits for real work more time to be answered
// than the server's general limit.
func allow(w http.ResponseWriter, d time.Duration) {
	// Not every writer supports it (tests); the general limit then applies.
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
