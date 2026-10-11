// Package web is SGC's HTTP interface: the JSON API under /api/ and the
// browser UI on every other path.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/health"
	"github.com/Troglobitten/sgc/internal/release"
	"github.com/Troglobitten/sgc/internal/update"
	"github.com/Troglobitten/sgc/internal/updater"
)

// maxRequestBody bounds what a client can make the server read. Every API
// request is a small JSON object.
const maxRequestBody = 64 * 1024

// Helper is what the web process may ask the root helper to do.
type Helper interface {
	RestartDevice(ctx context.Context) error
	StartUpdate(ctx context.Context, version string) error
}

// Updates is what the web process knows and can do about newer SGC versions.
type Updates interface {
	Status(ctx context.Context) (update.Status, error)
	Check(ctx context.Context) (update.Status, error)
	Fetch(ctx context.Context, version string) error
	SetAutoCheck(ctx context.Context, enabled bool) error
}

type Server struct {
	Auth    *auth.Service
	Audit   *audit.Log
	Health  *health.Monitor
	Helper  Helper
	Updates Updates
	// LastUpdate returns the outcome of the most recent update attempt, or
	// nil if there never was one.
	LastUpdate func() (*updater.Status, error)
	Version    string
	// UI holds the built browser interface (index.html, assets/...).
	UI fs.FS
	// InsecureCookies is for local development over plain http only. It
	// drops the cookie attributes that require HTTPS.
	InsecureCookies bool
	Log             *slog.Logger
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.requireSession(s.handleLogout))
	mux.HandleFunc("GET /api/health", s.requireSession(s.handleHealth))
	mux.HandleFunc("GET /api/audit", s.requireSession(s.handleAudit))
	mux.HandleFunc("POST /api/device/restart", s.requireSession(s.handleRestart))
	mux.HandleFunc("GET /api/update", s.requireSession(s.handleUpdateStatus))
	mux.HandleFunc("POST /api/update/check", s.requireSession(s.handleUpdateCheck))
	mux.HandleFunc("POST /api/update/settings", s.requireSession(s.handleUpdateSettings))
	mux.HandleFunc("POST /api/update/install", s.requireSession(s.handleUpdateInstall))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "no such API endpoint")
	})
	mux.Handle("/", s.uiHandler())

	// Rejects state-changing requests that a browser sends on behalf of
	// another website (cross-site request forgery). Requests from tools like
	// curl carry no browser origin headers and pass.
	crossOrigin := http.NewCrossOriginProtection()

	return securityHeaders(crossOrigin.Handler(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// The UI loads only its own files: no inline scripts, no other sites,
		// and it may not be embedded in a frame (clickjacking). Inline styles
		// are allowed because the dialog component injects a small style
		// element; scripts stay strictly limited to SGC's own files.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// --- Sessions ---------------------------------------------------------------

type sessionKey struct{}

func (s *Server) cookieName() string {
	if s.InsecureCookies {
		return "sgc_session_dev"
	}
	// The __Host- prefix makes browsers refuse the cookie unless it is
	// HTTPS-only and bound to exactly this host, so no other site or
	// subdomain can set or overwrite it.
	return "__Host-sgc_session"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, session *auth.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    session.Token,
		Path:     "/",
		Expires:  session.Expires,
		HttpOnly: true, // not readable by scripts in the page
		Secure:   !s.InsecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !s.InsecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) currentSession(r *http.Request) (*auth.Session, error) {
	cookie, err := r.Cookie(s.cookieName())
	if err != nil {
		return nil, nil
	}
	return s.Auth.Authenticate(r.Context(), cookie.Value)
}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := s.currentSession(r)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if session == nil {
			writeError(w, http.StatusUnauthorized, "sign in first")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session)))
	}
}

func sessionFrom(r *http.Request) *auth.Session {
	return r.Context().Value(sessionKey{}).(*auth.Session)
}

// --- Handlers ---------------------------------------------------------------

type stateResponse struct {
	Version       string `json:"version"`
	SetupRequired bool   `json:"setupRequired"`
	SignedIn      bool   `json:"signedIn"`
	Username      string `json:"username,omitempty"`
	MinPassword   int    `json:"minPasswordLength"`
}

// handleState tells the UI which screen to show. It is the only endpoint
// that answers without a session, and it reveals nothing beyond that.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	setupRequired, err := s.Auth.SetupRequired(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	resp := stateResponse{Version: s.Version, SetupRequired: setupRequired, MinPassword: auth.MinPasswordLength}
	if session, err := s.currentSession(r); err != nil {
		s.internalError(w, r, err)
		return
	} else if session != nil {
		resp.SignedIn, resp.Username = true, session.Username
	}
	writeJSON(w, http.StatusOK, resp)
}

type setupRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if !readJSON(w, r, &req) {
		return
	}
	addr := remoteIP(r)

	err := s.Auth.CompleteSetup(r.Context(), req.Token, req.Username, req.Password, addr)
	if err != nil {
		s.authError(w, r, err)
		return
	}
	s.record(r, req.Username, audit.ActionSetupCompleted, "admin account created")

	// Sign the new admin in straight away.
	session, err := s.Auth.Login(r.Context(), req.Username, req.Password, addr, r.UserAgent())
	if err != nil {
		s.authError(w, r, err)
		return
	}
	s.record(r, session.Username, audit.ActionLogin, "")
	s.setSessionCookie(w, session)
	writeJSON(w, http.StatusOK, struct{}{})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !readJSON(w, r, &req) {
		return
	}
	session, err := s.Auth.Login(r.Context(), req.Username, req.Password, remoteIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			// The attempted username is recorded, never the password.
			s.record(r, "-", audit.ActionLoginFailed, "username tried: "+truncate(req.Username, 64))
		}
		s.authError(w, r, err)
		return
	}
	s.record(r, session.Username, audit.ActionLogin, "")
	s.setSessionCookie(w, session)
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	if err := s.Auth.Logout(r.Context(), session.Token); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.record(r, session.Username, audit.ActionLogout, "")
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Health.Snapshot())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.Audit.Recent(r.Context(), 20)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

type restartRequest struct {
	Confirm bool `json:"confirm"`
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	var req restartRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "restarting the device needs confirmation")
		return
	}
	// Recorded before the restart: afterwards there may be nobody left to
	// write it. If the restart then fails, a second entry says so.
	username := sessionFrom(r).Username
	s.record(r, username, audit.ActionDeviceRestart, "")
	if err := s.Helper.RestartDevice(r.Context()); err != nil {
		s.Log.Error("restart device", "error", err)
		s.record(r, username, audit.ActionDeviceRestartFailed, "")
		writeError(w, http.StatusBadGateway, "The device could not be restarted. Details are in the SGC log.")
		return
	}
	writeJSON(w, http.StatusAccepted, struct{}{})
}

// --- Updates ----------------------------------------------------------------

type updateResponse struct {
	update.Status
	// LastUpdate is the outcome of the most recent update attempt, if any.
	LastUpdate *updater.Status `json:"lastUpdate"`
}

func (s *Server) writeUpdateStatus(w http.ResponseWriter, r *http.Request, status update.Status) {
	last, err := s.LastUpdate()
	if err != nil {
		// The dashboard is still useful without it.
		s.Log.Error("read last update outcome", "error", err)
	}
	writeJSON(w, http.StatusOK, updateResponse{Status: status, LastUpdate: last})
}

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Updates.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeUpdateStatus(w, r, status)
}

// handleUpdateCheck asks the update source right now. A check that fails is
// not an error of this request: the answer says why, and when.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	status, err := s.Updates.Check(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeUpdateStatus(w, r, status)
}

type updateSettingsRequest struct {
	AutoCheck bool `json:"autoCheck"`
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSettingsRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Updates.SetAutoCheck(r.Context(), req.AutoCheck); err != nil {
		s.internalError(w, r, err)
		return
	}
	detail := "daily check for updates switched off"
	if req.AutoCheck {
		detail = "daily check for updates switched on"
	}
	s.record(r, sessionFrom(r).Username, audit.ActionSettingChanged, detail)
	s.handleUpdateStatus(w, r)
}

type updateInstallRequest struct {
	Version string `json:"version"`
	Confirm bool   `json:"confirm"`
}

// handleUpdateInstall downloads and verifies the newest version, then hands
// it to the root updater. It answers once the update has started; from then
// on SGC restarts and the browser follows progress through /api/update.
func (s *Server) handleUpdateInstall(w http.ResponseWriter, r *http.Request) {
	var req updateInstallRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "updating needs confirmation")
		return
	}
	version, err := release.ParseVersion(req.Version)
	if err != nil {
		writeError(w, http.StatusBadRequest, sentence(err))
		return
	}

	// The download can take a while on a slow line; the usual time limit
	// for answering a request is too short for it.
	deadline := time.Now().Add(15 * time.Minute)
	controller := http.NewResponseController(w)
	controller.SetReadDeadline(deadline)
	controller.SetWriteDeadline(deadline)

	username := sessionFrom(r).Username
	s.record(r, username, audit.ActionUpdateStarted, "to "+version.String())

	fail := func(status int, message string, cause error) {
		s.Log.Error("start update", "version", version.String(), "error", cause)
		s.record(r, username, audit.ActionUpdateFailed, "to "+version.String()+": "+message)
		writeError(w, status, message)
	}
	if err := s.Updates.Fetch(r.Context(), version.String()); err != nil {
		switch {
		case errors.Is(err, update.ErrNoUpdate), errors.Is(err, update.ErrNotLatest):
			fail(http.StatusConflict, sentence(err), err)
		case errors.Is(err, release.ErrBadSignature), errors.Is(err, release.ErrBadChecksum), errors.Is(err, release.ErrNotListed):
			fail(http.StatusBadGateway, "The download was refused: "+err.Error()+". Nothing was changed.", err)
		default:
			fail(http.StatusBadGateway, "The update could not be downloaded: "+err.Error()+". Nothing was changed.", err)
		}
		return
	}
	if err := s.Helper.StartUpdate(r.Context(), version.String()); err != nil {
		fail(http.StatusBadGateway, "The update could not be started. Details are in the SGC log. Nothing was changed.", err)
		return
	}
	writeJSON(w, http.StatusAccepted, struct{}{})
}

// --- Browser UI -------------------------------------------------------------

func (s *Server) uiHandler() http.Handler {
	files := http.FileServerFS(s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}

		if _, err := fs.Stat(s.UI, name); err != nil {
			// The UI handles its own page addresses (/setup, /login). Any
			// path that is not a real file gets the app, which then shows
			// the right screen. A missing file with an extension is a
			// genuine 404, so a mistyped asset is not silently "fixed".
			if strings.Contains(name[strings.LastIndex(name, "/")+1:], ".") {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
		}

		if name == "index.html" {
			index, err := fs.ReadFile(s.UI, "index.html")
			if err != nil {
				http.Error(w, "This build of SGC does not include the web interface.", http.StatusServiceUnavailable)
				return
			}
			// Always revalidated, so a browser never runs an old UI against
			// a newer SGC after an update.
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(index)
			return
		}

		if strings.HasPrefix(name, "assets/") {
			// Built files carry a fingerprint of their content in the name,
			// so they can be cached for good.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

// --- Plumbing ---------------------------------------------------------------

func (s *Server) record(r *http.Request, actor, action, detail string) {
	if err := s.Audit.Record(r.Context(), actor, action, detail, remoteIP(r)); err != nil {
		s.Log.Error("write audit log", "action", action, "error", err)
	}
}

// authError turns an error from the auth package into a response the user
// can act on, without leaking internals.
func (s *Server) authError(w http.ResponseWriter, r *http.Request, err error) {
	var locked *auth.TooManyAttemptsError
	switch {
	case errors.As(err, &locked):
		w.Header().Set("Retry-After", strconv.Itoa(int(locked.RetryAfter.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, sentence(err))
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, sentence(err))
	case errors.Is(err, auth.ErrBadSetupToken):
		writeError(w, http.StatusForbidden, sentence(err))
	case errors.Is(err, auth.ErrAlreadySetUp):
		writeError(w, http.StatusConflict, sentence(err))
	case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrPasswordTooLong):
		writeError(w, http.StatusBadRequest, sentence(err))
	default:
		s.internalError(w, r, err)
	}
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	// The details go to the log; the browser gets a message without internals.
	s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "Something went wrong inside SGC. Details are in the SGC log.")
}

// readJSON decodes a small JSON request body into v. On failure it has
// already written the error response and returns false.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "requests must be JSON")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "the request could not be read")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// API answers are live data and may contain private details.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{message})
}

// remoteIP is the address of whoever opened the connection. SGC is reached
// directly at this stage; once it sits behind the proxy this must read the
// proxy's forwarded address instead (and only trust it from the proxy).
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sentence makes an error message presentable: capital first letter, full stop.
func sentence(err error) string {
	msg := err.Error()
	if msg == "" {
		return msg
	}
	msg = strings.ToUpper(msg[:1]) + msg[1:]
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
