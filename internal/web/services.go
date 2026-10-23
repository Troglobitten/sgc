package web

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Troglobitten/sgc/internal/announce"
	"github.com/Troglobitten/sgc/internal/proxycontrol"
	"github.com/Troglobitten/sgc/internal/services"
)

// Services is the list of services behind SGC's names (internal/services).
type Services interface {
	List(ctx context.Context) ([]services.Service, error)
	Add(ctx context.Context, actor, remote string, in services.Input) (services.Service, error)
	Update(ctx context.Context, actor, remote string, id int64, in services.Input) (services.Service, error)
	Remove(ctx context.Context, actor, remote string, id int64) error
	Approve(ctx context.Context, actor, remote string, id int64) error
	Icon(ctx context.Context, id int64) ([]byte, error)
	FetchIcon(ctx context.Context, id int64)
	Settings(ctx context.Context) (services.Settings, error)
	SetSettings(ctx context.Context, actor, remote string, s services.Settings) error
}

// Proxy is the owner's switch for the proxy (internal/proxycontrol).
type Proxy interface {
	Status(ctx context.Context) (proxycontrol.Status, error)
	SetEnabled(ctx context.Context, actor, remote string, enabled bool) error
}

// Announcer takes servers' announcements and keeps their tokens
// (internal/announce).
type Announcer interface {
	List(ctx context.Context) ([]announce.Token, error)
	Create(ctx context.Context, actor, remote, label string) (announce.Token, string, error)
	Remove(ctx context.Context, actor, remote string, id int64, keep bool) error
	Repin(ctx context.Context, actor, remote string, id int64) error
	Handle(ctx context.Context, bearer, ip string, form url.Values) ([]services.AnnounceResult, error)
}

type servicesResponse struct {
	Services []services.Service `json:"services"`
	Settings services.Settings  `json:"settings"`
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	list, err := s.Services.List(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	settings, err := s.Services.Settings(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, servicesResponse{Services: list, Settings: settings})
}

func (s *Server) handleServiceAdd(w http.ResponseWriter, r *http.Request) {
	var in services.Input
	if !readJSON(w, r, &in) {
		return
	}
	added, err := s.Services.Add(r.Context(), sessionFrom(r).Username, remoteIP(r), in)
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, added)
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) handleServiceUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such service")
		return
	}
	var in services.Input
	if !readJSON(w, r, &in) {
		return
	}
	updated, err := s.Services.Update(r.Context(), sessionFrom(r).Username, remoteIP(r), id, in)
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleServiceRemove(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such service")
		return
	}
	if err := s.Services.Remove(r.Context(), sessionFrom(r).Username, remoteIP(r), id); err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleServiceApprove(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such service")
		return
	}
	if err := s.Services.Approve(r.Context(), sessionFrom(r).Username, remoteIP(r), id); err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleServiceIconRefresh(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such service")
		return
	}
	s.Services.FetchIcon(r.Context(), id)
	writeJSON(w, http.StatusOK, struct{}{})
}

// handleServiceIcon serves an icon. It is always a PNG SGC drew itself
// (services.Redraw); the headers make sure a browser treats it as nothing
// else.
func (s *Server) handleServiceIcon(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := s.Services.Icon(r.Context(), id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if data == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Write(data)
}

func (s *Server) handleServiceSettings(w http.ResponseWriter, r *http.Request) {
	var req services.Settings
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Services.SetSettings(r.Context(), sessionFrom(r).Username, remoteIP(r), req); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleServices(w, r)
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Proxy.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type enabledRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleProxyEnabled(w http.ResponseWriter, r *http.Request) {
	var req enabledRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "say whether the proxy is to be on or off")
		return
	}
	if err := s.Proxy.SetEnabled(r.Context(), sessionFrom(r).Username, remoteIP(r), *req.Enabled); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleProxyStatus(w, r)
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	list, err := s.Announcer.List(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type tokenRequest struct {
	Label string `json:"label"`
}

type tokenCreated struct {
	Token announce.Token `json:"token"`
	// Secret is the token itself, shown this once.
	Secret string `json:"secret"`
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if !readJSON(w, r, &req) {
		return
	}
	token, secret, err := s.Announcer.Create(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Label)
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, tokenCreated{Token: token, Secret: secret})
}

type tokenRemoveRequest struct {
	// Keep: its services stay, as services of the page's own.
	Keep bool `json:"keep"`
}

func (s *Server) handleTokenRemove(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such token")
		return
	}
	var req tokenRemoveRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Announcer.Remove(r.Context(), sessionFrom(r).Username, remoteIP(r), id, req.Keep); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleTokens(w, r)
}

func (s *Server) handleTokenRepin(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such token")
		return
	}
	if err := s.Announcer.Repin(r.Context(), sessionFrom(r).Username, remoteIP(r), id); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleTokens(w, r)
}

// handleAnnounce is what the curl container in a server's compose file
// calls. It needs no session: the token is the server's proof. The answer
// is plain text, one line per service, for `docker compose logs announce`.
func (s *Server) announce(w http.ResponseWriter, r *http.Request, ip string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	bearer, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		io.WriteString(w, "send the fields as a form: curl -d service=name:port ...\n")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "the request could not be read\n")
		return
	}
	results, err := s.Announcer.Handle(r.Context(), strings.TrimSpace(bearer), ip, r.PostForm)
	var refusal *announce.Refusal
	switch {
	case errors.As(err, &refusal):
		w.WriteHeader(refusal.Status)
		fmt.Fprintf(w, "SGC refused the announcement: %s\n", refusal.Message)
		return
	case err != nil:
		s.Log.Error("announcement failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "something went wrong inside SGC; details are in its log\n")
		return
	}
	status := http.StatusOK
	var b strings.Builder
	for _, result := range results {
		switch {
		case result.Refused != "":
			status = http.StatusUnprocessableEntity
			fmt.Fprintf(&b, "%s: refused: %s\n", result.Name, result.Refused)
		case result.Pending:
			fmt.Fprintf(&b, "%s: waits for approval in SGC's page, then %s\n", result.Name, result.URL)
		default:
			fmt.Fprintf(&b, "%s: %s\n", result.Name, result.URL)
		}
	}
	w.WriteHeader(status)
	io.WriteString(w, b.String())
}

func (s *Server) handleAnnounce(w http.ResponseWriter, r *http.Request) {
	s.announce(w, r, remoteIP(r))
}

// --- The second listener, for Traefik only (127.0.0.1:8444) -------------------

// InternalHandler serves what Traefik asks SGC for: the friendly error
// pages, announcements that came through the proxy, and the login gate.
// Only the device itself reaches it.
func (s *Server) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxy-error/{status}", s.handleProxyError)
	mux.HandleFunc("/proxy-unknown", s.handleProxyUnknown)
	mux.HandleFunc("POST /api/announce", func(w http.ResponseWriter, r *http.Request) {
		// Traefik puts the address the request came from last in
		// X-Forwarded-For, replacing whatever the client sent (it trusts
		// no forwarded headers from outside).
		ip := forwardedFor(r)
		if ip == "" {
			http.Error(w, "no client address", http.StatusBadRequest)
			return
		}
		s.announce(w, r, ip)
	})
	s.gateRoutes(mux)
	return mux
}

func forwardedFor(r *http.Request) string {
	header := r.Header.Get("X-Forwarded-For")
	parts := strings.Split(header, ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	if net.ParseIP(last) == nil {
		return ""
	}
	return last
}

func (s *Server) handleProxyError(w http.ResponseWriter, r *http.Request) {
	status, err := strconv.Atoi(r.PathValue("status"))
	if err != nil || status < 400 || status > 599 {
		status = http.StatusBadGateway
	}
	host := hostOnly(r.Host)
	body := "The device behind <b>" + html.EscapeString(host) + "</b> does not answer. It may be switched off, restarting, or have a new address."
	if status == http.StatusGatewayTimeout {
		body = "The device behind <b>" + html.EscapeString(host) + "</b> took too long to answer."
	}
	friendlyPage(w, status, "Not reachable right now", body)
}

func (s *Server) handleProxyUnknown(w http.ResponseWriter, r *http.Request) {
	friendlyPage(w, http.StatusNotFound, "No service by this name",
		"SGC has no service called <b>"+html.EscapeString(hostOnly(r.Host))+"</b>. Services are added in SGC's page, or announce themselves.")
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// friendlyPage is a small page of SGC's own, with nothing from the device
// behind the name in it. body is HTML made of escaped parts.
func friendlyPage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title><style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:15vh auto;padding:0 1rem;color:#222;background:#fafafa}
h1{font-size:1.3rem}p{line-height:1.5}small{color:#777}@media(prefers-color-scheme:dark){body{color:#eee;background:#111}small{color:#999}}</style></head>
<body><h1>%s</h1><p>%s</p><p><small>Server Gateway Control · %d</small></p></body></html>`,
		html.EscapeString(title), html.EscapeString(title), body, status)
}
