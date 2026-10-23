package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/proxy"
)

// The login gate (docs/design.md §4.5 and §10). Traefik asks SGC's second
// listener before it passes a request for a protected name on (gateCheck).
// A visitor without a pass for that name is sent to SGC's own page
// (/gate), signs in there (as the admin, or as a person), and is sent back
// through the name's return path with a ticket that is good once, for 60
// seconds and for that name only. The return path swaps it for a cookie
// that only that name receives.

const (
	gateCookie     = "__Host-sgc_gate"
	personCookie   = "__Host-sgc_person"
	ticketFor      = 60 * time.Second
	gatePassFor    = 12 * time.Hour
	maxOpenTickets = 1000
)

// GateStore is what the gate keeps in the database: the passes each
// protected name received.
type GateStore struct {
	DB *sql.DB
}

type ticket struct {
	host     string
	personID int64 // 0: the admin
	admin    string
	rd       string
	expires  time.Time
}

type ticketBox struct {
	mu      sync.Mutex
	tickets map[string]ticket
}

func (b *ticketBox) put(t ticket) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tickets == nil {
		b.tickets = map[string]ticket{}
	}
	now := time.Now()
	for k, old := range b.tickets {
		if now.After(old.expires) {
			delete(b.tickets, k)
		}
	}
	if len(b.tickets) >= maxOpenTickets {
		return "", errors.New("too many sign-ins at once")
	}
	b.tickets[hashOf(token)] = t
	return token, nil
}

// take returns a ticket once.
func (b *ticketBox) take(token string) (ticket, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.tickets[hashOf(token)]
	delete(b.tickets, hashOf(token))
	if !ok || time.Now().After(t.expires) {
		return ticket{}, false
	}
	return t, true
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var gateTickets ticketBox

// gateRoutes adds the gate's routes to the second listener.
func (s *Server) gateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/gate/check", s.gateCheck)
	mux.HandleFunc("GET "+proxy.GatePath+"return", s.gateReturn)
	mux.HandleFunc("GET "+proxy.GatePath+"sign-out", s.gateSignOut)
}

// protectedService finds the protected web service a host belongs to.
func (s *Server) protectedService(ctx context.Context, host string) (int64, string, bool) {
	status, err := s.Names.Status(ctx)
	if err != nil || status.Domain == "" {
		return 0, "", false
	}
	label, ok := gateway.UnderDomain(hostOnly(host), status.Domain)
	if !ok {
		return 0, "", false
	}
	list, err := s.Services.List(ctx)
	if err != nil {
		return 0, "", false
	}
	for _, svc := range list {
		if svc.Name == label && svc.Kind == proxy.KindHTTP && svc.Protected && svc.Enabled && !svc.Pending {
			return svc.ID, svc.Name, true
		}
	}
	return 0, "", false
}

// gateCheck is Traefik's question: may this request pass? Traefik sends the
// visitor's headers, and where the request was for in X-Forwarded-*.
func (s *Server) gateCheck(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	serviceID, _, ok := s.protectedService(r.Context(), host)
	if !ok {
		// Not a protected name (any more): nothing to let through.
		http.Error(w, "not a protected name", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(gateCookie); err == nil {
		if who, ok := s.passFor(r.Context(), cookie.Value, hostOnly(host), serviceID); ok {
			w.Header().Set("X-SGC-User", who)
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	original := (&url.URL{Scheme: "https", Host: hostOnly(host), Path: "/"}).String()
	if uri := r.Header.Get("X-Forwarded-Uri"); strings.HasPrefix(uri, "/") {
		original = "https://" + hostOnly(host) + uri
	}
	status, err := s.Names.Status(r.Context())
	if err != nil || status.URL == "" {
		http.Error(w, "SGC has no name to sign in at", http.StatusForbidden)
		return
	}
	http.Redirect(w, r, status.URL+"/gate?rd="+url.QueryEscape(original), http.StatusFound)
}

// passFor checks a name's cookie: whose it is, if it is still good for
// this name and its owner may still use the service.
func (s *Server) passFor(ctx context.Context, token, host string, serviceID int64) (string, bool) {
	if s.Gate == nil {
		return "", false
	}
	var passHost, admin string
	var personID sql.NullInt64
	var expires int64
	err := s.Gate.DB.QueryRowContext(ctx, "SELECT host, person_id, admin, expires_at FROM gate_pass WHERE token_hash = ?",
		auth.HashToken(token)).Scan(&passHost, &personID, &admin, &expires)
	if err != nil || passHost != host || time.Now().Unix() >= expires {
		return "", false
	}
	if !personID.Valid {
		return admin, admin != ""
	}
	everyone, err := s.People.List(ctx)
	if err != nil {
		return "", false
	}
	for _, p := range everyone {
		if p.ID == personID.Int64 {
			if p.LoginEnabled && p.Reaches(serviceID) {
				return p.Name, true
			}
			return "", false
		}
	}
	return "", false
}

// gateReturn is the name's return path: a ticket becomes that name's cookie.
func (s *Server) gateReturn(w http.ResponseWriter, r *http.Request) {
	t, ok := gateTickets.take(r.URL.Query().Get("ticket"))
	host := hostOnly(r.Host)
	if !ok || t.host != host {
		friendlyPage(w, http.StatusForbidden, "That sign-in link has expired", "Open the service again to sign in.")
		return
	}
	token, hash, err := auth.NewToken()
	if err != nil || s.Gate == nil {
		s.internalError(w, r, err)
		return
	}
	var personID any
	if t.personID != 0 {
		personID = t.personID
	}
	now := time.Now()
	if _, err := s.Gate.DB.ExecContext(r.Context(), `INSERT INTO gate_pass (token_hash, host, person_id, admin, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, hash, host, personID, t.admin, now.Unix(), now.Add(gatePassFor).Unix()); err != nil {
		s.internalError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: gateCookie, Value: token, Path: "/", Expires: now.Add(gatePassFor),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, t.rd, http.StatusFound)
}

func (s *Server) gateSignOut(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(gateCookie); err == nil && s.Gate != nil {
		s.Gate.DB.ExecContext(r.Context(), "DELETE FROM gate_pass WHERE token_hash = ?", auth.HashToken(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: gateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	friendlyPage(w, http.StatusOK, "Signed out", "You are signed out of this service.")
}

// --- On SGC's own page (/gate) ---------------------------------------------------

type gateStateResponse struct {
	// Service is the protected service the visitor wants, "" if rd is not one.
	Service string `json:"service"`
	// Admin: signed in as the admin; Person: signed in as a person.
	Admin             bool   `json:"admin"`
	Person            string `json:"person"`
	Allowed           bool   `json:"allowed"`
	MinPasswordLength int    `json:"minPasswordLength"`
}

// checkReturn reads where a visitor is to be sent back to: an https address
// on a protected name of SGC's, nothing else (no other site, no other
// scheme, no user part, no port but 443).
func (s *Server) checkReturn(ctx context.Context, rd string) (*url.URL, int64, string, bool) {
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || (u.Port() != "" && u.Port() != "443") {
		return nil, 0, "", false
	}
	id, name, ok := s.protectedService(ctx, u.Hostname())
	if !ok {
		return nil, 0, "", false
	}
	return u, id, name, true
}

func (s *Server) gateVisitor(r *http.Request) (admin string, person *people.Person) {
	if session, err := s.currentSession(r); err == nil && session != nil {
		admin = session.Username
	}
	if cookie, err := r.Cookie(s.personCookieName()); err == nil {
		person, _ = s.People.Authenticate(r.Context(), cookie.Value)
	}
	return admin, person
}

func (s *Server) personCookieName() string {
	if s.InsecureCookies {
		return "sgc_person_dev"
	}
	return personCookie
}

func (s *Server) handleGateState(w http.ResponseWriter, r *http.Request) {
	resp := gateStateResponse{MinPasswordLength: auth.MinPasswordLength}
	_, serviceID, name, ok := s.checkReturn(r.Context(), r.URL.Query().Get("rd"))
	if ok {
		resp.Service = name
	}
	admin, person := s.gateVisitor(r)
	resp.Admin = admin != ""
	if person != nil {
		resp.Person = person.Name
	}
	resp.Allowed = ok && (resp.Admin || (person != nil && person.Reaches(serviceID)))
	writeJSON(w, http.StatusOK, resp)
}

type gateLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleGateLogin(w http.ResponseWriter, r *http.Request) {
	var req gateLoginRequest
	if !readJSON(w, r, &req) {
		return
	}
	session, err := s.People.Login(r.Context(), req.Username, req.Password, remoteIP(r), r.UserAgent())
	var locked *auth.TooManyAttemptsError
	switch {
	case errors.As(err, &locked):
		s.authError(w, r, err)
		return
	case err != nil:
		s.problemError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.personCookieName(), Value: session.Token, Path: "/", Expires: session.Expires,
		HttpOnly: true, Secure: !s.InsecureCookies, SameSite: http.SameSiteStrictMode})
	s.handleGateState(w, r)
}

func (s *Server) handleGateLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.personCookieName()); err == nil {
		s.People.Logout(r.Context(), cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: s.personCookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: !s.InsecureCookies, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, struct{}{})
}

type gateTicketRequest struct {
	RD string `json:"rd"`
}

type gateTicketResponse struct {
	Redirect string `json:"redirect"`
}

// handleGateTicket hands a signed-in visitor the way back to the service,
// with a ticket for that name.
func (s *Server) handleGateTicket(w http.ResponseWriter, r *http.Request) {
	var req gateTicketRequest
	if !readJSON(w, r, &req) {
		return
	}
	target, serviceID, name, ok := s.checkReturn(r.Context(), req.RD)
	if !ok {
		writeError(w, http.StatusBadRequest, "That is not a service behind SGC's login.")
		return
	}
	admin, person := s.gateVisitor(r)
	t := ticket{host: target.Hostname(), rd: target.String(), expires: time.Now().Add(ticketFor)}
	switch {
	case admin != "":
		t.admin = admin
	case person != nil && person.Reaches(serviceID):
		t.personID = person.ID
	case person != nil:
		writeError(w, http.StatusForbidden, "Your login does not include "+name+".")
		return
	default:
		writeError(w, http.StatusUnauthorized, "sign in first")
		return
	}
	token, err := gateTickets.put(t)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	who := t.admin
	if person != nil && t.personID != 0 {
		who = person.Name
	}
	s.record(r, who, audit.ActionGateLogin, "to "+name)
	back := "https://" + target.Hostname() + proxy.GatePath + "return?ticket=" + token
	writeJSON(w, http.StatusOK, gateTicketResponse{Redirect: back})
}

type gatePasswordRequest struct {
	Current string `json:"current"`
	Next    string `json:"next"`
}

func (s *Server) handleGatePassword(w http.ResponseWriter, r *http.Request) {
	var req gatePasswordRequest
	if !readJSON(w, r, &req) {
		return
	}
	_, person := s.gateVisitor(r)
	if person == nil {
		writeError(w, http.StatusUnauthorized, "sign in first")
		return
	}
	if err := s.People.ChangePassword(r.Context(), person.ID, req.Current, req.Next, remoteIP(r)); err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}
