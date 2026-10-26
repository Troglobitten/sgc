package web

import (
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/public"
)

// SGC's login for a protected service that is public (docs/design.md §14).
// SGC's own name never faces the internet, so the sign-in comes under the
// service's own name, at the gate's path (Traefik's "public-gate" router
// sends it to this listener). The admin and people may sign in; the pass
// they get opens that one service, never SGC's page. The page is SGC's own
// HTML, without scripts. What protects it:
//
//   - wrong passwords lock the visitor's address out for a while (the same
//     limit as every sign-in), and slow down guessing at one account from
//     many addresses (auth.AccountThrottle);
//   - only a few passwords are checked at once (auth), so a flood cannot
//     take the device's memory;
//   - the form only takes a sign-in sent from its own page (no other site
//     can post it), and cannot be shown inside another site's frame;
//   - every failure is written to the log with the visitor's address
//     first, for fail2ban (public.SignInFailedMessage);
//   - the way back is a path on the same name, nothing else.

// gateForms refuses a sign-in posted from another site.
var gateForms = http.NewCrossOriginProtection()

// forwardedFor is the visitor's address as Traefik passed it on: the last
// entry of X-Forwarded-For, which Traefik sets from the connection (it
// replaces what visitors send). Only for requests from this device, which
// is the only place this listener takes them from.
func forwardedFor(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return remoteIP(r)
	}
	if addr, err := netip.ParseAddr(host); err != nil || !addr.IsLoopback() {
		return host
	}
	values := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	last := strings.TrimSpace(values[len(values)-1])
	if addr, err := netip.ParseAddr(last); err == nil {
		return addr.String()
	}
	return host
}

// gateCheckPublic is Traefik's question for a request from the internet: as
// gateCheck, but the visitor without a pass is sent to the sign-in under
// the service's own name.
func (s *Server) gateCheckPublic(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Header.Get("X-Forwarded-Host"))
	serviceID, _, ok := s.protectedService(r.Context(), host)
	if !ok {
		http.Error(w, "not a protected name", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(gateCookie); err == nil {
		if who, ok := s.passFor(r.Context(), cookie.Value, host, serviceID); ok {
			w.Header().Set("X-SGC-User", who)
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	back := "/"
	if uri := r.Header.Get("X-Forwarded-Uri"); safePath(uri) {
		back = uri
	}
	http.Redirect(w, r, "https://"+host+proxy.GatePath+"sign-in?rd="+url.QueryEscape(back), http.StatusFound)
}

// safePath reports whether a way back is a path on the same name: it starts
// with one slash, and nothing in it can lead elsewhere.
func safePath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\\\r\n") && len(p) <= 2048
}

func (s *Server) gatePublicSignIn(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = hostOnly(r.Host)
	}
	serviceID, name, ok := s.protectedService(r.Context(), host)
	if !ok {
		friendlyPage(w, http.StatusNotFound, "Not found", "There is nothing to sign in to here.")
		return
	}
	back := r.URL.Query().Get("rd")
	if !safePath(back) {
		back = "/"
	}
	if r.Method == http.MethodGet {
		signInPage(w, http.StatusOK, name, back, "")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := gateForms.Check(r); err != nil {
		http.Error(w, "this sign-in must be sent from its own page", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		signInPage(w, http.StatusBadRequest, name, back, "That sign-in could not be read.")
		return
	}
	if rd := r.PostForm.Get("rd"); safePath(rd) {
		back = rd
	}
	username, password := r.PostForm.Get("username"), r.PostForm.Get("password")
	visitor := forwardedFor(r)
	ctx := r.Context()

	var personID int64
	var admin, who string
	adminName, _ := s.Auth.AdminUsername(ctx)
	var err error
	if adminName != "" && strings.EqualFold(strings.TrimSpace(username), adminName) {
		var slowed bool
		admin, slowed, err = s.Auth.CheckAdmin(ctx, strings.TrimSpace(username), password, visitor)
		who = admin
		if errors.Is(err, auth.ErrInvalidCredentials) {
			s.record(r, "-", audit.ActionGateLoginFailed, "username tried: "+truncate(username, 64)+", at "+name)
		}
		if slowed && s.Alert != nil {
			s.Alert(ctx, "Someone may be guessing the admin password", "Wrong passwords for the admin at the sign-in of "+name+" (reachable from the internet), the last from "+visitor+". Sign-ins for it are slowed down now.")
		}
	} else {
		var person *people.Person
		person, err = s.People.Verify(ctx, username, password, visitor)
		if err == nil && !person.Reaches(serviceID) {
			signInPage(w, http.StatusForbidden, name, back, "Your login does not include "+name+".")
			return
		}
		if person != nil {
			personID, who = person.ID, person.Name
		}
	}
	var locked *auth.TooManyAttemptsError
	switch {
	case errors.As(err, &locked):
		w.Header().Set("Retry-After", fmt.Sprint(int(locked.RetryAfter.Seconds())+1))
		signInPage(w, http.StatusTooManyRequests, name, back,
			fmt.Sprintf("Too many wrong passwords. Try again in %d minutes.", int(locked.RetryAfter.Minutes())+1))
		return
	case errors.Is(err, auth.ErrBusy):
		signInPage(w, http.StatusServiceUnavailable, name, back, "Many sign-ins are being checked at once. Try again in a moment.")
		return
	case err != nil:
		// For fail2ban: the message, then the visitor's address, and nothing
		// the visitor typed before it.
		s.Log.Warn(public.SignInFailedMessage, "visitor", visitor, "service", name)
		signInPage(w, http.StatusUnauthorized, name, back, "That username and password do not match a login.")
		return
	}

	token, hash, err := auth.NewToken()
	if err != nil || s.Gate == nil {
		s.internalError(w, r, err)
		return
	}
	var personRef any
	if personID != 0 {
		personRef = personID
	}
	now := time.Now()
	if _, err := s.Gate.DB.ExecContext(ctx, `INSERT INTO gate_pass (token_hash, host, person_id, admin, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, hash, host, personRef, admin, now.Unix(), now.Add(gatePassFor).Unix()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.record(r, who, audit.ActionGateLogin, "to "+name+" from the internet ("+visitor+")")
	http.SetCookie(w, &http.Cookie{Name: gateCookie, Value: token, Path: "/", Expires: now.Add(gatePassFor),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// signInPage is the sign-in form, SGC's own HTML without scripts.
func signInPage(w http.ResponseWriter, status int, service, back, problem string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	message := ""
	if problem != "" {
		message = `<p class="problem">` + html.EscapeString(problem) + `</p>`
	}
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to %[1]s</title><style>body{font-family:system-ui,sans-serif;max-width:22rem;margin:12vh auto;padding:0 1rem;color:#222;background:#fafafa}
h1{font-size:1.25rem}label{display:block;margin:.9rem 0 .3rem;font-size:.9rem}input{box-sizing:border-box;width:100%%;padding:.55rem;font-size:1rem;border:1px solid #bbb;border-radius:.4rem}
button{margin-top:1.2rem;width:100%%;padding:.6rem;font-size:1rem;border:0;border-radius:.4rem;background:#222;color:#fff}.problem{color:#b00020}small{color:#777}
@media(prefers-color-scheme:dark){body{color:#eee;background:#111}input{background:#1b1b1b;color:#eee;border-color:#444}button{background:#eee;color:#111}small{color:#999}.problem{color:#ff8a80}}</style></head>
<body><h1>Sign in to %[1]s</h1>%[2]s<form method="post" action="%[3]ssign-in" autocomplete="on">
<input type="hidden" name="rd" value="%[4]s">
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required maxlength="64" autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required maxlength="256">
<button type="submit">Sign in</button></form><p><small>Server Gateway Control</small></p></body></html>`,
		html.EscapeString(service), message, proxy.GatePath, html.EscapeString(back))
}
