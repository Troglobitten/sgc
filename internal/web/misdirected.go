package web

import (
	"context"
	"html"
	"net/http"
	"strings"
)

// Browsers reuse one HTTP/2 connection for several names when those names
// point at the same address and the certificate on the connection covers
// them all ("connection coalescing"). SGC's certificate is for *.domain, so
// a browser that has a connection open to a service at the proxy may send
// a request for SGC's own name over it, and the other way round. Neither
// end can serve the other's name: Traefik hands SGC's name to SGC unopened,
// by the name in the TLS handshake, which a reused connection does not
// repeat. Seen by the owner on 2026-10-25: sgc.domain now and then showed
// the proxy's "No service by this name" until the old connection had gone.
//
// The answer for that case is 421 Misdirected Request (RFC 9110 §15.5.20):
// the browser then sends the request again, once, over a connection of its
// own (Chromium since 2017, codereview.chromium.org/2771263002; Firefox
// too). SGC's page answers so a request whose name is not the one its
// connection was opened for (rejectMisdirected). At the proxy, a request for
// SGC's name over a service's connection meets the "unknown" router, whose
// page answers so for SGC's own name (handleProxyUnknown). A router of its
// own for SGC's name was tried first and took every connection for the name
// from the pass-through (see the comment in proxy.RenderDynamic).

// misdirected reports whether a request came over a TLS connection opened
// for another name. A connection by address carries no name and never is.
func misdirected(r *http.Request) bool {
	if r.TLS == nil || r.TLS.ServerName == "" {
		return false
	}
	// (A name in the handshake never has a port; Go's test requests give it
	// the address's, so it is taken off there too.)
	return !strings.EqualFold(strings.TrimSuffix(hostOnly(r.Host), "."), strings.TrimSuffix(hostOnly(r.TLS.ServerName), "."))
}

// rejectMisdirected answers misdirected requests with 421, before anything
// else looks at them.
func rejectMisdirected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if misdirected(r) {
			writeMisdirected(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isOwnName reports whether host is the gateway's own name under the domain.
func (s *Server) isOwnName(ctx context.Context, host string) bool {
	if s.Names == nil {
		return false
	}
	status, err := s.Names.Status(ctx)
	if err != nil || status.FQDN == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(hostOnly(host), "."), status.FQDN)
}

// writeMisdirected is the 421 answer. A browser retries by itself and shows
// this only if it does not.
func writeMisdirected(w http.ResponseWriter, r *http.Request) {
	friendlyPage(w, http.StatusMisdirectedRequest, "One moment",
		"Your browser reached <b>"+html.EscapeString(hostOnly(r.Host))+"</b> over a connection that belongs to another name. Reload the page: it then opens a connection of its own.")
}
