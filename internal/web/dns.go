package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/dnscontrol"
)

// DNS is what the interface can do about AdGuard Home (internal/dnscontrol).
type DNS interface {
	Status(ctx context.Context) (dnscontrol.Status, error)
	SetEnabled(ctx context.Context, actor, remote string, enabled bool) error
	Install(ctx context.Context, actor, remote string) error
	FinishRestore(ctx context.Context, actor, remote string) error
}

func (s *Server) handleDNSStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.DNS.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) dnsResult(w http.ResponseWriter, r *http.Request, err error) {
	var failure *dnscontrol.ChangeError
	switch {
	case err == nil:
		s.handleDNSStatus(w, r)
	case errors.As(err, &failure):
		writeError(w, http.StatusBadGateway, failure.Message)
	default:
		s.internalError(w, r, err)
	}
}

type dnsEnabledRequest struct {
	// A pointer, so that a request without the field is refused, not read as "off".
	Enabled *bool `json:"enabled"`
}

// handleDNSEnabled switches DNS on or off. On a device that does not have
// AdGuard Home yet, switching on downloads and installs it, which takes a
// while.
func (s *Server) handleDNSEnabled(w http.ResponseWriter, r *http.Request) {
	var req dnsEnabledRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "the request does not say whether DNS is to be on or off")
		return
	}
	extendDeadlines(w)
	s.dnsResult(w, r, s.DNS.SetEnabled(r.Context(), sessionFrom(r).Username, remoteIP(r), *req.Enabled))
}

// handleDNSInstall replaces the installed AdGuard Home with the newer
// release this SGC brings, which takes a while.
func (s *Server) handleDNSInstall(w http.ResponseWriter, r *http.Request) {
	extendDeadlines(w)
	s.dnsResult(w, r, s.DNS.Install(r.Context(), sessionFrom(r).Username, remoteIP(r)))
}

// handleDNSFinishRestore puts the DNS part of a restored export in place.
// SGC does that by itself after a restore; this is for when that failed.
func (s *Server) handleDNSFinishRestore(w http.ResponseWriter, r *http.Request) {
	extendDeadlines(w)
	s.dnsResult(w, r, s.DNS.FinishRestore(r.Context(), sessionFrom(r).Username, remoteIP(r)))
}

// adguardPrefix is where AdGuard Home's own page appears in SGC's.
const adguardPrefix = "/adguard"

// adguardProxy passes requests under /adguard/ on to AdGuard Home's own
// page, which listens on this device only and has no login of its own. This
// is its only door, and it is behind SGC's login.
//
// SGC's own cookies are not passed on: AdGuard Home has no business knowing
// the admin's session.
func (s *Server) adguardProxy() http.Handler {
	target := &url.URL{Scheme: "http", Host: s.AdguardAddress}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.URL.Path = strings.TrimPrefix(r.In.URL.Path, adguardPrefix)
			r.Out.URL.RawPath = ""
			r.Out.Host = target.Host
			r.Out.Header.Del("Cookie")
			r.Out.Header.Del("Authorization")
		},
		ModifyResponse: func(resp *http.Response) error {
			// AdGuard Home believes it lives at "/".
			if location := resp.Header.Get("Location"); strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
				resp.Header.Set("Location", adguardPrefix+location)
			}
			resp.Header.Del("Set-Cookie")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.Log.Warn("reach AdGuard Home's page", "error", err)
			http.Error(w, "AdGuard Home does not answer. Is DNS switched on? See SGC's System page.", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == adguardPrefix {
			http.Redirect(w, r, adguardPrefix+"/", http.StatusFound)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

// adguardAddressDefault is where AdGuard Home's page listens on a real device.
const adguardAddressDefault = adguard.WebAddress
