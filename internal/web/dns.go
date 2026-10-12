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
	Install(ctx context.Context, actor, remote string) error
	Remove(ctx context.Context, actor, remote string) error
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

// handleDNSInstall downloads and installs AdGuard Home, which takes a while.
func (s *Server) handleDNSInstall(w http.ResponseWriter, r *http.Request) {
	extendDeadlines(w)
	s.dnsResult(w, r, s.DNS.Install(r.Context(), sessionFrom(r).Username, remoteIP(r)))
}

type dnsRemoveRequest struct {
	Confirm bool `json:"confirm"`
}

func (s *Server) handleDNSRemove(w http.ResponseWriter, r *http.Request) {
	var req dnsRemoveRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "removing AdGuard Home needs confirmation")
		return
	}
	extendDeadlines(w)
	s.dnsResult(w, r, s.DNS.Remove(r.Context(), sessionFrom(r).Username, remoteIP(r)))
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
			http.Error(w, "AdGuard Home does not answer. Is it installed and running? See SGC's System page.", http.StatusBadGateway)
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
