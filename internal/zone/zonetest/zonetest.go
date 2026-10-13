// Package zonetest is a stand-in for Zone.eu's API, for SGC's own tests and
// for the whole-machine test. No test of SGC ever talks to the real Zone.eu.
//
// It answers the way Zone.eu's documentation describes (see internal/zone),
// for one account with a fixed set of domains.
package zonetest

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// Server is the stand-in. It is an http.Handler serving the API under /v2/.
type Server struct {
	mu       sync.Mutex
	username string
	apiKey   string
	domains  map[string]bool // name -> active
	requests int
	// Answer every request with this status instead (0: answer normally).
	failWith int
}

// New returns a stand-in for an account with the given DNS zones, all active.
func New(username, apiKey string, domains ...string) *Server {
	s := &Server{username: username, apiKey: apiKey, domains: map[string]bool{}}
	for _, domain := range domains {
		s.domains[domain] = true
	}
	return s
}

// SetAPIKey changes the key the account accepts, as when the owner replaces
// or withdraws a key at Zone.eu.
func (s *Server) SetAPIKey(apiKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKey = apiKey
}

// SetActive says whether a zone is active.
func (s *Server) SetActive(domain string, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains[domain] = active
}

// FailWith makes every request end with the given status, as when Zone.eu
// has trouble of its own or the limit of requests is reached. 0 ends that.
func (s *Server) FailWith(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWith = status
}

// Requests is how many requests have arrived.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	w.Header().Set("X-Ratelimit-Limit", "60")
	w.Header().Set("X-Ratelimit-Remaining", "59")

	refuse := func(status int, message string) {
		w.Header().Set("X-Status-Message", message)
		w.WriteHeader(status)
	}
	if s.failWith != 0 {
		refuse(s.failWith, "the stand-in was told to fail")
		return
	}
	username, apiKey, ok := r.BasicAuth()
	if !ok || username != s.username || apiKey != s.apiKey {
		refuse(http.StatusUnauthorized, "Unauthorized")
		return
	}
	// /v2/dns/<zone>
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v2/"), "/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/v2/") || len(parts) < 2 || parts[0] != "dns" {
		refuse(http.StatusNotFound, "Not found")
		return
	}
	domain := parts[1]
	active, known := s.domains[domain]
	if !known {
		refuse(http.StatusNotFound, "Not found")
		return
	}
	switch {
	case len(parts) == 2 && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{{
			"resource_url":  "https://api.zone.eu/v2/dns/" + domain,
			"identificator": domain,
			"active":        active,
			"ipv6":          false,
		}})
	default:
		refuse(http.StatusBadRequest, "operation not supported")
	}
}
