// Package zonetest is a stand-in for Zone.eu, for SGC's own tests and for the
// whole-machine test. No test of SGC ever talks to the real Zone.eu.
//
// It is one account with a fixed set of domains, and plays both of Zone.eu's
// parts: the API, answering the way Zone.eu's documentation describes (see
// internal/zone), and the name servers, which answer DNS questions about the
// TXT records that were made through the API. The second part is what a
// certificate authority asks when SGC proves that the domain is the owner's.
package zonetest

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type record struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Destination string `json:"destination"`
}

// Server is the stand-in. It is an http.Handler serving the API under /v2/,
// and a dns.Handler answering for the account's zones.
type Server struct {
	mu       sync.Mutex
	username string
	apiKey   string
	domains  map[string]bool     // name -> active
	txt      map[string][]record // zone -> TXT records
	nextID   int
	requests int
	// Answer every request with this status instead (0: answer normally).
	failWith int
	// The name servers do not show TXT records (as when a change has not
	// reached them yet).
	hideTXT bool
}

// New returns a stand-in for an account with the given DNS zones, all active.
func New(username, apiKey string, domains ...string) *Server {
	s := &Server{username: username, apiKey: apiKey, domains: map[string]bool{}, txt: map[string][]record{}, nextID: 100}
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

// FailWith makes every request to the API end with the given status, as when
// Zone.eu has trouble of its own or the limit of requests is reached. 0 ends
// that.
func (s *Server) FailWith(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWith = status
}

// HideTXT makes the name servers leave TXT records out of their answers, as
// when a change made through the API has not reached them.
func (s *Server) HideTXT(hide bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hideTXT = hide
}

// Requests is how many requests to the API have arrived.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// TXT returns the values of the TXT records with the given name, whatever
// zone they are in.
func (s *Server) TXT(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var values []string
	for _, records := range s.txt {
		for _, r := range records {
			if strings.EqualFold(r.Name, name) {
				values = append(values, r.Destination)
			}
		}
	}
	return values
}

// Records is how many TXT records the account's zones hold.
func (s *Server) Records() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, records := range s.txt {
		count += len(records)
	}
	return count
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
	answer := func(status int, records []record) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		out := make([]map[string]any, 0, len(records))
		for _, r := range records {
			out = append(out, map[string]any{
				"resource_url": "https://api.zone.eu/v2/dns/x/txt/" + r.ID,
				"destination":  r.Destination,
				// As a string, which is what Zone.eu's examples show (its
				// description of the format says "integer").
				"id":     r.ID,
				"name":   r.Name,
				"delete": true,
				"modify": true,
			})
		}
		json.NewEncoder(w).Encode(out)
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
	// /v2/dns/<zone>[/txt[/<id>]]
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

	case len(parts) == 3 && parts[2] == "txt" && r.Method == http.MethodGet:
		answer(http.StatusOK, s.txt[domain])

	case len(parts) == 3 && parts[2] == "txt" && r.Method == http.MethodPost:
		var body struct {
			Name        string `json:"name"`
			Destination string `json:"destination"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			refuse(http.StatusBadRequest, "invalid request")
			return
		}
		// A record belongs in its zone, and has something in it.
		if body.Destination == "" || (body.Name != domain && !strings.HasSuffix(body.Name, "."+domain)) {
			refuse(http.StatusUnprocessableEntity, "invalid input")
			return
		}
		s.nextID++
		created := record{ID: strconv.Itoa(s.nextID), Name: body.Name, Destination: body.Destination}
		s.txt[domain] = append(s.txt[domain], created)
		answer(http.StatusCreated, []record{created})

	case len(parts) == 4 && parts[2] == "txt" && r.Method == http.MethodDelete:
		records := s.txt[domain]
		for i, existing := range records {
			if existing.ID == parts[3] {
				s.txt[domain] = append(records[:i:i], records[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		refuse(http.StatusNotFound, "Not found")

	default:
		refuse(http.StatusBadRequest, "operation not supported")
	}
}

// ServeDNS answers as the zones' name servers would: TXT questions from the
// records made through the API, anything else about a name in a zone with
// "nothing of that kind", and names outside the zones with "no such name".
func (s *Server) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(request)
	reply.Authoritative = true
	if len(request.Question) != 1 {
		reply.Rcode = dns.RcodeFormatError
		w.WriteMsg(reply)
		return
	}
	question := request.Question[0]
	name := strings.ToLower(strings.TrimSuffix(question.Name, "."))

	s.mu.Lock()
	inZone := false
	for domain := range s.domains {
		if name == domain || strings.HasSuffix(name, "."+domain) {
			inZone = true
		}
	}
	if inZone && question.Qtype == dns.TypeTXT && !s.hideTXT {
		for _, records := range s.txt {
			for _, r := range records {
				if strings.EqualFold(r.Name, name) {
					reply.Answer = append(reply.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
						Txt: []string{r.Destination},
					})
				}
			}
		}
	}
	s.mu.Unlock()

	if !inZone {
		reply.Rcode = dns.RcodeNameError
	}
	w.WriteMsg(reply)
}

// ListenDNS serves the name servers' part on the given address ("host:port";
// port 0 picks a free one), over UDP and TCP. It returns the address in use
// and a function that stops both.
func (s *Server) ListenDNS(address string) (string, func(), error) {
	packets, err := net.ListenPacket("udp", address)
	if err != nil {
		return "", nil, err
	}
	// The same port for TCP, which is what a client falls back to.
	listener, err := net.Listen("tcp", packets.LocalAddr().String())
	if err != nil {
		packets.Close()
		return "", nil, err
	}
	udp := &dns.Server{PacketConn: packets, Handler: s}
	tcp := &dns.Server{Listener: listener, Handler: s}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	stop := func() {
		udp.Shutdown()
		tcp.Shutdown()
	}
	return packets.LocalAddr().String(), stop, nil
}
