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
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type record struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Destination string `json:"destination"`
}

// srvRecord is a service record as Zone.eu's API writes it.
type srvRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Destination string `json:"destination"`
	Priority    int    `json:"priority"`
	Weight      int    `json:"weight"`
	Port        int    `json:"port"`
}

// Server is the stand-in. It is an http.Handler serving the API under /v2/,
// and a dns.Handler answering for the account's zones.
type Server struct {
	mu       sync.Mutex
	username string
	apiKey   string
	domains  map[string]bool     // name -> active
	txt      map[string][]record // zone -> TXT records
	a        map[string][]record // zone -> A records
	srv      map[string][]srvRecord
	nextID   int
	requests int
	// Answer every request with this status instead (0: answer normally).
	failWith int
	// The name servers do not show TXT records (as when a change has not
	// reached them yet).
	hideTXT bool
	// What the TXT records were after each change, for name servers that
	// are behind.
	history []snapshot
}

// snapshot is the TXT records as they were from a moment on.
type snapshot struct {
	from time.Time
	txt  map[string][]record
}

// New returns a stand-in for an account with the given DNS zones, all active.
func New(username, apiKey string, domains ...string) *Server {
	s := &Server{username: username, apiKey: apiKey, domains: map[string]bool{}, txt: map[string][]record{}, a: map[string][]record{},
		srv: map[string][]srvRecord{}, nextID: 100}
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

// A returns the addresses of the A records with the given name.
func (s *Server) A(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var values []string
	for _, records := range s.a {
		for _, r := range records {
			if strings.EqualFold(r.Name, name) {
				values = append(values, r.Destination)
			}
		}
	}
	return values
}

// SRV returns the service records with the given name as
// "priority weight port target".
func (s *Server) SRV(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var values []string
	for _, records := range s.srv {
		for _, r := range records {
			if strings.EqualFold(r.Name, name) {
				values = append(values, fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Destination))
			}
		}
	}
	return values
}

// AddA makes an A record as the owner would in Zone.eu's own page.
func (s *Server) AddA(domain, name, address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	s.a[domain] = append(s.a[domain], record{ID: strconv.Itoa(s.nextID), Name: name, Destination: address})
}

// RemoveByHand removes the A and SRV records with the given name, as the
// owner would in Zone.eu's own page.
func (s *Server) RemoveByHand(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for zone, records := range s.a {
		s.a[zone] = slices.DeleteFunc(records, func(r record) bool { return strings.EqualFold(r.Name, name) })
	}
	for zone, records := range s.srv {
		s.srv[zone] = slices.DeleteFunc(records, func(r srvRecord) bool { return strings.EqualFold(r.Name, name) })
	}
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
	answerSRV := func(status int, records []srvRecord) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		out := make([]map[string]any, 0, len(records))
		for _, r := range records {
			out = append(out, map[string]any{"id": r.ID, "name": r.Name, "destination": r.Destination,
				"priority": r.Priority, "weight": r.Weight, "port": r.Port, "delete": true, "modify": true})
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

	case len(parts) == 3 && parts[2] == "a" && r.Method == http.MethodGet:
		answer(http.StatusOK, s.a[domain])

	case len(parts) == 3 && parts[2] == "a" && r.Method == http.MethodPost:
		var body struct {
			Name        string `json:"name"`
			Destination string `json:"destination"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			refuse(http.StatusBadRequest, "invalid request")
			return
		}
		if addr := net.ParseIP(body.Destination); addr == nil || addr.To4() == nil || (body.Name != domain && !strings.HasSuffix(body.Name, "."+domain)) {
			refuse(http.StatusUnprocessableEntity, "invalid input")
			return
		}
		s.nextID++
		created := record{ID: strconv.Itoa(s.nextID), Name: body.Name, Destination: body.Destination}
		s.a[domain] = append(s.a[domain], created)
		answer(http.StatusCreated, []record{created})

	case len(parts) == 4 && parts[2] == "a" && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
		records := s.a[domain]
		for i, existing := range records {
			if existing.ID != parts[3] {
				continue
			}
			if r.Method == http.MethodDelete {
				s.a[domain] = append(records[:i:i], records[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			var body struct {
				Name        string `json:"name"`
				Destination string `json:"destination"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || net.ParseIP(body.Destination).To4() == nil {
				refuse(http.StatusUnprocessableEntity, "invalid input")
				return
			}
			records[i].Name, records[i].Destination = body.Name, body.Destination
			answer(http.StatusOK, []record{records[i]})
			return
		}
		refuse(http.StatusNotFound, "Not found")

	case len(parts) == 3 && parts[2] == "srv" && r.Method == http.MethodGet:
		answerSRV(http.StatusOK, s.srv[domain])

	case len(parts) == 3 && parts[2] == "srv" && r.Method == http.MethodPost:
		var body srvRecord
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			refuse(http.StatusBadRequest, "invalid request")
			return
		}
		if body.Destination == "" || body.Port < 1 || body.Port > 65535 || !strings.HasPrefix(body.Name, "_") ||
			!strings.HasSuffix(body.Name, "."+domain) {
			refuse(http.StatusUnprocessableEntity, "invalid input")
			return
		}
		s.nextID++
		body.ID = strconv.Itoa(s.nextID)
		s.srv[domain] = append(s.srv[domain], body)
		answerSRV(http.StatusCreated, []srvRecord{body})

	case len(parts) == 4 && parts[2] == "srv" && r.Method == http.MethodDelete:
		records := s.srv[domain]
		for i, existing := range records {
			if existing.ID == parts[3] {
				s.srv[domain] = append(records[:i:i], records[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		refuse(http.StatusNotFound, "Not found")

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
		s.remember()
		answer(http.StatusCreated, []record{created})

	case len(parts) == 4 && parts[2] == "txt" && r.Method == http.MethodDelete:
		records := s.txt[domain]
		for i, existing := range records {
			if existing.ID == parts[3] {
				s.txt[domain] = append(records[:i:i], records[i+1:]...)
				s.remember()
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		refuse(http.StatusNotFound, "Not found")

	default:
		refuse(http.StatusBadRequest, "operation not supported")
	}
}

// remember notes what the TXT records are from now on. The caller holds the lock.
func (s *Server) remember() {
	copied := make(map[string][]record, len(s.txt))
	for domain, records := range s.txt {
		copied[domain] = append([]record(nil), records...)
	}
	s.history = append(s.history, snapshot{from: time.Now(), txt: copied})
}

// recordsAt returns the TXT records as they were at a moment. The caller
// holds the lock.
func (s *Server) recordsAt(moment time.Time) map[string][]record {
	for i := len(s.history) - 1; i >= 0; i-- {
		if !s.history[i].from.After(moment) {
			return s.history[i].txt
		}
	}
	return nil
}

// ServeDNS answers as the zones' name servers would: TXT questions from the
// records made through the API, anything else about a name in a zone with
// "nothing of that kind", and names outside the zones with "no such name".
func (s *Server) ServeDNS(w dns.ResponseWriter, request *dns.Msg) { s.serveDNS(w, request, 0) }

// behind is the name servers as seen from far away: they show what the
// records were a while ago.
type behind struct {
	server *Server
	lag    time.Duration
}

func (b behind) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	b.server.serveDNS(w, request, b.lag)
}

func (s *Server) serveDNS(w dns.ResponseWriter, request *dns.Msg, lag time.Duration) {
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
	shown := s.txt
	if lag > 0 {
		shown = s.recordsAt(time.Now().Add(-lag))
	}
	if inZone && question.Qtype == dns.TypeTXT && !s.hideTXT {
		for _, records := range shown {
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
	return listenDNS(address, s)
}

// ListenLaggingDNS serves name servers that are behind by the given time:
// they show what the records were that long ago. This is how the name
// servers can look to a certificate authority on the other side of the
// world, while the ones nearby are up to date.
func (s *Server) ListenLaggingDNS(address string, lag time.Duration) (string, func(), error) {
	return listenDNS(address, behind{server: s, lag: lag})
}

func listenDNS(address string, handler dns.Handler) (string, func(), error) {
	// The same port for UDP and for TCP, which is what a client falls back
	// to. A port the system picks as free for UDP can be taken for TCP (by
	// another test running at the same moment, for one), so when the choice
	// is the system's, it is asked again until a port is free for both.
	attempts := 1
	if _, port, err := net.SplitHostPort(address); err == nil && port == "0" {
		attempts = 50
	}
	var (
		packets  net.PacketConn
		listener net.Listener
		err      error
	)
	for ; attempts > 0; attempts-- {
		if packets, err = net.ListenPacket("udp", address); err != nil {
			return "", nil, err
		}
		if listener, err = net.Listen("tcp", packets.LocalAddr().String()); err == nil {
			break
		}
		packets.Close()
	}
	if err != nil {
		return "", nil, err
	}
	udp := &dns.Server{PacketConn: packets, Handler: handler}
	tcp := &dns.Server{Listener: listener, Handler: handler}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	stop := func() {
		udp.Shutdown()
		tcp.Shutdown()
	}
	return packets.LocalAddr().String(), stop, nil
}
