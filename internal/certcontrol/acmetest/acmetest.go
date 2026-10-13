// Package acmetest is a stand-in for Let's Encrypt, for SGC's own tests and
// for the whole-machine test. No test of SGC ever talks to Let's Encrypt,
// not even to its test authority.
//
// It is Pebble, the small certificate authority Let's Encrypt publishes for
// exactly this purpose, run inside the test. Pebble speaks the same protocol
// and really checks the proof in DNS; what it issues is signed by a root of
// its own that no browser knows.
package acmetest

import (
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

// DirectoryPath is where the authority's directory is, under the address it
// is served at.
const DirectoryPath = wfe.DirectoryPath

// Authority is the stand-in: an http.Handler, to be served over TLS.
type Authority struct {
	handler   http.Handler
	authority *ca.CAImpl

	mu       sync.Mutex
	requests int
	orders   int
}

// New returns an authority that looks for proofs at the DNS server with the
// given address ("host:port").
func New(dnsAddress string) *Authority {
	// Pebble waits a random while before it checks a proof and refuses a
	// share of all requests on purpose, to shake out careless clients. Both
	// only make tests slow.
	os.Setenv("PEBBLE_VA_NOSLEEP", "1")
	os.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	// An authority remembers a proof for a while and does not ask for it
	// again. Renewals are months apart, when every proof is long forgotten,
	// so here it never remembers: each certificate takes a fresh proof.
	os.Setenv("PEBBLE_AUTHZREUSE", "0")

	quiet := log.New(io.Discard, "", 0)
	store := db.NewMemoryStore()
	authority := ca.New(quiet, store, "", "ecdsa", 0, 1, map[string]ca.Profile{
		"default": {Description: "The default profile"},
	})
	// The two ports are for kinds of proof SGC does not use.
	validator := va.New(quiet, 80, 443, false, dnsAddress, store)
	frontEnd := wfe.New(quiet, store, validator, authority, []string{"pebble.letsencrypt.org"}, false, false, 3, 5)
	return &Authority{handler: frontEnd.Handler(), authority: authority}
}

func (a *Authority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.requests++
	// Pebble's own name for "a new order for a certificate".
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/order-plz") {
		a.orders++
	}
	a.mu.Unlock()
	a.handler.ServeHTTP(w, r)
}

// Requests is how many requests have arrived; Orders how many of them asked
// for a certificate.
func (a *Authority) Requests() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests
}

func (a *Authority) Orders() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.orders
}

// Roots is the root certificate that what this authority issues leads up to.
func (a *Authority) Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.authority.GetRootCert(0).Cert)
	return pool
}
