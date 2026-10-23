// Package certcontrol gets the certificate for the owner's domain from
// Let's Encrypt, keeps it, and renews it.
//
// It is one certificate for every name under the domain ("*.domain.tld").
// Let's Encrypt gives it to whoever can publish a piece of text it names in
// the domain's DNS; SGC publishes that text through the owner's Zone.eu
// account (internal/zone) and removes it again.
//
// Before the first real certificate SGC goes through the same steps with
// Let's Encrypt's test authority. What can go wrong almost always goes wrong
// there (the key, the zone, name servers that are slow to show a change),
// and the real authority counts failures and locks a domain out for a while
// after a handful of them. The test authority's certificate is thrown away.
//
// Both proofs are published under the same name, and that needs time. The
// owner's first real attempt (2026-10-13) failed for the lack of it: the
// test authority had issued, SGC removed its proof, published the real
// authority's, saw it at Zone.eu's name servers and asked Let's Encrypt to
// look, forty seconds later. Let's Encrypt, asking from other places in the
// world, still got the old proof. So SGC now waits twice: a while after the
// trial, until the old proof is forgotten everywhere; and, in every attempt,
// a little after the name servers it can ask show the new one.
//
// The ACME protocol itself is the lego library's. This package tells it what
// to ask for, hands it the Zone.eu records, and keeps the results: the
// certificate with its private key, and the accounts at the authorities, are
// settings in the database and travel with an export, so that a restored
// device has its certificate without asking for a new one.
//
// All of this runs in the web process. The root side has no part in it.
package certcontrol

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	"github.com/miekg/dns"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/zone"
)

const (
	// SettingCurrent is the certificate in use, with its private key.
	// SettingAccounts are SGC's accounts at the authorities (a key each).
	// SettingTerms is the owner's agreement to the authority's terms. An
	// export carries all three.
	SettingCurrent  = "certificate.current"
	SettingAccounts = "acme.accounts"
	SettingTerms    = "certificate.terms"
	// Bookkeeping of one installation, which an export does not carry: how
	// the last attempt went, the DNS records an attempt has made and not yet
	// removed, and when to renew.
	SettingAttempt     = "certificate.attempt"
	SettingOpenRecords = "certificate.open_records"
	SettingRenewal     = "certificate.renewal"

	// The authority is asked once a day when it wants the certificate
	// renewed. If it does not say, SGC renews when two thirds of the
	// certificate's life are over.
	askEvery = 24 * time.Hour
	// A renewal that failed is tried again after this long: often enough to
	// succeed well before the certificate runs out, seldom enough not to run
	// into the authority's limits.
	retryRenewalAfter = 12 * time.Hour
	// How long a stopping SGC waits for an attempt to wind down.
	stopGrace = 10 * time.Second
	// The attempt's log, as kept for the page.
	maxLogLines = 150
)

// The kinds of attempt.
const (
	KindFirst   = "first"   // the first certificate for a domain, with a trial
	KindManual  = "manual"  // "Renew now"
	KindRenewal = "renewal" // by itself, when it is time
)

// ChangeError is a refused request with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

// Account is the owner's domain and the Zone.eu account its DNS is in.
type Account struct {
	Domain, Username, APIKey string
}

type Config struct {
	DB    *sql.DB
	Audit *audit.Log
	Log   *slog.Logger
	// Account returns the domain and Zone.eu account that are set up, and
	// whether any are (internal/domaincontrol).
	Account func(ctx context.Context) (Account, bool, error)
	// ZoneEndpoint is Zone.eu's API; ZoneHTTP makes the requests to it.
	ZoneEndpoint string
	ZoneHTTP     *http.Client
	UserAgent    string
	// Directory is the authority's address (Let's Encrypt), TrialDirectory
	// that of its test authority. AuthorityHTTP makes the requests to both.
	Directory      string
	TrialDirectory string
	AuthorityHTTP  *http.Client
	// DNSResolver, if set, is asked whether a record is visible, instead of
	// the zone's own name servers. For tests, whose zones do not exist.
	DNSResolver string
	// ResolvConf is the system's list of DNS servers ("" for the usual
	// place). It is read anew for every attempt.
	ResolvConf string
	// How long to wait for a record to show at the name servers, and how
	// often to look.
	PropagationTimeout  time.Duration
	PropagationInterval time.Duration
	// Settle is how much longer to wait once the name servers SGC can ask
	// show the record: the authority asks from several places in the world,
	// and name servers far away can be behind.
	Settle time.Duration
	// TrialGap is the wait between the trial and the real request. Both
	// proofs go under the same name, and the trial's has to be forgotten by
	// every name server and every cache before the real one is looked for.
	TrialGap time.Duration
	// The button is refused for this long after a failure, and after a
	// certificate was issued. The authority counts both.
	RetryAfterFailure time.Duration
	RenewAgainAfter   time.Duration
	Now               func() time.Time
	// Disabled, if set, says why this SGC gets no certificates at all.
	Disabled string
}

type Service struct {
	cfg Config

	mu sync.Mutex
	// base is the context attempts run in; nil until Run has started.
	base context.Context
	// running is the attempt in progress, if any.
	running *Progress
	jobs    sync.WaitGroup

	// What KeyPair handed out last, so that every TLS handshake does not
	// read the database.
	servingMu  sync.Mutex
	servingRaw string
	servingAt  time.Time
	serving    *KeyPair
}

func New(cfg Config) *Service {
	s := &Service{cfg: cfg}
	// lego reports what it does through one logger for the whole program.
	// Its lines go into the log of the attempt in progress.
	legolog.Logger = (*lineLogger)(s)
	return s
}

// Certificate is what the page shows of the certificate. The private key is
// not in it.
type Certificate struct {
	Names      []string  `json:"names"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
	Serial     string    `json:"serial"`
	ObtainedAt time.Time `json:"obtainedAt"`
	// ForDomain: it is for the domain that is set up now.
	ForDomain bool `json:"forDomain"`
}

// Progress is an attempt that is running.
type Progress struct {
	Kind string `json:"kind"`
	// Phase is "trial" while the test authority is asked, "pause" while SGC
	// waits for the trial's proof to be forgotten, then "real".
	Phase string    `json:"phase"`
	Since time.Time `json:"since"`
	Log   []string  `json:"log"`
}

// Attempt is how the last attempt ended.
type Attempt struct {
	Kind       string    `json:"kind"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	OK         bool      `json:"ok"`
	// Message says in words what went wrong.
	Message string   `json:"message"`
	Log     []string `json:"log"`
}

type Status struct {
	// Domain is the domain that is set up, "" if none.
	Domain string `json:"domain"`
	// Disabled says why this SGC gets no certificates, "" if it does.
	Disabled string `json:"disabled"`
	// TermsAgreed: the owner has agreed to the authority's terms.
	TermsAgreed bool         `json:"termsAgreed"`
	Certificate *Certificate `json:"certificate"`
	Running     *Progress    `json:"running"`
	LastAttempt *Attempt     `json:"lastAttempt"`
	// RenewsAt is when SGC means to renew by itself.
	RenewsAt *time.Time `json:"renewsAt"`
	// WaitUntil: until then a request from the page is refused.
	WaitUntil *time.Time `json:"waitUntil"`
}

// stored is the certificate as kept in the database.
type stored struct {
	Domain string `json:"domain"`
	// CertificatePEM is the certificate followed by the authority's own
	// certificates that lead up to one browsers know.
	CertificatePEM string    `json:"certificatePem"`
	PrivateKeyPEM  string    `json:"privateKeyPem"`
	Directory      string    `json:"directory"`
	ObtainedAt     time.Time `json:"obtainedAt"`
}

// accountRecord is SGC's account at one authority.
type accountRecord struct {
	PrivateKeyPEM string `json:"privateKeyPem"`
	URI           string `json:"uri"`
}

type terms struct {
	AgreedAt time.Time `json:"agreedAt"`
	By       string    `json:"by"`
	// URL is the text agreed to, as the authority named it when SGC opened
	// its account there.
	URL string `json:"url,omitempty"`
}

type openRecord struct {
	Domain string `json:"domain"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type renewal struct {
	// AskedAt is when the authority was last asked; RenewAt what came of it.
	AskedAt time.Time `json:"askedAt"`
	RenewAt time.Time `json:"renewAt"`
	// FailedAt is when a renewal by itself last failed, zero if the last
	// one did not.
	FailedAt time.Time `json:"failedAt"`
	// Serial is the certificate all of this is about.
	Serial string `json:"serial"`
}

func (s *Service) readJSON(ctx context.Context, key string, into any) (bool, error) {
	raw, _, err := store.Setting(ctx, s.cfg.DB, key)
	if err != nil || raw == "" {
		return false, err
	}
	if err := json.Unmarshal([]byte(raw), into); err != nil {
		return false, fmt.Errorf("the setting %s cannot be read: %w", key, err)
	}
	return true, nil
}

func (s *Service) writeJSON(ctx context.Context, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, key, string(data))
}

// current returns the certificate that is kept, parsed, or nil.
func (s *Service) current(ctx context.Context) (*stored, *x509.Certificate, error) {
	var kept stored
	found, err := s.readJSON(ctx, SettingCurrent, &kept)
	if err != nil || !found {
		return nil, nil, err
	}
	leaf, err := leafOf(kept.CertificatePEM)
	if err != nil {
		return nil, nil, fmt.Errorf("the kept certificate cannot be read: %w", err)
	}
	return &kept, leaf, nil
}

func leafOf(bundle string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(bundle))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate in it")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	status := Status{Disabled: s.cfg.Disabled}
	// "Running" is looked at first. An attempt ends it last, after writing
	// its result, so a state that says "not running" holds the result of
	// whatever ran before, whole.
	s.mu.Lock()
	if s.running != nil {
		running := *s.running
		running.Log = append([]string(nil), s.running.Log...)
		status.Running = &running
	}
	s.mu.Unlock()
	account, configured, err := s.cfg.Account(ctx)
	if err != nil {
		return status, err
	}
	if configured {
		status.Domain = account.Domain
	}
	var agreed terms
	if status.TermsAgreed, err = s.readJSON(ctx, SettingTerms, &agreed); err != nil {
		return status, err
	}
	kept, leaf, err := s.current(ctx)
	if err != nil {
		return status, err
	}
	if kept != nil {
		status.Certificate = &Certificate{
			Names: leaf.DNSNames, Issuer: issuerName(leaf), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
			Serial: leaf.SerialNumber.Text(16), ObtainedAt: kept.ObtainedAt, ForDomain: configured && kept.Domain == account.Domain,
		}
		if status.Certificate.ForDomain {
			renewAt := s.plan(ctx, leaf).RenewAt
			status.RenewsAt = &renewAt
		}
	}
	var last Attempt
	if found, err := s.readJSON(ctx, SettingAttempt, &last); err != nil {
		return status, err
	} else if found {
		status.LastAttempt = &last
	}
	if wait := s.waitUntil(kept, status.Certificate, status.LastAttempt); wait.After(s.cfg.Now()) {
		status.WaitUntil = &wait
	}
	return status, nil
}

// waitUntil is the moment up to which a request from the page is refused.
func (s *Service) waitUntil(kept *stored, shown *Certificate, last *Attempt) time.Time {
	var wait time.Time
	if kept != nil && shown != nil && shown.ForDomain {
		wait = kept.ObtainedAt.Add(s.cfg.RenewAgainAfter)
	}
	if last != nil && !last.OK {
		if after := last.FinishedAt.Add(s.cfg.RetryAfterFailure); after.After(wait) {
			wait = after
		}
	}
	return wait
}

// Request starts an attempt from the page: the first certificate for the
// domain, or a renewal ahead of its time. It returns once the attempt has
// started; Status shows how it goes. agree is the owner's agreement to the
// authority's terms, which the first certificate needs.
func (s *Service) Request(ctx context.Context, actor, remote string, agree bool) error {
	if s.cfg.Disabled != "" {
		return &ChangeError{s.cfg.Disabled}
	}
	account, configured, err := s.cfg.Account(ctx)
	if err != nil {
		return err
	}
	if !configured {
		return &ChangeError{"A certificate is for a domain. Set up the domain first."}
	}
	status, err := s.Status(ctx)
	if err != nil {
		return err
	}
	switch {
	case status.Running != nil:
		return &ChangeError{"A certificate is being requested already."}
	case status.WaitUntil != nil:
		return &ChangeError{"Not yet: the certificate authority counts requests and failures, so SGC waits until " +
			status.WaitUntil.Local().Format("15:04 on 2 January") + " before asking again."}
	case !status.TermsAgreed && !agree:
		return &ChangeError{"A certificate from Let's Encrypt needs your agreement to its terms."}
	}
	if !status.TermsAgreed {
		if err := s.writeJSON(ctx, SettingTerms, terms{AgreedAt: s.cfg.Now(), By: actor}); err != nil {
			return err
		}
		s.record(ctx, actor, audit.ActionCertificateTermsAgreed, "the terms of Let's Encrypt", remote)
	}
	kind := KindManual
	if status.Certificate == nil || !status.Certificate.ForDomain {
		kind = KindFirst
	}
	if !s.start(kind, actor, account) {
		return &ChangeError{"A certificate cannot be requested right now: SGC is starting or stopping."}
	}
	return nil
}

// start begins an attempt in the background, unless one is running or SGC
// is not running attempts at the moment.
func (s *Service) start(kind, actor string, account Account) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base == nil || s.base.Err() != nil || s.running != nil {
		return false
	}
	phase := "real"
	if kind == KindFirst {
		phase = "trial"
	}
	s.running = &Progress{Kind: kind, Phase: phase, Since: s.cfg.Now()}
	base := s.base
	s.jobs.Add(1)
	go func() {
		defer s.jobs.Done()
		s.attempt(base, kind, actor, account)
	}()
	return true
}

// attempt is one try at a certificate, from start to the entry in the history.
func (s *Service) attempt(ctx context.Context, kind, actor string, account Account) {
	started := s.cfg.Now()
	issued, err := s.issue(ctx, kind, account)

	s.mu.Lock()
	log := append([]string(nil), s.running.Log...)
	s.mu.Unlock()
	// "Running" ends last, after the result and the history are written:
	// whoever sees that nothing is running finds how it went.
	defer func() {
		s.mu.Lock()
		s.running = nil
		s.mu.Unlock()
	}()

	result := Attempt{Kind: kind, StartedAt: started, FinishedAt: s.cfg.Now(), OK: err == nil, Log: log}
	if err != nil {
		result.Message = words(err)
		s.cfg.Log.Error("get the certificate", "kind", kind, "error", err)
	}
	if err := s.writeJSON(ctx, SettingAttempt, result); err != nil {
		s.cfg.Log.Error("keep how the attempt went", "error", err)
	}
	switch {
	case err != nil && kind == KindRenewal:
		// The next try is a while off, and the page shows that it is failing.
		if _, leaf, readErr := s.current(ctx); readErr == nil && leaf != nil {
			plan := s.plan(ctx, leaf)
			plan.FailedAt = s.cfg.Now()
			if err := s.writeJSON(ctx, SettingRenewal, plan); err != nil {
				s.cfg.Log.Error("keep the renewal plan", "error", err)
			}
		}
		s.record(ctx, audit.ActorSystem, audit.ActionCertificateFailed, "renewing: "+result.Message, "")
	case err != nil:
		s.record(ctx, actor, audit.ActionCertificateFailed, result.Message, "")
	case kind == KindFirst:
		s.record(ctx, actor, audit.ActionCertificateIssued, describe(issued), "")
	default:
		s.record(ctx, actor, audit.ActionCertificateRenewed, describe(issued), "")
	}
}

func describe(leaf *x509.Certificate) string {
	return strings.Join(leaf.DNSNames, ", ") + ", from " + issuerName(leaf) + ", valid until " + leaf.NotAfter.UTC().Format("2 January 2006")
}

func issuerName(leaf *x509.Certificate) string {
	name := leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 && leaf.Issuer.Organization[0] != "" {
		if name == "" {
			return leaf.Issuer.Organization[0]
		}
		name += " (" + leaf.Issuer.Organization[0] + ")"
	}
	return name
}

// issue gets a certificate for the account's domain and keeps it.
func (s *Service) issue(ctx context.Context, kind string, account Account) (*x509.Certificate, error) {
	zoneClient, err := zone.NewClient(s.cfg.ZoneEndpoint, account.Username, account.APIKey, s.cfg.UserAgent, s.cfg.ZoneHTTP)
	if err != nil {
		return nil, err
	}
	// What an attempt that was cut short left at Zone.eu goes first.
	if err := s.removeOpenRecords(ctx, zoneClient); err != nil {
		return nil, err
	}
	names := []string{"*." + account.Domain}

	if kind == KindFirst {
		s.say("Trying with the certificate authority's test authority first.")
		if _, err := s.obtain(ctx, s.cfg.TrialDirectory, account, zoneClient, names); err != nil {
			return nil, &phaseError{trial: true, err: err}
		}
		s.say("The test authority issued a certificate, which is thrown away: the set-up works.")
		if s.cfg.TrialGap > 0 {
			s.phase("pause")
			s.say("Waiting " + plainDuration(s.cfg.TrialGap) + " before asking for the real certificate. The trial's proof was under the same name, and every name server, also the ones far away, has to have forgotten it.")
			if err := wait(ctx, s.cfg.TrialGap); err != nil {
				return nil, err
			}
		}
		s.phase("real")
	}
	s.say("Asking the certificate authority for the certificate.")
	resource, err := s.obtain(ctx, s.cfg.Directory, account, zoneClient, names)
	if err != nil {
		return nil, &phaseError{err: err}
	}
	leaf, err := leafOf(string(resource.Certificate))
	if err != nil {
		return nil, fmt.Errorf("the authority's answer holds no certificate: %w", err)
	}
	kept := stored{
		Domain: account.Domain, CertificatePEM: string(resource.Certificate), PrivateKeyPEM: string(resource.PrivateKey),
		Directory: s.cfg.Directory, ObtainedAt: s.cfg.Now(),
	}
	if err := s.writeJSON(ctx, SettingCurrent, kept); err != nil {
		return nil, err
	}
	s.forgetServing()
	// A new certificate has a renewal time of its own.
	if err := store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingRenewal, ""); err != nil {
		return nil, err
	}
	s.say("The certificate is here, valid until " + leaf.NotAfter.UTC().Format("2 January 2006") + ".")
	return leaf, nil
}

// phaseError says in which of the two phases an attempt failed.
type phaseError struct {
	trial bool
	err   error
}

func (e *phaseError) Error() string { return e.err.Error() }
func (e *phaseError) Unwrap() error { return e.err }

// client returns lego's client for an authority, with SGC's account there.
// The account is opened if SGC has none yet.
func (s *Service) client(ctx context.Context, directory string) (*lego.Client, error) {
	accounts := map[string]accountRecord{}
	if _, err := s.readJSON(ctx, SettingAccounts, &accounts); err != nil {
		return nil, err
	}
	user := &acmeUser{}
	if record, has := accounts[directory]; has {
		key, err := certcrypto.ParsePEMPrivateKey([]byte(record.PrivateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("the key of SGC's account at the authority cannot be read: %w", err)
		}
		user.key, user.registration = key, &registration.Resource{URI: record.URI}
	} else {
		key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, err
		}
		user.key = key
	}

	config := lego.NewConfig(user)
	config.CADirURL = directory
	config.UserAgent = s.cfg.UserAgent
	config.Certificate.KeyType = certcrypto.EC256
	// Every request to the authority ends when the attempt is told to.
	httpClient := *s.cfg.AuthorityHTTP
	base := httpClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	httpClient.Transport = bound{ctx: ctx, base: base}
	config.HTTPClient = &httpClient

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	if user.registration == nil {
		// The owner agreed in SGC's page before any attempt starts.
		opened, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
		user.registration = opened
		accounts[directory] = accountRecord{PrivateKeyPEM: string(certcrypto.PEMEncode(user.key)), URI: opened.URI}
		if err := s.writeJSON(ctx, SettingAccounts, accounts); err != nil {
			return nil, err
		}
		if directory == s.cfg.Directory {
			var agreed terms
			if found, _ := s.readJSON(ctx, SettingTerms, &agreed); found && agreed.URL == "" {
				agreed.URL = client.GetToSURL()
				s.writeJSON(ctx, SettingTerms, agreed)
			}
		}
	}
	return client, nil
}

// obtain gets a certificate from one authority.
//
// An authority can forget an account: Let's Encrypt's test authority is
// emptied now and then, and an account can be closed. SGC's account is
// nothing but a key, so it then opens a new one and goes on, once.
func (s *Service) obtain(ctx context.Context, directory string, account Account, zoneClient *zone.Client, names []string) (*certificate.Resource, error) {
	resource, err := s.obtainOnce(ctx, directory, account, zoneClient, names)
	var problem *acme.ProblemDetails
	if err == nil || !errors.As(err, &problem) || !strings.HasSuffix(problem.Type, ":accountDoesNotExist") {
		return resource, err
	}
	s.say("The authority no longer knows SGC's account there. Opening a new one.")
	accounts := map[string]accountRecord{}
	if _, err := s.readJSON(ctx, SettingAccounts, &accounts); err != nil {
		return nil, err
	}
	delete(accounts, directory)
	if err := s.writeJSON(ctx, SettingAccounts, accounts); err != nil {
		return nil, err
	}
	return s.obtainOnce(ctx, directory, account, zoneClient, names)
}

// obtainOnce goes through one authority's steps for a certificate.
func (s *Service) obtainOnce(ctx context.Context, directory string, account Account, zoneClient *zone.Client, names []string) (*certificate.Resource, error) {
	client, err := s.client(ctx, directory)
	if err != nil {
		return nil, err
	}
	options := []dns01.ChallengeOption{
		dns01.WrapPreCheck(func(_, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			// When the attempt is told to end, the wait for the record
			// ends: what follows is a request to the authority, which then
			// fails at once.
			if ctx.Err() != nil {
				return true, nil
			}
			shown, err := check(fqdn, value)
			if !shown || err != nil || s.cfg.Settle <= 0 {
				return shown, err
			}
			s.say("The proof shows at the name servers. Waiting " + plainDuration(s.cfg.Settle) + " more, for name servers further away.")
			wait(ctx, s.cfg.Settle)
			return true, nil
		}),
	}
	if s.cfg.DNSResolver != "" {
		options = append(options,
			dns01.AddRecursiveNameservers([]string{s.cfg.DNSResolver}),
			dns01.DisableAuthoritativeNssPropagationRequirement(),
			dns01.RecursiveNSsPropagationRequirement())
	} else if servers := systemResolvers(s.cfg.ResolvConf); len(servers) > 0 {
		// lego reads the system's list of DNS servers once, when the program
		// starts, and that list changes: on a device with systemd-resolved
		// it does on the day AdGuard Home takes over port 53, after which
		// the old entry is AdGuard Home itself. So it is read for every
		// attempt. Nothing SGC does to keep its certificate may depend on
		// AdGuard Home running.
		options = append(options, dns01.AddRecursiveNameservers(servers))
	}
	if err := client.Challenge.SetDNS01Provider(&records{ctx: ctx, service: s, zone: zoneClient, domain: account.Domain}, options...); err != nil {
		return nil, err
	}
	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: names, Bundle: true})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return resource, nil
}

// systemResolvers returns the DNS servers the device itself asks, as
// "address:port", or nothing if the list cannot be read.
func systemResolvers(path string) []string {
	if path == "" {
		path = "/etc/resolv.conf"
	}
	config, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil
	}
	var servers []string
	for _, server := range config.Servers {
		servers = append(servers, net.JoinHostPort(server, config.Port))
	}
	return servers
}

// wait lets time pass, unless ctx ends first.
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// plainDuration writes a wait the way it is said: "2 minutes", "45 seconds".
func plainDuration(d time.Duration) string {
	unit, count := "second", int(d.Round(time.Second)/time.Second)
	if d >= time.Minute && d%time.Minute == 0 {
		unit, count = "minute", int(d/time.Minute)
	}
	if count != 1 {
		unit += "s"
	}
	return fmt.Sprintf("%d %s", count, unit)
}

// phase says which part of an attempt is under way.
func (s *Service) phase(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != nil {
		s.running.Phase = name
	}
}

// acmeUser is SGC as an authority's account holder. No e-mail address: Let's
// Encrypt no longer writes to its account holders, and SGC does the warning
// itself.
type acmeUser struct {
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return "" }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// bound makes requests end with a context.
type bound struct {
	ctx  context.Context
	base http.RoundTripper
}

func (b bound) RoundTrip(r *http.Request) (*http.Response, error) {
	return b.base.RoundTrip(r.WithContext(b.ctx))
}

// records is what lego calls to have the proof published and removed.
type records struct {
	ctx     context.Context
	service *Service
	zone    *zone.Client
	domain  string
}

func (r *records) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	name := dns01.UnFqdn(info.EffectiveFQDN)
	if !strings.HasSuffix(name, "."+r.domain) {
		return fmt.Errorf("the proof for %s belongs under %s, which is not in the zone of %s", domain, name, r.domain)
	}
	created, err := r.zone.AddTXT(r.ctx, r.domain, name, info.Value)
	if err != nil {
		return err
	}
	r.service.say("Published the proof at Zone.eu, under " + name + ".")
	return r.service.rememberRecord(r.ctx, openRecord{Domain: r.domain, ID: created.ID, Name: name, Value: info.Value})
}

func (r *records) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	name := dns01.UnFqdn(info.EffectiveFQDN)
	// The attempt may have been told to end; what it published goes all the same.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 30*time.Second)
	defer cancel()
	return r.service.forgetRecords(ctx, r.zone, func(open openRecord) bool { return open.Name == name && open.Value == info.Value })
}

func (r *records) Timeout() (timeout, interval time.Duration) {
	return r.service.cfg.PropagationTimeout, r.service.cfg.PropagationInterval
}

func (s *Service) rememberRecord(ctx context.Context, record openRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var open []openRecord
	if _, err := s.readJSON(ctx, SettingOpenRecords, &open); err != nil {
		return err
	}
	return s.writeJSON(ctx, SettingOpenRecords, append(open, record))
}

// forgetRecords removes the records the filter picks at Zone.eu and from the
// list. A record that cannot be removed stays on the list, for the next try.
func (s *Service) forgetRecords(ctx context.Context, zoneClient *zone.Client, pick func(openRecord) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var open, left []openRecord
	if _, err := s.readJSON(ctx, SettingOpenRecords, &open); err != nil {
		return err
	}
	var failure error
	for _, record := range open {
		if !pick(record) {
			left = append(left, record)
			continue
		}
		if err := zoneClient.DeleteTXT(ctx, record.Domain, record.ID); err != nil {
			left, failure = append(left, record), err
		}
	}
	if err := s.writeJSON(ctx, SettingOpenRecords, left); err != nil {
		return err
	}
	return failure
}

func (s *Service) removeOpenRecords(ctx context.Context, zoneClient *zone.Client) error {
	err := s.forgetRecords(ctx, zoneClient, func(openRecord) bool { return true })
	if err != nil {
		return fmt.Errorf("remove what an earlier attempt left at Zone.eu: %w", err)
	}
	return nil
}

// Run renews the certificate when it is time, until ctx ends, and is what
// attempts started from the page run under.
func (s *Service) Run(ctx context.Context) {
	s.mu.Lock()
	s.base = ctx
	s.mu.Unlock()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// An attempt in progress is given a moment to remove what it
			// published. What it leaves is on the list for the next one.
			done := make(chan struct{})
			go func() { s.jobs.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(stopGrace):
				s.cfg.Log.Warn("an attempt at a certificate was still running when SGC stopped")
			}
			return
		case <-ticker.C:
			s.Tick(ctx)
		}
	}
}

// Tick starts a renewal if one is due. Run calls it every minute.
func (s *Service) Tick(ctx context.Context) {
	if s.cfg.Disabled != "" {
		return
	}
	account, configured, err := s.cfg.Account(ctx)
	if err != nil || !configured {
		return
	}
	kept, leaf, err := s.current(ctx)
	if err != nil || kept == nil || kept.Domain != account.Domain || kept.Directory != s.cfg.Directory {
		return
	}
	s.mu.Lock()
	busy := s.running != nil
	s.mu.Unlock()
	if busy {
		return
	}
	now := s.cfg.Now()
	plan := s.plan(ctx, leaf)
	if now.Sub(plan.AskedAt) >= askEvery || plan.AskedAt.After(now) {
		plan = s.ask(ctx, leaf, plan)
	}
	if now.Before(plan.RenewAt) {
		return
	}
	if !plan.FailedAt.IsZero() && now.Sub(plan.FailedAt) >= 0 && now.Sub(plan.FailedAt) < retryRenewalAfter {
		return
	}
	s.start(KindRenewal, audit.ActorSystem, account)
}

// plan returns when the certificate is to be renewed, as last worked out.
// Without anything worked out yet: when two thirds of its life are over.
func (s *Service) plan(ctx context.Context, leaf *x509.Certificate) renewal {
	var plan renewal
	serial := leaf.SerialNumber.Text(16)
	if found, err := s.readJSON(ctx, SettingRenewal, &plan); err == nil && found && plan.Serial == serial {
		return plan
	}
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return renewal{Serial: serial, RenewAt: leaf.NotBefore.Add(life * 2 / 3)}
}

// ask puts the question "when do you want this renewed" to the authority
// and keeps the answer. If the authority does not say, the plan stays.
func (s *Service) ask(ctx context.Context, leaf *x509.Certificate, plan renewal) renewal {
	plan.AskedAt = s.cfg.Now()
	if client, err := s.client(ctx, s.cfg.Directory); err != nil {
		s.cfg.Log.Warn("ask the authority when to renew", "error", err)
	} else if info, err := client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf}); err != nil {
		// Not every authority answers this; the plan made from the
		// certificate's own dates stands.
		s.cfg.Log.Info("the authority did not say when to renew", "error", err)
	} else if window := info.SuggestedWindow; !window.Start.IsZero() && window.End.After(window.Start) {
		// The middle of the time the authority suggests. (An authority that
		// has withdrawn a certificate suggests a time that is past.)
		plan.RenewAt = window.Start.Add(window.End.Sub(window.Start) / 2)
	}
	if err := s.writeJSON(ctx, SettingRenewal, plan); err != nil {
		s.cfg.Log.Error("keep the renewal plan", "error", err)
	}
	return plan
}

// say adds a line to the log of the attempt in progress.
func (s *Service) say(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil {
		return
	}
	if len(s.running.Log) < maxLogLines {
		s.running.Log = append(s.running.Log, line)
	}
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

// lineLogger takes what lego reports. lego names the domain and the
// authority's addresses in it, never a key.
type lineLogger Service

func (l *lineLogger) line(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	(*Service)(l).cfg.Log.Debug("lego: " + text)
	(*Service)(l).say(text)
}

// lego calls Fatal where it means "this cannot go on". The attempt fails
// with the error lego returns; SGC itself goes on.
func (l *lineLogger) Fatal(args ...any)                 { l.line(fmt.Sprint(args...)) }
func (l *lineLogger) Fatalln(args ...any)               { l.line(fmt.Sprintln(args...)) }
func (l *lineLogger) Fatalf(format string, args ...any) { l.line(fmt.Sprintf(format, args...)) }
func (l *lineLogger) Print(args ...any)                 { l.line(fmt.Sprint(args...)) }
func (l *lineLogger) Println(args ...any)               { l.line(fmt.Sprintln(args...)) }
func (l *lineLogger) Printf(format string, args ...any) { l.line(fmt.Sprintf(format, args...)) }

// words says what went wrong in terms the owner can act on.
func words(err error) string {
	where := "Let's Encrypt"
	var phase *phaseError
	if errors.As(err, &phase) && phase.trial {
		where = "Let's Encrypt's test authority"
	}
	var problem *acme.ProblemDetails
	var refusal *zone.StatusError
	text := err.Error()
	switch {
	case errors.Is(err, context.Canceled):
		return "SGC was stopped while the certificate was being requested."
	case errors.Is(err, zone.ErrCredentials):
		return "Zone.eu does not accept the username and API key, so the proof could not be published."
	case errors.Is(err, zone.ErrNotFound):
		return "Zone.eu has no DNS zone for the domain in this account, so the proof could not be published."
	case errors.Is(err, zone.ErrRateLimited):
		return "Zone.eu answered that too many requests were made in the last minute. Try again in a few minutes."
	case errors.As(err, &refusal):
		return "The proof could not be published: " + refusal.Error() + "."
	case strings.Contains(text, "reach Zone.eu"):
		return "Zone.eu could not be reached, so the proof could not be published. Does this device reach the internet?"
	case errors.As(err, &problem) && strings.HasSuffix(problem.Type, ":rateLimited"):
		return where + " has reached its limit of requests for this domain: " + oneLine(problem.Detail) + " Try again later; SGC does not retry by itself before then."
	case errors.As(err, &problem) && strings.Contains(problem.Detail, "TXT record"):
		// "Incorrect TXT record ... found at ..." or "No TXT record found
		// at ...": the proof was published, and where the authority looked
		// it was not there yet, or an older one still was.
		return where + " did not find the proof in the domain's DNS: " + oneLine(problem.Detail) + " SGC had published it, and the name servers it could ask showed it; others had not caught up. Trying again later usually works."
	case errors.As(err, &problem):
		return where + " refused: " + oneLine(problem.Detail)
	case strings.Contains(text, "propagation") || strings.Contains(text, "time limit exceeded"):
		return "The proof was published at Zone.eu, but its name servers did not show it in time. That can take a while after a change; try again later."
	case strings.Contains(text, "dial tcp") || strings.Contains(text, "no such host") || strings.Contains(text, "connection refused") || strings.Contains(text, "i/o timeout"):
		return where + " could not be reached. Does this device reach the internet?"
	default:
		return "It did not work: " + oneLine(text)
	}
}

func oneLine(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if runes := []rune(text); len(runes) > 300 {
		text = string(runes[:300]) + "…"
	}
	if text != "" && !strings.HasSuffix(text, ".") {
		text += "."
	}
	return text
}

// KeyPair is the certificate in use, ready to serve.
type KeyPair struct {
	// Domain is the domain it is for (the certificate's name is "*." + Domain).
	Domain         string
	CertificatePEM string
	PrivateKeyPEM  string
	TLS            *tls.Certificate
	NotAfter       time.Time
}

// Serving returns the certificate to serve for the domain that is set up
// now, or nil if there is none that is valid for it. It reads the database
// at most every ten seconds; a renewed certificate is therefore served from
// then on, without a restart.
func (s *Service) Serving(ctx context.Context) (*KeyPair, error) {
	s.servingMu.Lock()
	defer s.servingMu.Unlock()
	now := time.Now()
	if !s.servingAt.IsZero() && now.Sub(s.servingAt) < 10*time.Second {
		return s.valid(s.serving, now), nil
	}
	raw, _, err := store.Setting(ctx, s.cfg.DB, SettingCurrent)
	if err != nil {
		return nil, err
	}
	account, configured, err := s.cfg.Account(ctx)
	if err != nil {
		return nil, err
	}
	key := raw + "\x00" + account.Domain
	if key == s.servingRaw && !s.servingAt.IsZero() {
		s.servingAt = now
		return s.valid(s.serving, now), nil
	}
	s.servingRaw, s.servingAt, s.serving = key, now, nil
	if raw == "" || !configured {
		return nil, nil
	}
	var kept stored
	if err := json.Unmarshal([]byte(raw), &kept); err != nil {
		return nil, fmt.Errorf("the kept certificate cannot be read: %w", err)
	}
	if kept.Domain != account.Domain {
		return nil, nil // a certificate for a domain that is no longer set up
	}
	pair, err := tls.X509KeyPair([]byte(kept.CertificatePEM), []byte(kept.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("the kept certificate and its key do not fit together: %w", err)
	}
	s.serving = &KeyPair{Domain: kept.Domain, CertificatePEM: kept.CertificatePEM, PrivateKeyPEM: kept.PrivateKeyPEM, TLS: &pair, NotAfter: pair.Leaf.NotAfter}
	return s.valid(s.serving, now), nil
}

// forgetServing makes the next Serving read the database: a certificate
// that was just obtained is served from the next connection on, not up to
// ten seconds later (the whole-machine test asked within those ten seconds
// and got the self-signed one).
func (s *Service) forgetServing() {
	s.servingMu.Lock()
	defer s.servingMu.Unlock()
	s.servingAt = time.Time{}
}

func (s *Service) valid(pair *KeyPair, now time.Time) *KeyPair {
	if pair == nil || !now.Before(pair.NotAfter) {
		return nil
	}
	return pair
}
