package certcontrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/certcontrol/acmetest"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/zone"
	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

const (
	username = "alex"
	apiKey   = "a-made-up-api-key"
	domain   = "domain.tld"
)

// env is a whole small world: Zone.eu's stand-in (API and name servers), two
// authorities (the test one and the "real" one, both Pebble), and SGC's
// certificate part between them.
type env struct {
	t       *testing.T
	db      *sql.DB
	zone    *zonetest.Server
	zoneAPI *httptest.Server
	trial   *acmetest.Authority
	real    *acmetest.Authority
	service *Service
	// Added to the clock SGC decides by.
	offset time.Duration
	// The account SGC is given; nil is "no domain set up".
	account *Account
	options options
	// cancel stops the service; stopped is closed when it has stopped.
	cancel  func()
	stopped chan struct{}
}

// options are what differs from one small world to the next.
type options struct {
	// The authorities see the name servers as they were this long ago, as
	// from the other side of the world. SGC sees them as they are.
	authorityLag time.Duration
	settle       time.Duration
	trialGap     time.Duration
}

func newEnv(t *testing.T) *env { return newEnvWith(t, options{}) }

func newEnvWith(t *testing.T, o options) *env {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, zone: zonetest.New(username, apiKey, domain), account: &Account{Domain: domain, Username: username, APIKey: apiKey}, options: o}
	e.zoneAPI = httptest.NewServer(e.zone)
	dnsAddress, stopDNS, err := e.zone.ListenDNS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authorityDNS, stopFarDNS := dnsAddress, func() {}
	if o.authorityLag > 0 {
		if authorityDNS, stopFarDNS, err = e.zone.ListenLaggingDNS("127.0.0.1:0", o.authorityLag); err != nil {
			t.Fatal(err)
		}
	}
	e.trial, e.real = acmetest.New(authorityDNS), acmetest.New(authorityDNS)
	trialServer, realServer := httptest.NewTLSServer(e.trial), httptest.NewTLSServer(e.real)

	e.service = New(e.config(trialServer, realServer, dnsAddress))
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	e.cancel, e.stopped = cancel, stopped
	go func() { e.service.Run(ctx); close(stopped) }()
	// Run has to have started before anything is requested.
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.service.mu.Lock()
		started := e.service.base != nil
		e.service.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the service never started")
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		<-stopped
		trialServer.Close()
		realServer.Close()
		e.zoneAPI.Close()
		stopDNS()
		stopFarDNS()
		db.Close()
	})
	return e
}

func (e *env) config(trialServer, realServer *httptest.Server, dnsAddress string) Config {
	return Config{
		DB: e.db, Audit: audit.New(e.db), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Account: func(context.Context) (Account, bool, error) {
			if e.account == nil {
				return Account{}, false, nil
			}
			return *e.account, true, nil
		},
		ZoneEndpoint: e.zoneAPI.URL + "/v2/", ZoneHTTP: &http.Client{Timeout: 5 * time.Second}, UserAgent: "sgc/test",
		Directory: realServer.URL + acmetest.DirectoryPath, TrialDirectory: trialServer.URL + acmetest.DirectoryPath,
		// Every test server of this kind shows the same certificate, which
		// its client trusts.
		AuthorityHTTP:      realServer.Client(),
		DNSResolver:        dnsAddress,
		PropagationTimeout: 3 * time.Second, PropagationInterval: 100 * time.Millisecond,
		Settle: e.options.settle, TrialGap: e.options.trialGap,
		RetryAfterFailure: 5 * time.Minute, RenewAgainAfter: time.Hour,
		Now: func() time.Time { return time.Now().Add(e.offset) },
	}
}

func (e *env) status() Status {
	e.t.Helper()
	status, err := e.service.Status(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return status
}

// finished waits for the attempt in progress to end and returns how it went.
func (e *env) finished() Status {
	e.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		status := e.status()
		if status.Running == nil {
			return status
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("the attempt never ended: %+v", status.Running)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *env) request(agree bool) error {
	return e.service.Request(context.Background(), "alex", "192.168.1.10", agree)
}

func (e *env) refused(err error, words string) {
	e.t.Helper()
	var failure *ChangeError
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, words) {
		e.t.Errorf("want a refusal with %q, got: %v", words, err)
	}
}

func (e *env) history(count int) string {
	e.t.Helper()
	entries, err := audit.New(e.db).Recent(context.Background(), count)
	if err != nil {
		e.t.Fatal(err)
	}
	var lines []string
	for _, entry := range entries {
		lines = append(lines, entry.Actor+" "+entry.Action)
	}
	return strings.Join(lines, ", ")
}

// kept returns the certificate as it is in the database.
func (e *env) kept() stored {
	e.t.Helper()
	var kept stored
	if found, err := e.service.readJSON(context.Background(), SettingCurrent, &kept); err != nil || !found {
		e.t.Fatalf("no certificate is kept: %v", err)
	}
	return kept
}

func TestTheFirstCertificate(t *testing.T) {
	e := newEnv(t)
	if s := e.status(); s.Domain != domain || s.Certificate != nil || s.TermsAgreed || s.Running != nil || s.LastAttempt != nil {
		t.Fatalf("to begin with: %+v", s)
	}
	// Not without the owner's agreement to the authority's terms.
	e.refused(e.request(false), "needs your agreement")
	if e.trial.Requests()+e.real.Requests() != 0 {
		t.Fatal("an authority was asked before the owner agreed")
	}

	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	// A second request while the first runs is refused.
	e.refused(e.request(true), "already")
	s := e.finished()
	if s.LastAttempt == nil || !s.LastAttempt.OK || s.LastAttempt.Kind != KindFirst || len(s.LastAttempt.Log) == 0 {
		t.Fatalf("the attempt: %+v", s.LastAttempt)
	}
	// The test authority was asked first, then the real one, once each.
	if e.trial.Orders() != 1 || e.real.Orders() != 1 {
		t.Errorf("certificates asked for: %d at the test authority, %d at the real one", e.trial.Orders(), e.real.Orders())
	}
	c := s.Certificate
	if c == nil || len(c.Names) != 1 || c.Names[0] != "*."+domain || !c.ForDomain || !c.NotAfter.After(time.Now()) || c.Issuer == "" || c.Serial == "" {
		t.Fatalf("the certificate: %+v", c)
	}
	if !s.TermsAgreed || s.RenewsAt == nil || !s.RenewsAt.After(c.NotBefore) || !s.RenewsAt.Before(c.NotAfter) {
		t.Errorf("after the first certificate: agreed %v, renews at %v", s.TermsAgreed, s.RenewsAt)
	}

	// What is kept is a certificate of the real authority for every name
	// under the domain, with the key that belongs to it.
	kept := e.kept()
	pair, err := tls.X509KeyPair([]byte(kept.CertificatePEM), []byte(kept.PrivateKeyPEM))
	if err != nil {
		t.Fatalf("certificate and key do not belong together: %v", err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	between := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			between.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "gateway." + domain, Roots: e.real.Roots(), Intermediates: between}); err != nil {
		t.Errorf("the certificate does not lead up to the real authority: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "gateway." + domain, Roots: e.trial.Roots(), Intermediates: between}); err == nil {
		t.Error("the kept certificate is the test authority's")
	}

	// Nothing is left at Zone.eu, and nothing is waiting to be removed.
	if e.zone.Records() != 0 {
		t.Errorf("records left at Zone.eu: %d", e.zone.Records())
	}
	var open []openRecord
	e.service.readJSON(context.Background(), SettingOpenRecords, &open)
	if len(open) != 0 {
		t.Errorf("records still on the list: %+v", open)
	}
	// An account at each authority is kept, for the next time.
	accounts := map[string]accountRecord{}
	e.service.readJSON(context.Background(), SettingAccounts, &accounts)
	if len(accounts) != 2 {
		t.Errorf("accounts kept: %d", len(accounts))
	}
	if e.history(2) != "alex certificate.issued, alex certificate.terms_agreed" {
		t.Errorf("history: %s", e.history(2))
	}
	// What the page gets holds no key.
	shown, _ := json.Marshal(s)
	if strings.Contains(string(shown), "PRIVATE KEY") || strings.Contains(string(shown), apiKey) {
		t.Error("the answer to the page carries a key")
	}

	// Asking again right away is refused: the authority counts.
	e.refused(e.request(false), "Not yet")
	// Later it is a renewal ahead of its time: no trial, the same accounts.
	e.offset = 2 * time.Hour
	if err := e.request(false); err != nil {
		t.Fatal(err)
	}
	again := e.finished()
	if !again.LastAttempt.OK || again.LastAttempt.Kind != KindManual || again.Certificate.Serial == c.Serial {
		t.Errorf("the renewal from the page: %+v, serial %s then %s", again.LastAttempt, c.Serial, again.Certificate.Serial)
	}
	if e.trial.Orders() != 1 || e.real.Orders() != 2 {
		t.Errorf("certificates asked for after the renewal: %d and %d", e.trial.Orders(), e.real.Orders())
	}
	e.service.readJSON(context.Background(), SettingAccounts, &accounts)
	if len(accounts) != 2 || e.history(1) != "alex certificate.renewed" {
		t.Errorf("accounts %d, history %s", len(accounts), e.history(1))
	}
}

func TestWhatFailsWithTheTestAuthorityNeverReachesTheRealOne(t *testing.T) {
	e := newEnv(t)
	// The key was withdrawn at Zone.eu.
	e.zone.SetAPIKey("a-key-made-later")
	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	s := e.finished()
	if s.LastAttempt.OK || !strings.Contains(s.LastAttempt.Message, "Zone.eu does not accept the username and API key") || s.Certificate != nil {
		t.Fatalf("with a withdrawn key: %+v", s.LastAttempt)
	}
	if e.real.Orders() != 0 {
		t.Error("the real authority was asked although the trial failed")
	}
	if e.history(1) != "alex certificate.failed" {
		t.Errorf("history: %s", e.history(1))
	}
	// Not again at once.
	if s.WaitUntil == nil {
		t.Fatal("no wait after a failure")
	}
	e.refused(e.request(true), "Not yet")
	// With the key put right, and after the wait, it works.
	e.zone.SetAPIKey(apiKey)
	e.offset = 6 * time.Minute
	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	if s := e.finished(); !s.LastAttempt.OK || s.Certificate == nil {
		t.Errorf("afterwards: %+v", s.LastAttempt)
	}
}

func TestAProofTheNameServersDoNotShow(t *testing.T) {
	e := newEnv(t)
	e.zone.HideTXT(true)
	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	s := e.finished()
	if s.LastAttempt.OK || !strings.Contains(s.LastAttempt.Message, "did not show it in time") {
		t.Fatalf("with a proof that does not show: %+v", s.LastAttempt)
	}
	// What was published is removed again, also after a failure.
	if e.zone.Records() != 0 {
		t.Errorf("records left at Zone.eu after the failure: %d", e.zone.Records())
	}
	if e.real.Orders() != 0 {
		t.Error("the real authority was asked")
	}
}

func TestWhatAnInterruptedAttemptLeftIsRemovedFirst(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	client, err := zone.NewClient(e.zoneAPI.URL+"/v2/", username, apiKey, "sgc/test", &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	left, err := client.AddTXT(ctx, domain, "_acme-challenge."+domain, "from-an-attempt-that-was-cut-short")
	if err != nil {
		t.Fatal(err)
	}
	// A record of somebody else's under the same name is not SGC's to remove.
	if _, err := client.AddTXT(ctx, domain, "_acme-challenge."+domain, "made-by-the-owner"); err != nil {
		t.Fatal(err)
	}
	e.service.writeJSON(ctx, SettingOpenRecords, []openRecord{{Domain: domain, ID: left.ID, Name: left.Name, Value: left.Value}})

	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	if s := e.finished(); !s.LastAttempt.OK {
		t.Fatalf("the attempt: %+v", s.LastAttempt)
	}
	if got := e.zone.TXT("_acme-challenge." + domain); len(got) != 1 || got[0] != "made-by-the-owner" {
		t.Errorf("left at Zone.eu: %v", got)
	}
}

// An authority can forget an account (Let's Encrypt's test authority is
// emptied now and then). SGC's account is only a key: it opens a new one.
func TestAnAccountTheAuthorityNoLongerKnows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	first := e.finished()
	if !first.LastAttempt.OK {
		t.Fatalf("the first certificate: %+v", first.LastAttempt)
	}
	// As if the real authority had forgotten the account SGC has there.
	before := map[string]accountRecord{}
	e.service.readJSON(ctx, SettingAccounts, &before)
	forgotten := map[string]accountRecord{}
	for directory, account := range before {
		if directory == e.service.cfg.Directory {
			account.URI = account.URI[:strings.LastIndex(account.URI, "/")+1] + "an-account-that-is-gone"
		}
		forgotten[directory] = account
	}
	e.service.writeJSON(ctx, SettingAccounts, forgotten)

	e.offset = 2 * time.Hour
	if err := e.request(false); err != nil {
		t.Fatal(err)
	}
	s := e.finished()
	if !s.LastAttempt.OK || s.Certificate.Serial == first.Certificate.Serial {
		t.Fatalf("with a forgotten account: serial %s then %s; %+v", first.Certificate.Serial, s.Certificate.Serial, s.LastAttempt)
	}
	if !strings.Contains(strings.Join(s.LastAttempt.Log, "\n"), "Opening a new one") {
		t.Errorf("the attempt does not say that it opened a new account:\n%s", strings.Join(s.LastAttempt.Log, "\n"))
	}
	after := map[string]accountRecord{}
	e.service.readJSON(ctx, SettingAccounts, &after)
	real := e.service.cfg.Directory
	if len(after) != 2 || after[real].URI == forgotten[real].URI || after[real].PrivateKeyPEM == before[real].PrivateKeyPEM {
		t.Errorf("the account kept afterwards is the forgotten one")
	}
}

func TestRenewingByItself(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Nothing to renew: nothing happens.
	e.service.Tick(ctx)
	if e.status().Running != nil || e.real.Requests() != 0 {
		t.Fatal("a renewal started without a certificate")
	}
	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	first := e.finished()
	if !first.LastAttempt.OK {
		t.Fatalf("the first certificate: %+v", first.LastAttempt)
	}

	// Long before its time: the authority is asked when, and that is all.
	e.service.Tick(ctx)
	if e.status().Running != nil || e.real.Orders() != 1 {
		t.Fatal("a renewal started right after the certificate was issued")
	}
	var plan renewal
	if found, _ := e.service.readJSON(ctx, SettingRenewal, &plan); !found || plan.AskedAt.IsZero() || plan.Serial != first.Certificate.Serial ||
		!plan.RenewAt.After(first.Certificate.NotBefore) || !plan.RenewAt.Before(first.Certificate.NotAfter) {
		t.Errorf("the plan: %+v, for a certificate valid %v to %v", plan, first.Certificate.NotBefore, first.Certificate.NotAfter)
	}

	// When it is time: renewed, by the real authority alone.
	e.offset = plan.RenewAt.Sub(time.Now()) + time.Hour
	e.service.Tick(ctx)
	second := e.finished()
	if second.LastAttempt.Kind != KindRenewal || !second.LastAttempt.OK || second.Certificate.Serial == first.Certificate.Serial {
		t.Fatalf("the renewal: %+v", second.LastAttempt)
	}
	if e.trial.Orders() != 1 || e.real.Orders() != 2 || e.history(1) != "system certificate.renewed" {
		t.Errorf("asked for: %d and %d; history: %s", e.trial.Orders(), e.real.Orders(), e.history(1))
	}

	// A renewal that fails is said, and tried again later, not every minute.
	e.zone.SetAPIKey("a-key-made-later")
	e.service.Tick(ctx) // asks the authority about the new certificate
	e.service.readJSON(ctx, SettingRenewal, &plan)
	e.offset = plan.RenewAt.Sub(time.Now()) + time.Hour
	e.service.Tick(ctx)
	failed := e.finished()
	if failed.LastAttempt.OK || failed.LastAttempt.Kind != KindRenewal || failed.Certificate.Serial != second.Certificate.Serial {
		t.Fatalf("the failing renewal: %+v", failed.LastAttempt)
	}
	if e.history(1) != "system certificate.failed" {
		t.Errorf("history: %s", e.history(1))
	}
	e.service.Tick(ctx)
	if s := e.status(); s.Running != nil || !s.LastAttempt.StartedAt.Equal(failed.LastAttempt.StartedAt) {
		t.Error("the failed renewal was tried again at once")
	}
	e.offset += retryRenewalAfter + time.Minute
	e.zone.SetAPIKey(apiKey)
	e.service.Tick(ctx)
	if s := e.finished(); !s.LastAttempt.OK || s.Certificate.Serial == second.Certificate.Serial {
		t.Errorf("the next try: %+v", s.LastAttempt)
	}
}

// What the owner's first real attempt ran into: the name servers nearby show
// the proof, the authority asks from far away and does not see it yet.
func TestNameServersFarAwayAreBehind(t *testing.T) {
	// Asked at once, the authority finds nothing, and refuses.
	hasty := newEnvWith(t, options{authorityLag: 800 * time.Millisecond})
	if err := hasty.request(true); err != nil {
		t.Fatal(err)
	}
	if s := hasty.finished(); s.LastAttempt.OK || s.Certificate != nil {
		t.Fatalf("an authority that could not see the proof issued all the same: %+v", s.LastAttempt)
	}
	if hasty.zone.Records() != 0 {
		t.Errorf("records left at Zone.eu after the failure: %d", hasty.zone.Records())
	}

	// With a wait after the proof shows nearby, it works: the trial and the
	// real request, one after the other under the same name.
	patient := newEnvWith(t, options{authorityLag: 800 * time.Millisecond, settle: 1500 * time.Millisecond})
	if err := patient.request(true); err != nil {
		t.Fatal(err)
	}
	s := patient.finished()
	if !s.LastAttempt.OK || s.Certificate == nil {
		t.Fatalf("with a wait for the name servers far away: %+v", s.LastAttempt)
	}
	if steps := strings.Join(s.LastAttempt.Log, "\n"); strings.Count(steps, "Waiting 2 seconds more, for name servers further away") != 2 {
		t.Errorf("the wait is not in the steps of both requests:\n%s", steps)
	}
}

func TestThePauseBetweenTheTrialAndTheRealRequest(t *testing.T) {
	e := newEnvWith(t, options{trialGap: 1500 * time.Millisecond})
	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	paused := false
	deadline := time.Now().Add(90 * time.Second)
	for {
		s := e.status()
		if s.Running == nil {
			break
		}
		if s.Running.Phase == "pause" {
			paused = true
			// The trial is over, and the real authority has not been asked.
			if e.trial.Orders() != 1 || e.real.Orders() != 0 {
				t.Fatalf("during the pause: %d asked of the test authority, %d of the real one", e.trial.Orders(), e.real.Orders())
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the attempt never ended")
		}
		time.Sleep(5 * time.Millisecond)
	}
	s := e.status()
	if !paused || !s.LastAttempt.OK || s.Certificate == nil {
		t.Fatalf("paused %v; the attempt: %+v", paused, s.LastAttempt)
	}
	if steps := strings.Join(s.LastAttempt.Log, "\n"); !strings.Contains(steps, "Waiting 2 seconds before asking for the real certificate") {
		t.Errorf("the pause is not in the steps:\n%s", steps)
	}

	// A renewal has no trial and no pause.
	e.offset = 2 * time.Hour
	if err := e.request(false); err != nil {
		t.Fatal(err)
	}
	if again := e.finished(); !again.LastAttempt.OK || strings.Contains(strings.Join(again.LastAttempt.Log, "\n"), "before asking for the real certificate") {
		t.Errorf("the renewal: %+v", again.LastAttempt)
	}
}

func TestStoppingSGCDuringThePause(t *testing.T) {
	e := newEnvWith(t, options{trialGap: time.Minute})
	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		if s := e.status(); s.Running != nil && s.Running.Phase == "pause" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the pause never came")
		}
		time.Sleep(5 * time.Millisecond)
	}
	asked := time.Now()
	e.cancel()
	<-e.stopped
	if took := time.Since(asked); took > 5*time.Second {
		t.Errorf("stopping took %v", took)
	}
	var last Attempt
	if found, err := e.service.readJSON(context.Background(), SettingAttempt, &last); err != nil || !found || last.OK || !strings.Contains(last.Message, "SGC was stopped") {
		t.Errorf("how the attempt is remembered: %+v, %v", last, err)
	}
	if e.real.Orders() != 0 {
		t.Error("the real authority was asked")
	}
}

func TestTheDevicesOwnDNSServersAreReadForEveryAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	list := func(content string) string {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return strings.Join(systemResolvers(path), " ")
	}
	// As on a device with systemd-resolved before AdGuard Home was installed.
	if got := list("nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch home\n"); got != "127.0.0.53:53" {
		t.Errorf("the first list: %s", got)
	}
	// And after: the servers the network hands out.
	if got := list("# This is /run/systemd/resolve/resolv.conf\nnameserver 192.168.1.1\nnameserver 192.168.1.2\n"); got != "192.168.1.1:53 192.168.1.2:53" {
		t.Errorf("the list after it changed: %s", got)
	}
	os.Remove(path)
	if got := systemResolvers(path); got != nil {
		t.Errorf("without a list: %v", got)
	}
}

func TestWhatGoesWrongIsSaidInWords(t *testing.T) {
	// What Let's Encrypt answered on 2026-10-13, with a made-up domain.
	old := &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized", Detail: `Incorrect TXT record "the-trials-proof" found at _acme-challenge.domain.tld`}
	got := words(&phaseError{err: old})
	if !strings.HasPrefix(got, "Let's Encrypt did not find the proof in the domain's DNS: Incorrect TXT record") || !strings.Contains(got, "Trying again later usually works") {
		t.Errorf("an older proof still being served: %s", got)
	}
	if got := words(&phaseError{trial: true, err: old}); !strings.HasPrefix(got, "Let's Encrypt's test authority did not find the proof") {
		t.Errorf("the same from the test authority: %s", got)
	}
	limited := &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited", Detail: "too many failed authorizations (5) for \"domain.tld\" in the last 1h0m0s"}
	if got := words(&phaseError{err: limited}); !strings.Contains(got, "has reached its limit") {
		t.Errorf("a limit: %s", got)
	}
	if got := words(context.Canceled); !strings.Contains(got, "SGC was stopped") {
		t.Errorf("stopped: %s", got)
	}
	for d, want := range map[time.Duration]string{2 * time.Minute: "2 minutes", time.Minute: "1 minute", 90 * time.Second: "90 seconds", 1500 * time.Millisecond: "2 seconds", time.Second: "1 second"} {
		if got := plainDuration(d); got != want {
			t.Errorf("%v is written as %q, want %q", d, got, want)
		}
	}
}

func TestWithoutADomainAndWhenSwitchedOff(t *testing.T) {
	e := newEnv(t)
	e.account = nil
	if s := e.status(); s.Domain != "" {
		t.Errorf("without a domain: %+v", s)
	}
	e.refused(e.request(true), "Set up the domain first")
	e.service.Tick(context.Background())

	// A domain other than the certificate's: the certificate is shown as not
	// for it, and the next request is a first certificate again.
	e.account = &Account{Domain: domain, Username: username, APIKey: apiKey}
	if err := e.request(true); err != nil {
		t.Fatal(err)
	}
	if s := e.finished(); !s.LastAttempt.OK {
		t.Fatalf("the certificate: %+v", s.LastAttempt)
	}
	e.account = &Account{Domain: "other.tld", Username: username, APIKey: apiKey}
	if s := e.status(); s.Certificate == nil || s.Certificate.ForDomain || s.RenewsAt != nil || s.WaitUntil != nil {
		t.Errorf("with another domain set up: %+v", s)
	}
	e.service.Tick(context.Background())
	if e.status().Running != nil {
		t.Error("a certificate for an earlier domain was renewed")
	}

	// An SGC that is told not to get certificates gets none.
	e.service.cfg.Disabled = "This SGC is pointed at a stand-in for Zone.eu but not for Let's Encrypt."
	e.refused(e.request(true), "stand-in")
	if e.status().Disabled == "" {
		t.Error("the page is not told")
	}
}
