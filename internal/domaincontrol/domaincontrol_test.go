package domaincontrol

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsprovider"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

const (
	username = "alex"
	apiKey   = "a-made-up-api-key"
)

type env struct {
	t       *testing.T
	db      *sql.DB
	zone    *zonetest.Server
	server  *httptest.Server
	service *Service
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{t: t, db: db, zone: zonetest.New(username, apiKey, "domain.tld"), now: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	e.server = httptest.NewServer(e.zone)
	t.Cleanup(e.server.Close)
	e.service = New(Config{
		DB: db, Audit: audit.New(db), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		DNS: dnsprovider.Options{ZoneEndpoint: e.server.URL + "/v2/", StandIn: true, HTTP: &http.Client{Timeout: 5 * time.Second}, UserAgent: "sgc/test"},
		Now: func() time.Time { return e.now },
	})
	return e
}

func (e *env) status() Status {
	e.t.Helper()
	status, err := e.service.Status(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return status
}

func (e *env) lastHistory() string {
	e.t.Helper()
	entries, err := audit.New(e.db).Recent(context.Background(), 1)
	if err != nil || len(entries) == 0 {
		return ""
	}
	return entries[0].Actor + " " + entries[0].Action + " " + entries[0].Detail
}

func (e *env) refused(err error, words string) {
	e.t.Helper()
	var failure *ChangeError
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, words) {
		e.t.Errorf("want a refusal with %q, got: %v", words, err)
	}
}

func TestSavingADomainAsksZoneFirst(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if s := e.status(); s.Configured || s.Domain != "" {
		t.Fatalf("to begin with: %+v", s)
	}

	// Refused by Zone.eu, each for its own reason: nothing is kept.
	e.refused(e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, "another-key")), "does not accept the username and API key")
	e.refused(e.service.Save(ctx, "alex", "", "other.tld", "zone", values(username, apiKey)), "has no DNS zone for other.tld")
	e.zone.SetActive("domain.tld", false)
	e.refused(e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, apiKey)), "is not active")
	e.zone.SetActive("domain.tld", true)
	e.zone.FailWith(http.StatusInternalServerError)
	e.refused(e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, apiKey)), "answered with an error (500")
	e.zone.FailWith(0)
	if s := e.status(); s.Configured {
		t.Fatalf("something was kept after refusals: %+v", s)
	}

	// Refused by SGC itself, before Zone.eu is asked.
	asked := e.zone.Requests()
	e.refused(e.service.Save(ctx, "alex", "", "domain", "zone", values(username, apiKey)), "at least two parts")
	e.refused(e.service.Save(ctx, "alex", "", "domain.tld/../x", "zone", values(username, apiKey)), "letters, digits and hyphens only")
	e.refused(e.service.Save(ctx, "alex", "", "domain.tld", "zone", values("", apiKey)), "not a ZoneID username")
	e.refused(e.service.Save(ctx, "alex", "", "domain.tld", "zone", values("alex:x", apiKey)), "not a ZoneID username")
	e.refused(e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, "a key with spaces")), "not an API key")
	e.refused(e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, "")), "not an API key")
	if e.zone.Requests() != asked {
		t.Error("Zone.eu was asked about input that SGC should have refused itself")
	}

	// Accepted. The domain is kept as SGC writes it.
	if err := e.service.Save(ctx, "alex", "192.168.1.10", " Domain.TLD. ", "zone", values(" "+username+" ", apiKey+"\n")); err != nil {
		t.Fatal(err)
	}
	s := e.status()
	if !s.Configured || s.Domain != "domain.tld" || s.Shown["username"] != username || s.Provider != "zone" || s.ProviderName != "Zone.eu" || !s.OK || s.CheckedAt == nil || s.Problem != "" {
		t.Errorf("after saving: %+v", s)
	}
	if e.lastHistory() != "alex domain.saved domain.tld, with the Zone.eu account alex" {
		t.Errorf("history: %s", e.lastHistory())
	}
	// The key is kept, and is in neither the status nor the history.
	if kept, _, _ := store.Setting(ctx, e.db, SettingCredentials); kept != `{"apiKey":"`+apiKey+`","username":"alex"}` {
		t.Errorf("the key as kept: %q", kept)
	}
	entries, _ := audit.New(e.db).Recent(ctx, 20)
	for _, entry := range entries {
		if strings.Contains(entry.Detail, apiKey) {
			t.Errorf("the key is in the history: %+v", entry)
		}
	}

	// Removed: all of it is gone.
	if err := e.service.Remove(ctx, "alex", ""); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.Configured {
		t.Errorf("after removing: %+v", s)
	}
	if kept, _, _ := store.Setting(ctx, e.db, SettingCredentials); kept != "" || e.lastHistory() != "alex domain.removed domain.tld" {
		t.Errorf("after removing: key %q, history %s", kept, e.lastHistory())
	}
}

func TestWhenZoneStopsAcceptingTheKey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Nothing saved: nothing to ask.
	if s, err := e.service.CheckNow(ctx); err != nil || s.Configured || e.zone.Requests() != 0 {
		t.Fatalf("without an account: %+v, %v", s, err)
	}
	if err := e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, apiKey)); err != nil {
		t.Fatal(err)
	}

	// The key is withdrawn at Zone.eu.
	e.zone.SetAPIKey("a-new-key")
	e.now = e.now.Add(6 * time.Hour)
	since := e.now
	s, err := e.service.CheckNow(ctx)
	if err != nil || s.OK || !strings.Contains(s.Problem, "does not accept the username and API key") || s.FailingSince == nil || !s.FailingSince.Equal(since) {
		t.Fatalf("after the key was withdrawn: %+v, %v", s, err)
	}
	if e.lastHistory() != "system zone.check_failed Zone.eu does not accept the username and API key." {
		t.Errorf("history: %s", e.lastHistory())
	}
	// Still failing an hour later: the same failure, not a new one.
	e.now = e.now.Add(time.Hour)
	entriesBefore, _ := audit.New(e.db).Recent(ctx, 50)
	s, _ = e.service.CheckNow(ctx)
	entriesAfter, _ := audit.New(e.db).Recent(ctx, 50)
	if s.OK || !s.FailingSince.Equal(since) || len(entriesAfter) != len(entriesBefore) {
		t.Errorf("an hour later: %+v, history grew by %d", s, len(entriesAfter)-len(entriesBefore))
	}
	if got := e.status(); got.OK || got.Problem == "" || !got.CheckedAt.Equal(e.now) {
		t.Errorf("as the page sees it: %+v", got)
	}

	// The owner enters the new key: all is well again.
	if err := e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, "a-new-key")); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); !s.OK || s.Problem != "" || s.FailingSince != nil {
		t.Errorf("with the new key: %+v", s)
	}

	// Zone.eu cannot be reached: said as that, and as a turn in the history.
	e.server.Close()
	e.now = e.now.Add(6 * time.Hour)
	if s, _ := e.service.CheckNow(ctx); s.OK || !strings.Contains(s.Problem, "could not be reached") {
		t.Errorf("Zone.eu out of reach: %+v", s)
	}
	if !strings.HasPrefix(e.lastHistory(), "system zone.check_failed Zone.eu could not be reached") {
		t.Errorf("history: %s", e.lastHistory())
	}
}

func TestItComesBackByItself(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, apiKey)); err != nil {
		t.Fatal(err)
	}
	e.zone.FailWith(http.StatusTooManyRequests)
	if s, _ := e.service.CheckNow(ctx); s.OK || !strings.Contains(s.Problem, "too many requests") {
		t.Fatalf("past the limit: %+v", s)
	}
	e.zone.FailWith(0)
	if s, _ := e.service.CheckNow(ctx); !s.OK || s.FailingSince != nil {
		t.Fatalf("afterwards: %+v", s)
	}
	if e.lastHistory() != "system zone.check_recovered domain.tld" {
		t.Errorf("history: %s", e.lastHistory())
	}
}

func TestWhenZoneIsAsked(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Not without an account, however long SGC has been running.
	e.now = e.now.Add(time.Hour)
	if e.service.due(ctx) {
		t.Error("due without an account")
	}
	if err := e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, apiKey)); err != nil {
		t.Fatal(err)
	}
	// Saving asked Zone.eu just now.
	if e.service.due(ctx) {
		t.Error("due right after saving")
	}
	e.now = e.now.Add(checkEvery - time.Minute)
	if e.service.due(ctx) {
		t.Error("due before its time")
	}
	e.now = e.now.Add(time.Minute)
	if !e.service.due(ctx) {
		t.Error("not due when its time has come")
	}
	// While Zone.eu says no, it is asked sooner.
	e.zone.SetAPIKey("a-new-key")
	e.service.CheckNow(ctx)
	e.now = e.now.Add(retryEvery - time.Minute)
	if e.service.due(ctx) {
		t.Error("due again too soon after a failure")
	}
	e.now = e.now.Add(time.Minute)
	if !e.service.due(ctx) {
		t.Error("not due an hour after a failure")
	}
	// A clock that went back does not stop the questions.
	e.service.CheckNow(ctx)
	e.now = e.now.Add(-48 * time.Hour)
	if !e.service.due(ctx) {
		t.Error("not due after the clock went back")
	}

	// Right after start-up it waits a little, even if a check is long due.
	late := newEnv(t)
	if err := late.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, apiKey)); err != nil {
		t.Fatal(err)
	}
	restarted := New(late.service.cfg)
	late.now = late.now.Add(24 * time.Hour)
	restarted.started = late.now
	if restarted.due(ctx) {
		t.Error("due in the first minutes after start-up")
	}
	late.now = late.now.Add(startDelay)
	if !restarted.due(ctx) {
		t.Error("not due once start-up is over")
	}
}

func values(username, apiKey string) map[string]string {
	return map[string]string{"username": username, "apiKey": apiKey}
}

// An account saved before 0.18.0 (or restored from an export of then) is a
// Zone.eu account with two settings of its own; saving moves it.
func TestAnAccountFromBefore018(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for key, value := range map[string]string{SettingDomain: "domain.tld", legacyUsername: username, legacyAPIKey: apiKey} {
		if err := store.SetSetting(ctx, e.db, key, value); err != nil {
			t.Fatal(err)
		}
	}
	if s := e.status(); !s.Configured || s.Provider != "zone" || s.Shown["username"] != username {
		t.Fatalf("an old account reads as %+v", s)
	}
	a, configured, err := e.service.Account(ctx)
	if err != nil || !configured || a.Values["apiKey"] != apiKey {
		t.Fatalf("Account = %+v, %v, %v", a, configured, err)
	}
	if s, _ := e.service.CheckNow(ctx); !s.OK {
		t.Fatalf("Zone.eu does not take the old account: %+v", s)
	}
	if err := e.service.Save(ctx, "alex", "", "domain.tld", "zone", values(username, apiKey)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{legacyUsername, legacyAPIKey} {
		if _, found, _ := store.Setting(ctx, e.db, key); found {
			t.Errorf("%s is still kept after saving", key)
		}
	}
	if s := e.status(); !s.Configured || s.Provider != "zone" {
		t.Errorf("after saving: %+v", s)
	}
}

// Another provider is refused while Zone.eu is a stand-in: the page cannot
// make a test set-up reach a real provider.
func TestOtherProvidersAreRefusedInATestSetUp(t *testing.T) {
	e := newEnv(t)
	e.refused(e.service.Save(context.Background(), "alex", "", "domain.tld", "cloudflare", map[string]string{"apiToken": "a-made-up-token"}), "stand-in")
	e.refused(e.service.Save(context.Background(), "alex", "", "domain.tld", "made-up", map[string]string{}), "does not know")
	e.refused(e.service.Save(context.Background(), "alex", "", "domain.tld", "zone", map[string]string{"username": username, "apiKey": apiKey, "extra": "x"}), "does not use")
	if e.zone.Requests() != 0 || e.status().Configured {
		t.Error("something was asked or kept")
	}
}
