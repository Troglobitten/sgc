package zone_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/zone"
	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

const (
	username = "alex"
	apiKey   = "a-made-up-api-key"
)

func account(t *testing.T) (*zonetest.Server, func(username, apiKey string) *zone.Client) {
	t.Helper()
	standIn := zonetest.New(username, apiKey, "domain.tld")
	server := httptest.NewServer(standIn)
	t.Cleanup(server.Close)
	return standIn, func(username, apiKey string) *zone.Client {
		client, err := zone.NewClient(server.URL+"/v2/", username, apiKey, "sgc/test", &http.Client{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
}

func TestTheZoneOfADomain(t *testing.T) {
	ctx := context.Background()
	standIn, client := account(t)

	got, err := client(username, apiKey).Zone(ctx, "domain.tld")
	if err != nil || got.Name != "domain.tld" || !got.Active {
		t.Fatalf("the zone: %+v, %v", got, err)
	}
	standIn.SetActive("domain.tld", false)
	if got, err := client(username, apiKey).Zone(ctx, "domain.tld"); err != nil || got.Active {
		t.Errorf("a zone that is not active: %+v, %v", got, err)
	}

	// A domain that is not in the account.
	if _, err := client(username, apiKey).Zone(ctx, "other.tld"); !errors.Is(err, zone.ErrNotFound) {
		t.Errorf("a domain of somebody else: %v", err)
	}
	// A wrong key, and a wrong username.
	if _, err := client(username, "another-key").Zone(ctx, "domain.tld"); !errors.Is(err, zone.ErrCredentials) {
		t.Errorf("a wrong key: %v", err)
	}
	if _, err := client("mallory", apiKey).Zone(ctx, "domain.tld"); !errors.Is(err, zone.ErrCredentials) {
		t.Errorf("a wrong username: %v", err)
	}
	// Too many requests, and trouble at Zone.eu, in its own words.
	standIn.FailWith(http.StatusTooManyRequests)
	if _, err := client(username, apiKey).Zone(ctx, "domain.tld"); !errors.Is(err, zone.ErrRateLimited) {
		t.Errorf("past the limit of requests: %v", err)
	}
	standIn.FailWith(http.StatusInternalServerError)
	var failure *zone.StatusError
	if _, err := client(username, apiKey).Zone(ctx, "domain.tld"); !errors.As(err, &failure) || failure.Code != 500 || !strings.Contains(err.Error(), "told to fail") {
		t.Errorf("trouble at Zone.eu: %v", err)
	}
}

func TestNothingInANameCanChangeWhereARequestGoes(t *testing.T) {
	ctx := context.Background()
	var asked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.EscapedPath())
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client, err := zone.NewClient(server.URL+"/v2/", username, apiKey, "sgc/test", &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.Zone(ctx, "domain.tld/../../other")
	client.Zone(ctx, "domain.tld?x=1")
	for _, path := range asked {
		if !strings.HasPrefix(path, "/v2/dns/") || strings.Count(path, "/") != 3 {
			t.Errorf("a request went to %s", path)
		}
	}
	if len(asked) != 2 {
		t.Errorf("requests made: %v", asked)
	}
	// Names that are steps in an address are not sent at all.
	for _, name := range []string{"..", ".", ""} {
		if _, err := client.Zone(ctx, name); err == nil || len(asked) != 2 {
			t.Errorf("%q: %v, requests %v", name, err, asked)
		}
	}
}

func TestTheKeyIsNeverInAnError(t *testing.T) {
	// Nothing listens here: the request fails before it is sent.
	client, err := zone.NewClient("http://127.0.0.1:1/v2/", username, apiKey, "sgc/test", &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Zone(context.Background(), "domain.tld")
	if err == nil || strings.Contains(err.Error(), apiKey) || !strings.Contains(err.Error(), "reach Zone.eu") {
		t.Errorf("an unreachable Zone.eu: %v", err)
	}
	if _, err := zone.NewClient("not an address", username, apiKey, "sgc/test", http.DefaultClient); err == nil {
		t.Error("an endpoint that is no address was accepted")
	}
}

func TestDomainNames(t *testing.T) {
	for given, want := range map[string]string{
		"domain.tld":          "domain.tld",
		" Domain.TLD. ":       "domain.tld",
		"home.domain.co.uk":   "home.domain.co.uk",
		"xn--bcher-kva.tld":   "xn--bcher-kva.tld",
		"my-house.domain.tld": "my-house.domain.tld",
		"4you.tld":            "4you.tld",
	} {
		if got, err := zone.NormalizeDomain(given); err != nil || got != want {
			t.Errorf("%q: %q, %v", given, got, err)
		}
	}
	for _, given := range []string{
		"", "domain", "domain..tld", ".tld", "-domain.tld", "domain-.tld", "domain.tld/x", "domain.tld?x=1",
		"do main.tld", "bücher.tld", "domain.123", "192.168.1.10", "*.domain.tld", "domain.tld:8443",
		strings.Repeat("a", 64) + ".tld", strings.Repeat("a.", 130) + "tld", "https://domain.tld", "domain_name.tld",
	} {
		if got, err := zone.NormalizeDomain(given); err == nil {
			t.Errorf("%q was accepted as %q", given, got)
		}
	}
}
