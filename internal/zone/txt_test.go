package zone_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Troglobitten/sgc/internal/zone"
)

const challengeName = "_acme-challenge.domain.tld"

func TestTXTRecords(t *testing.T) {
	ctx := context.Background()
	standIn, client := account(t)
	zoneClient := client(username, apiKey)

	if records, err := zoneClient.TXTRecords(ctx, "domain.tld"); err != nil || len(records) != 0 {
		t.Fatalf("to begin with: %v, %v", records, err)
	}
	first, err := zoneClient.AddTXT(ctx, "domain.tld", challengeName, "first-value")
	if err != nil || first.ID == "" || first.Name != challengeName || first.Value != "first-value" {
		t.Fatalf("the record made: %+v, %v", first, err)
	}
	// Two records under one name is what a certificate for a domain and for
	// everything under it asks for.
	second, err := zoneClient.AddTXT(ctx, "domain.tld", challengeName, "second-value")
	if err != nil || second.ID == first.ID {
		t.Fatalf("a second record under the same name: %+v, %v", second, err)
	}
	records, err := zoneClient.TXTRecords(ctx, "domain.tld")
	if err != nil || len(records) != 2 || records[0] != first || records[1] != second {
		t.Errorf("the zone's records: %+v, %v", records, err)
	}

	if err := zoneClient.DeleteTXT(ctx, "domain.tld", first.ID); err != nil {
		t.Fatal(err)
	}
	if got := standIn.TXT(challengeName); len(got) != 1 || got[0] != "second-value" {
		t.Errorf("left after removing the first: %v", got)
	}
	// Removing what is gone already is not a failure.
	if err := zoneClient.DeleteTXT(ctx, "domain.tld", first.ID); err != nil {
		t.Errorf("removing a record twice: %v", err)
	}
	// A name outside the zone is Zone.eu's to refuse, in its own words.
	var refusal *zone.StatusError
	if _, err := zoneClient.AddTXT(ctx, "domain.tld", "_acme-challenge.other.tld", "x"); !errors.As(err, &refusal) || refusal.Code != http.StatusUnprocessableEntity {
		t.Errorf("a record outside the zone: %v", err)
	}
	// And all of it needs the key.
	if _, err := client(username, "another-key").AddTXT(ctx, "domain.tld", challengeName, "x"); !errors.Is(err, zone.ErrCredentials) {
		t.Errorf("a record with a wrong key: %v", err)
	}
	if standIn.Records() != 1 {
		t.Errorf("records in the account: %d", standIn.Records())
	}
}

// Zone.eu's description says a record's id is a number; its examples show it
// in quotes. Both are read.
func TestARecordsNumberComesInTwoShapes(t *testing.T) {
	ctx := context.Background()
	for _, body := range []string{
		`[{"id":"123","name":"_acme-challenge.domain.tld","destination":"value"}]`,
		`[{"id":123,"name":"_acme-challenge.domain.tld","destination":"value"}]`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(body))
		}))
		client, err := zone.NewClient(server.URL+"/v2/", username, apiKey, "sgc/test", &http.Client{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		records, err := client.TXTRecords(ctx, "domain.tld")
		if err != nil || len(records) != 1 || records[0].ID != "123" {
			t.Errorf("%s: %+v, %v", body, records, err)
		}
		server.Close()
	}
	// What SGC sends when it makes a record has no id in it.
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&sent)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`[{"id":"7","name":"n","destination":"v"}]`))
	}))
	defer server.Close()
	client, _ := zone.NewClient(server.URL+"/v2/", username, apiKey, "sgc/test", &http.Client{Timeout: 5 * time.Second})
	if _, err := client.AddTXT(ctx, "domain.tld", "n", "v"); err != nil {
		t.Fatal(err)
	}
	if _, has := sent["id"]; has || sent["name"] != "n" || sent["destination"] != "v" || len(sent) != 2 {
		t.Errorf("sent to make a record: %v", sent)
	}
}

// The stand-in's name servers show what was made through its API, which is
// what a certificate authority looks at.
func TestTheStandInsNameServers(t *testing.T) {
	ctx := context.Background()
	standIn, client := account(t)
	address, stop, err := standIn.ListenDNS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ask := func(name string, kind uint16) *dns.Msg {
		t.Helper()
		question := new(dns.Msg)
		question.SetQuestion(dns.Fqdn(name), kind)
		answer, _, err := new(dns.Client).Exchange(question, address)
		if err != nil {
			t.Fatal(err)
		}
		return answer
	}
	if answer := ask(challengeName, dns.TypeTXT); answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
		t.Errorf("before a record is made: %v", answer)
	}
	if _, err := client(username, apiKey).AddTXT(ctx, "domain.tld", challengeName, "the-proof"); err != nil {
		t.Fatal(err)
	}
	answer := ask(challengeName, dns.TypeTXT)
	if len(answer.Answer) != 1 || answer.Answer[0].(*dns.TXT).Txt[0] != "the-proof" {
		t.Errorf("with the record made: %v", answer)
	}
	// Asked in capitals, as some resolvers do.
	if answer := ask("_ACME-Challenge.Domain.TLD", dns.TypeTXT); len(answer.Answer) != 1 {
		t.Errorf("asked in capitals: %v", answer)
	}
	// Another kind of record under that name: none, but the name exists.
	if answer := ask(challengeName, dns.TypeCNAME); answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
		t.Errorf("a CNAME under that name: %v", answer)
	}
	// A name in nobody's zone here.
	if answer := ask("_acme-challenge.other.tld", dns.TypeTXT); answer.Rcode != dns.RcodeNameError {
		t.Errorf("a name outside the zones: %v", answer)
	}
	// A change that has not reached the name servers yet.
	standIn.HideTXT(true)
	if answer := ask(challengeName, dns.TypeTXT); len(answer.Answer) != 0 {
		t.Errorf("while hidden: %v", answer)
	}
}
