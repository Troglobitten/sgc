package dnsprovider

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

// Made-up credentials; every error is checked for them.
const (
	secretOne = "a-made-up-secret-key-1"
	secretTwo = "a-made-up-secret-key-2"
	homeIP    = "203.0.113.10"
)

// fakeDNS is the records a stand-in provider holds, in one place for the
// checks: name (full), type, value.
type fakeDNS struct {
	mu      sync.Mutex
	next    int
	records []fakeRecord
}

type fakeRecord struct {
	id, name, kind, value string
	extra                 map[string]string
}

func (f *fakeDNS) add(name, kind, value string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	id := strconv.Itoa(1000 + f.next)
	f.records = append(f.records, fakeRecord{id: id, name: strings.ToLower(name), kind: kind, value: value})
	return id
}

func (f *fakeDNS) values(name, kind string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.records {
		if r.name == strings.ToLower(name) && r.kind == kind {
			out = append(out, r.value)
		}
	}
	return out
}

// conformance is one provider under the same checks as every other.
type conformance struct {
	id string
	// start returns the owner's values and the options that reach the
	// stand-in, and a way to read what it holds.
	start func(t *testing.T) (values map[string]string, opt Options, txt, a func(name string) []string)
	// wrong is a set of values the stand-in refuses.
	wrong map[string]string
}

func publicIP(context.Context) (netip.Addr, error) { return netip.MustParseAddr(homeIP), nil }

func conformances() []conformance {
	return []conformance{
		{
			id: ZoneID,
			start: func(t *testing.T) (map[string]string, Options, func(string) []string, func(string) []string) {
				z := zonetest.New("alex", secretOne, "domain.tld")
				server := httptest.NewServer(z)
				t.Cleanup(server.Close)
				return map[string]string{"username": "alex", "apiKey": secretOne},
					Options{ZoneEndpoint: server.URL + "/v2/", StandIn: true}, z.TXT, z.A
			},
			wrong: map[string]string{"username": "alex", "apiKey": secretTwo},
		},
		{
			id: "cloudflare",
			start: func(t *testing.T) (map[string]string, Options, func(string) []string, func(string) []string) {
				f := &fakeDNS{}
				server := httptest.NewServer(fakeCloudflare(t, f, secretOne))
				t.Cleanup(server.Close)
				return map[string]string{"apiToken": secretOne}, Options{Endpoint: server.URL},
					func(name string) []string {
						// Cloudflare keeps a TXT record's text in quotes.
						var out []string
						for _, v := range f.values(name, "TXT") {
							unquoted, err := strconv.Unquote(v)
							if err != nil {
								t.Errorf("a TXT record at Cloudflare is not in quotes: %s", v)
							}
							out = append(out, unquoted)
						}
						return out
					},
					func(name string) []string { return f.values(name, "A") }
			},
			wrong: map[string]string{"apiToken": secretTwo},
		},
		{
			id: "porkbun",
			start: func(t *testing.T) (map[string]string, Options, func(string) []string, func(string) []string) {
				f := &fakeDNS{}
				server := httptest.NewServer(fakePorkbun(t, f))
				t.Cleanup(server.Close)
				return map[string]string{"apiKey": secretOne, "secretKey": secretTwo}, Options{Endpoint: server.URL},
					func(name string) []string { return f.values(name, "TXT") },
					func(name string) []string { return f.values(name, "A") }
			},
			wrong: map[string]string{"apiKey": secretOne, "secretKey": "a-made-up-wrong-key"},
		},
		{
			id: "namecheap",
			start: func(t *testing.T) (map[string]string, Options, func(string) []string, func(string) []string) {
				f := newFakeNamecheap(t)
				server := httptest.NewServer(f)
				t.Cleanup(server.Close)
				return map[string]string{"username": "alex", "apiKey": secretOne}, Options{Endpoint: server.URL, PublicIP: publicIP},
					func(name string) []string { return f.values(name, "TXT") },
					func(name string) []string { return f.values(name, "A") }
			},
			wrong: map[string]string{"username": "alex", "apiKey": secretTwo},
		},
	}
}

// noSecret fails the test if an error names one of the made-up secrets.
func noSecret(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, secret := range []string{secretOne, secretTwo, "a-made-up-wrong-key"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("an error names a credential: %v", err)
		}
	}
}

func TestEveryProviderDoesWhatSGCNeeds(t *testing.T) {
	if got := len(Kinds()); got != len(conformances()) {
		t.Fatalf("%d providers are registered and %d are tested: every provider goes through these checks", got, len(conformances()))
	}
	for _, c := range conformances() {
		t.Run(c.id, func(t *testing.T) {
			ctx := context.Background()
			values, opt, txt, a := c.start(t)
			opt.HTTP = &http.Client{Timeout: 5 * time.Second}
			if c.id != ZoneID {
				opt.StandIn = false
			}
			p, err := Open(Account{Domain: "domain.tld", Provider: c.id, Values: values}, opt)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Check(ctx, "domain.tld"); err != nil {
				t.Fatalf("Check: %v", err)
			}
			if err := p.Check(ctx, "other.tld"); !errors.Is(err, ErrNotFound) {
				t.Errorf("Check of a domain that is not in the account: %v, want ErrNotFound", err)
			}

			// The proof for a certificate.
			proof, err := p.AddTXT(ctx, "domain.tld", "_acme-challenge.domain.tld", "a-made-up-proof")
			if err != nil {
				t.Fatalf("AddTXT: %v", err)
			}
			if got := txt("_acme-challenge.domain.tld"); !slices.Equal(got, []string{"a-made-up-proof"}) {
				t.Errorf("the provider holds %q under the proof's name", got)
			}
			if err := p.DeleteTXT(ctx, "domain.tld", proof.ID); err != nil {
				t.Fatalf("DeleteTXT: %v", err)
			}
			if got := txt("_acme-challenge.domain.tld"); len(got) != 0 {
				t.Errorf("the proof is still there: %q", got)
			}
			if err := p.DeleteTXT(ctx, "domain.tld", proof.ID); err != nil {
				t.Errorf("removing a proof that is already gone: %v", err)
			}

			// The VPN's name.
			made, err := p.AddA(ctx, "domain.tld", "vpn.domain.tld", "203.0.113.7")
			if err != nil {
				t.Fatalf("AddA: %v", err)
			}
			records, err := p.ARecords(ctx, "domain.tld")
			if err != nil {
				t.Fatalf("ARecords: %v", err)
			}
			if !slices.Contains(records, Record{ID: made.ID, Name: "vpn.domain.tld", Value: "203.0.113.7"}) {
				t.Errorf("ARecords = %+v, want the record AddA made (%+v)", records, made)
			}
			if err := p.UpdateA(ctx, "domain.tld", made.ID, "vpn.domain.tld", "203.0.113.8"); err != nil {
				t.Fatalf("UpdateA: %v", err)
			}
			if got := a("vpn.domain.tld"); !slices.Equal(got, []string{"203.0.113.8"}) {
				t.Errorf("after UpdateA the provider holds %q", got)
			}
			records, _ = p.ARecords(ctx, "domain.tld")
			if !slices.Contains(records, Record{ID: made.ID, Name: "vpn.domain.tld", Value: "203.0.113.8"}) {
				t.Errorf("after UpdateA the record has another ID: %+v (was %s)", records, made.ID)
			}

			// Credentials that are not accepted.
			wrong, err := Open(Account{Domain: "domain.tld", Provider: c.id, Values: c.wrong}, opt)
			if err != nil {
				t.Fatal(err)
			}
			err = wrong.Check(ctx, "domain.tld")
			if !errors.Is(err, ErrCredentials) {
				t.Errorf("Check with wrong credentials: %v, want ErrCredentials", err)
			}
			noSecret(t, err)
			_, err = wrong.AddTXT(ctx, "domain.tld", "_acme-challenge.domain.tld", "x")
			noSecret(t, err)

			// Nothing reachable: the error says so and names no credential.
			opt.Endpoint, opt.ZoneEndpoint = "http://127.0.0.1:1/"+secretOne, "http://127.0.0.1:1/"+secretOne+"/"
			gone, err := Open(Account{Domain: "domain.tld", Provider: c.id, Values: values}, opt)
			if err != nil {
				t.Fatal(err)
			}
			err = gone.Check(ctx, "domain.tld")
			if !errors.Is(err, ErrUnreachable) {
				t.Errorf("Check with nothing to reach: %v, want ErrUnreachable", err)
			}
			noSecret(t, err)
		})
	}
}

func TestAStandInAllowsNoOtherProvider(t *testing.T) {
	for _, k := range Kinds() {
		values := map[string]string{}
		for _, f := range k.Fields {
			values[f.Key] = "a-made-up-value"
		}
		_, err := Open(Account{Domain: "domain.tld", Provider: k.ID, Values: values}, Options{StandIn: true, PublicIP: publicIP})
		if k.ID == ZoneID && err != nil {
			t.Errorf("Zone.eu with its stand-in: %v", err)
		}
		if k.ID != ZoneID && err == nil {
			t.Errorf("%s was opened while Zone.eu is a stand-in: a test set-up would reach the real %s", k.ID, k.Name)
		}
	}
}

func TestTheOwnersValuesAreChecked(t *testing.T) {
	for _, bad := range []map[string]string{
		{"username": "alex"},                                     // a field missing
		{"username": "alex", "apiKey": "with space"},             // a space
		{"username": "alex", "apiKey": "x", "extra": "y"},        // a field the provider does not use
		{"username": "alex", "apiKey": strings.Repeat("k", 201)}, // too long
		{"username": "alex", "apiKey": "ключ"},                   // not plain text
	} {
		if _, err := CheckValues(ZoneID, bad); err == nil {
			t.Errorf("CheckValues(%v) took it", bad)
		}
	}
	if _, err := CheckValues("made-up", map[string]string{}); err == nil {
		t.Error("an unknown provider was taken")
	}
	clean, err := CheckValues(ZoneID, map[string]string{"username": " alex ", "apiKey": "k"})
	if err != nil || clean["username"] != "alex" {
		t.Errorf("CheckValues = %v, %v", clean, err)
	}
	if Kinds()[0].ID != ZoneID {
		t.Errorf("the first provider listed is %s, not Zone.eu", Kinds()[0].ID)
	}
}

// --- Namecheap's own risks ---------------------------------------------

func TestNamecheapKeepsEveryOtherRecord(t *testing.T) {
	f := newFakeNamecheap(t)
	server := httptest.NewServer(f)
	defer server.Close()
	before := slices.Clone(f.hosts)
	p, err := Open(Account{Domain: "domain.tld", Provider: "namecheap", Values: map[string]string{"username": "alex", "apiKey": secretOne}},
		Options{Endpoint: server.URL, PublicIP: publicIP})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	proof, err := p.AddTXT(ctx, "domain.tld", "_acme-challenge.domain.tld", "a-made-up-proof")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteTXT(ctx, "domain.tld", proof.ID); err != nil {
		t.Fatal(err)
	}
	if !sameHosts(f.hosts, before) {
		t.Errorf("after adding and removing the proof the records are\n%+v\nnot\n%+v", f.hosts, before)
	}
	if f.emailTypes[len(f.emailTypes)-1] != "MX" || slices.Contains(f.emailTypes, "") {
		t.Errorf("the mail setting was written as %q, not kept as MX", f.emailTypes)
	}
	// Removing what is already gone writes nothing.
	writes := len(f.emailTypes)
	if err := p.DeleteTXT(ctx, "domain.tld", proof.ID); err != nil || len(f.emailTypes) != writes {
		t.Errorf("removing a gone proof: %v, %d writes", err, len(f.emailTypes)-writes)
	}
}

func TestNamecheapSaysWhenTheListDidNotTake(t *testing.T) {
	f := newFakeNamecheap(t)
	f.dropOnWrite = "URL" // Namecheap keeps all but the redirect
	server := httptest.NewServer(f)
	defer server.Close()
	p, _ := Open(Account{Domain: "domain.tld", Provider: "namecheap", Values: map[string]string{"username": "alex", "apiKey": secretOne}},
		Options{Endpoint: server.URL, PublicIP: publicIP})
	_, err := p.AddTXT(context.Background(), "domain.tld", "_acme-challenge.domain.tld", "a-made-up-proof")
	var refusal *Refusal
	if !errors.As(err, &refusal) || !strings.Contains(refusal.Message, "not what SGC wrote") {
		t.Errorf("AddTXT = %v, want the warning that the list is not what SGC wrote", err)
	}
}

func TestNamecheapChangesOneAtATime(t *testing.T) {
	f := newFakeNamecheap(t)
	f.slow = 20 * time.Millisecond
	server := httptest.NewServer(f)
	defer server.Close()
	p, _ := Open(Account{Domain: "domain.tld", Provider: "namecheap", Values: map[string]string{"username": "alex", "apiKey": secretOne}},
		Options{Endpoint: server.URL, PublicIP: publicIP})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.AddTXT(context.Background(), "domain.tld", "_acme-challenge.domain.tld", fmt.Sprintf("proof-%d", i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := f.values("_acme-challenge.domain.tld", "TXT"); len(got) != 4 {
		t.Errorf("after four changes at once, the proofs are %q", got)
	}
}

func TestNamecheapNamesAnAddressThatIsNotAllowed(t *testing.T) {
	f := newFakeNamecheap(t)
	server := httptest.NewServer(f)
	defer server.Close()
	p, _ := Open(Account{Domain: "domain.tld", Provider: "namecheap", Values: map[string]string{"username": "alex", "apiKey": secretOne}},
		Options{Endpoint: server.URL, PublicIP: func(context.Context) (netip.Addr, error) { return netip.MustParseAddr("198.51.100.1"), nil }})
	err := p.Check(context.Background(), "domain.tld")
	var refusal *Refusal
	if !errors.As(err, &refusal) || !strings.Contains(refusal.Message, "198.51.100.1") || !strings.Contains(refusal.Message, "Whitelisted IPs") {
		t.Errorf("Check from an address not on the list: %v", err)
	}
}

// --- the stand-ins -----------------------------------------------------

func writeJSONAnswer(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// fakeCloudflare plays Cloudflare's API v4 for one zone, domain.tld.
func fakeCloudflare(t *testing.T, f *fakeDNS, token string) http.Handler {
	const zoneID = "a-made-up-zone-id"
	ok := func(w http.ResponseWriter, result any) {
		writeJSONAnswer(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "result": result})
	}
	fail := func(w http.ResponseWriter, status, code int, message string) {
		writeJSONAnswer(w, status, map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": message}}, "result": nil})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			fail(w, http.StatusForbidden, 9109, "Invalid access token")
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "zones":
			if r.URL.Query().Get("name") == "domain.tld" {
				ok(w, []any{map[string]any{"id": zoneID, "name": "domain.tld", "status": "active"}})
			} else {
				ok(w, []any{})
			}
		case len(parts) >= 3 && parts[0] == "zones" && parts[1] == zoneID && parts[2] == "dns_records":
			switch {
			case r.Method == http.MethodGet && len(parts) == 3:
				kind := r.URL.Query().Get("type")
				var out []cfRecord
				f.mu.Lock()
				for _, rec := range f.records {
					if kind == "" || rec.kind == kind {
						out = append(out, cfRecord{ID: rec.id, Type: rec.kind, Name: rec.name, Content: rec.value, TTL: 1})
					}
				}
				f.mu.Unlock()
				if page, _ := strconv.Atoi(r.URL.Query().Get("page")); page > 1 {
					out = nil
				}
				ok(w, out)
			case r.Method == http.MethodPost && len(parts) == 3:
				var rec cfRecord
				json.NewDecoder(r.Body).Decode(&rec)
				if rec.Type == "A" && (rec.Proxied == nil || *rec.Proxied) {
					t.Errorf("an A record was made through Cloudflare's proxy: %+v", rec)
				}
				id := f.add(rec.Name, rec.Type, rec.Content)
				ok(w, cfRecord{ID: id, Type: rec.Type, Name: rec.Name, Content: rec.Content})
			case (r.Method == http.MethodPatch || r.Method == http.MethodDelete) && len(parts) == 4:
				var rec cfRecord
				json.NewDecoder(r.Body).Decode(&rec)
				f.mu.Lock()
				defer f.mu.Unlock()
				for i := range f.records {
					if f.records[i].id != parts[3] {
						continue
					}
					if r.Method == http.MethodDelete {
						f.records = slices.Delete(f.records, i, i+1)
						ok(w, map[string]any{"id": parts[3]})
						return
					}
					if rec.Proxied == nil || *rec.Proxied {
						t.Errorf("an A record was changed to go through Cloudflare's proxy: %+v", rec)
					}
					f.records[i].value = rec.Content
					ok(w, rec)
					return
				}
				fail(w, http.StatusNotFound, 81044, "Record does not exist.")
			default:
				fail(w, http.StatusMethodNotAllowed, 10405, "not here")
			}
		default:
			fail(w, http.StatusNotFound, 7003, "Could not route to "+r.URL.Path)
		}
	})
}

// fakePorkbun plays Porkbun's API v3 for domain.tld.
func fakePorkbun(t *testing.T, f *fakeDNS) http.Handler {
	fail := func(w http.ResponseWriter, status int, message string) {
		writeJSONAnswer(w, status, map[string]any{"status": "ERROR", "message": message})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil {
			fail(w, http.StatusBadRequest, "Invalid request.")
			return
		}
		if body["apikey"] != secretOne || body["secretapikey"] != secretTwo {
			fail(w, http.StatusBadRequest, "Invalid API key. (002)")
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 || parts[0] != "dns" {
			fail(w, http.StatusNotFound, "Not found")
			return
		}
		if parts[2] != "domain.tld" {
			writeJSONAnswer(w, http.StatusBadRequest, map[string]any{"status": "ERROR", "code": "DOMAIN_NOT_FOUND", "message": "Domain not found."})
			return
		}
		full := func(name string) string {
			if name == "" {
				return "domain.tld"
			}
			return name + ".domain.tld"
		}
		switch parts[1] {
		case "retrieve":
			var out []pbRecord
			f.mu.Lock()
			for _, rec := range f.records {
				out = append(out, pbRecord{ID: rec.id, Name: rec.name, Type: rec.kind, Content: rec.value, TTL: "300"})
			}
			f.mu.Unlock()
			writeJSONAnswer(w, http.StatusOK, map[string]any{"status": "SUCCESS", "records": out})
		case "create":
			if strings.HasSuffix(body["name"], "domain.tld") {
				t.Errorf("a record was made at Porkbun with its full name %q: Porkbun takes the name relative to the domain", body["name"])
			}
			id := f.add(full(body["name"]), body["type"], body["content"])
			n, _ := strconv.Atoi(id)
			writeJSONAnswer(w, http.StatusOK, map[string]any{"status": "SUCCESS", "id": n})
		case "edit", "delete":
			if len(parts) != 4 {
				fail(w, http.StatusBadRequest, "Invalid record ID.")
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for i := range f.records {
				if f.records[i].id != parts[3] {
					continue
				}
				if parts[1] == "delete" {
					f.records = slices.Delete(f.records, i, i+1)
				} else {
					f.records[i].name, f.records[i].value = full(body["name"]), body["content"]
				}
				writeJSONAnswer(w, http.StatusOK, map[string]any{"status": "SUCCESS"})
				return
			}
			fail(w, http.StatusBadRequest, "Invalid record ID.")
		default:
			fail(w, http.StatusNotFound, "Not found")
		}
	})
}

// fakeNamecheap plays Namecheap's XML API for domain.tld, which already
// holds the owner's records: mail, a redirect, a name for the web.
type fakeNamecheap struct {
	t           *testing.T
	mu          sync.Mutex
	hosts       []ncHost
	emailType   string
	emailTypes  []string // as each setHosts sent it
	dropOnWrite string   // a type Namecheap leaves out when it takes a list
	slow        time.Duration
}

func newFakeNamecheap(t *testing.T) *fakeNamecheap {
	return &fakeNamecheap{t: t, emailType: "MX", hosts: []ncHost{
		{Name: "@", Type: "MX", Address: "mail.domain.tld.", MXPref: "10", TTL: "1800"},
		{Name: "@", Type: "MX", Address: "mail2.domain.tld.", MXPref: "20", TTL: "1800"},
		{Name: "www", Type: "CNAME", Address: "domain.tld.", MXPref: "10", TTL: "1799"},
		{Name: "old", Type: "URL", Address: "https://domain.tld/new", MXPref: "10", TTL: "1799"},
		{Name: "@", Type: "TXT", Address: "v=spf1 include:mail.domain.tld ~all", MXPref: "10", TTL: "1799"},
	}}
}

func (f *fakeNamecheap) values(name, kind string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, h := range f.hosts {
		if fullName(h.Name, "domain.tld") == strings.ToLower(name) && h.Type == kind {
			out = append(out, h.Address)
		}
	}
	return out
}

func (f *fakeNamecheap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fail := func(number, message string) {
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response"><Errors><Error Number="%s">%s</Error></Errors></ApiResponse>`, number, message)
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		f.t.Errorf("a request to Namecheap that is not a form: %s %s", r.Method, r.URL)
	}
	r.ParseForm()
	form := r.PostForm
	switch {
	case form.Get("ApiKey") != secretOne || form.Get("ApiUser") != "alex" || form.Get("UserName") != "alex":
		fail("1011102", "API Key is invalid or API access has not been enabled")
		return
	case form.Get("ClientIp") != homeIP:
		fail("1011150", "Invalid request IP: "+form.Get("ClientIp"))
		return
	case form.Get("SLD") != "domain" || form.Get("TLD") != "tld":
		fail("2019166", "Domain not found")
		return
	}
	time.Sleep(f.slow)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch form.Get("Command") {
	case "namecheap.domains.dns.getHosts":
		var rows strings.Builder
		for i, h := range f.hosts {
			fmt.Fprintf(&rows, `<host HostId="%d" Name="%s" Type="%s" Address="%s" MXPref="%s" TTL="%s" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false" />`,
				500+i, xmlText(h.Name), xmlText(h.Type), xmlText(h.Address), xmlText(h.MXPref), xmlText(h.TTL))
		}
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors /><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="domain.tld" EmailType="%s" IsUsingOurDNS="true">%s</DomainDNSGetHostsResult></CommandResponse></ApiResponse>`,
			f.emailType, rows.String())
	case "namecheap.domains.dns.setHosts":
		var hosts []ncHost
		for i := 1; form.Has("HostName" + strconv.Itoa(i)); i++ {
			at := strconv.Itoa(i)
			h := ncHost{Name: form.Get("HostName" + at), Type: form.Get("RecordType" + at), Address: form.Get("Address" + at), MXPref: form.Get("MXPref" + at), TTL: form.Get("TTL" + at)}
			if h.Type != f.dropOnWrite {
				hosts = append(hosts, h)
			}
		}
		f.hosts = hosts
		f.emailTypes = append(f.emailTypes, form.Get("EmailType"))
		if form.Get("EmailType") != "" {
			f.emailType = form.Get("EmailType")
		}
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors /><CommandResponse Type="namecheap.domains.dns.setHosts"><DomainDNSSetHostsResult Domain="domain.tld" IsSuccess="true" /></CommandResponse></ApiResponse>`)
	default:
		fail("1010101", "Unknown command")
	}
}

func xmlText(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return strings.ReplaceAll(b.String(), `"`, "&quot;")
}
