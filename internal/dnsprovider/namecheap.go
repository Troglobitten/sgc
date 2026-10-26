package dnsprovider

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Namecheap's XML API, as Namecheap's own Go SDK uses it
// (github.com/namecheap/go-namecheap-sdk/v2 v2.10.5, read on 2026-10-24),
// and lego's provider for it:
//
//   - every call is a POST of a form to xml.response, with ApiUser, ApiKey,
//     UserName, ClientIp and Command; the key is never in an address;
//   - ClientIp is the address the request comes from, which the owner must
//     have put on the account's list of allowed addresses;
//   - a domain's records can only be written all at once (setHosts), so
//     every change reads the whole list (getHosts), changes SGC's record in
//     it, writes it back with every other record as it was, and reads it
//     again to see that it took. The zone's mail setting (EmailType) is
//     written back as it was read: the SDK does the same, and warns that
//     another value silently reroutes the domain's mail.
//
// Records have no IDs that last (a write makes new ones), so SGC names its
// own by what they are: "txt|<host>|<text>" and "a|<host>".
const (
	namecheapAPI = "https://api.namecheap.com/xml.response"
	// Time-to-live of SGC's records, in seconds: lego's for the proof, five
	// minutes for the VPN's name so that a new home address spreads soon.
	namecheapTXTTTL = "120"
	namecheapATTL   = "300"
)

func init() {
	Register(Kind{
		ID:          "namecheap",
		Name:        "Namecheap",
		Credentials: "username and API key",
		Fields: []Field{
			{Key: "username", Label: "Namecheap username", Max: 100,
				Help: "The name you sign in with at Namecheap."},
			{Key: "apiKey", Label: "API key", Max: 200, Secret: true,
				Help: "Shown at namecheap.com under Profile, Tools, Namecheap API Access, once API access is switched on. It opens your whole Namecheap account, so SGC keeps it to itself: it is saved on this device, travels in an export, and is never shown again."},
		},
		Before: "At namecheap.com, under Profile, Tools, Namecheap API Access: switch API access on (Namecheap allows it for accounts with at least 20 domains, $50 in the account or $50 spent in the last two years), and add this home's public address to the Whitelisted IPs. The domain must use Namecheap's own DNS (BasicDNS or PremiumDNS). Namecheap's API can only replace a domain's whole list of records: SGC reads the list first and writes every other record back as it was.",
		// lego waits up to an hour for Namecheap.
		Propagation: time.Hour,
		open: func(values map[string]string, opt Options) (Provider, error) {
			if opt.PublicIP == nil {
				return nil, errors.New("Namecheap needs the home's public address, and SGC was given no way to find it")
			}
			base := namecheapAPI
			if opt.Endpoint != "" {
				base = opt.Endpoint
			}
			return &namecheap{base: base, user: values["username"], apiKey: values["apiKey"], opt: opt}, nil
		},
	})
}

// namecheapWrites keeps SGC's changes to Namecheap one at a time: two at
// once would each write back a list without the other's record.
var namecheapWrites sync.Mutex

type namecheap struct {
	base         string
	user, apiKey string
	opt          Options
}

type ncHost struct {
	Name    string `xml:"Name,attr"`
	Type    string `xml:"Type,attr"`
	Address string `xml:"Address,attr"`
	MXPref  string `xml:"MXPref,attr"`
	TTL     string `xml:"TTL,attr"`
}

type ncAnswer struct {
	XMLName xml.Name `xml:"ApiResponse"`
	Status  string   `xml:"Status,attr"`
	Errors  []struct {
		Number  string `xml:"Number,attr"`
		Message string `xml:",chardata"`
	} `xml:"Errors>Error"`
	Hosts *struct {
		EmailType     string   `xml:"EmailType,attr"`
		IsUsingOurDNS string   `xml:"IsUsingOurDNS,attr"`
		Hosts         []ncHost `xml:"host"`
	} `xml:"CommandResponse>DomainDNSGetHostsResult"`
	Set *struct {
		IsSuccess string `xml:"IsSuccess,attr"`
	} `xml:"CommandResponse>DomainDNSSetHostsResult"`
}

// zone is a domain's records as getHosts gave them.
type ncZone struct {
	emailType string
	hosts     []ncHost
}

// split is the domain as Namecheap names it: "domain" and "tld" (or
// "co.uk"). Namecheap holds registered domains only.
func split(domain string) (sld, tld string, err error) {
	tld, _ = publicsuffix.PublicSuffix(domain)
	sld, ok := strings.CutSuffix(domain, "."+tld)
	if !ok || sld == "" || strings.Contains(sld, ".") {
		return "", "", &Refusal{Message: domain + " is not a domain as Namecheap registers it: enter the domain itself (like domain.tld), not a name under it"}
	}
	return sld, tld, nil
}

func (n *namecheap) call(ctx context.Context, domain, command string, params url.Values) (*ncAnswer, error) {
	ip, err := n.opt.PublicIP(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: the home's public address, which Namecheap wants with every request, could not be found: %v", ErrUnreachable, err)
	}
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	form.Set("ApiUser", n.user)
	form.Set("UserName", n.user)
	form.Set("ApiKey", n.apiKey)
	form.Set("ClientIp", ip.String())
	form.Set("Command", command)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.base, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, data, err := send(n.opt, "Namecheap", req)
	if err != nil {
		return nil, err
	}
	switch {
	// Namecheap answers too many requests with 405 (its SDK, errors.go).
	case status == http.StatusTooManyRequests || status == http.StatusMethodNotAllowed:
		return nil, ErrRateLimited
	case status >= 500:
		return nil, fmt.Errorf("%w: Namecheap: it answered %d", ErrUnreachable, status)
	case status != http.StatusOK:
		return nil, &Refusal{Message: fmt.Sprintf("Namecheap answered with an error (%d)", status)}
	}
	var answer ncAnswer
	if err := xml.Unmarshal(data, &answer); err != nil {
		return nil, fmt.Errorf("Namecheap's answer could not be read: %w", err)
	}
	if len(answer.Errors) > 0 || !strings.EqualFold(answer.Status, "OK") {
		return nil, namecheapRefusal(domain, ip.String(), &answer)
	}
	return &answer, nil
}

// namecheapRefusal reads Namecheap's errors. The numbers are those its SDK
// names (errors.go) and lego's tests show; an address that is not on the
// list has no number there, so its words are looked at.
func namecheapRefusal(domain, ip string, answer *ncAnswer) error {
	if len(answer.Errors) == 0 {
		return &Refusal{Message: "Namecheap refused, without saying why"}
	}
	first := answer.Errors[0]
	words := strings.ToLower(first.Message)
	switch {
	case first.Number == "1011102" || strings.Contains(words, "api key is invalid"):
		return ErrCredentials
	case strings.Contains(words, "ip address") || strings.Contains(words, "request ip") || strings.Contains(words, "invalid ip") ||
		strings.Contains(words, "clientip") || strings.Contains(words, "whitelist"):
		return &Refusal{Message: "Namecheap does not take requests from this home's address (" + ip + "): add it to the Whitelisted IPs at namecheap.com, under Profile, Tools, Namecheap API Access (" + plainText(first.Message) + ")"}
	case first.Number == "2019166" || first.Number == "2016166" || first.Number == "3016166":
		return ErrNotFound
	case first.Number == "4011103":
		return &Refusal{Message: "Namecheap does not let this account manage " + domain + " (" + plainText(first.Message) + ")"}
	case slices.Contains([]string{"3050900", "5019169", "5050169", "5050900"}, first.Number):
		return fmt.Errorf("%w: Namecheap: %s", ErrUnreachable, plainText(first.Message))
	}
	return &Refusal{Message: "Namecheap refused: " + plainText(first.Message) + " (" + first.Number + ")"}
}

func (n *namecheap) read(ctx context.Context, domain string) (ncZone, error) {
	sld, tld, err := split(domain)
	if err != nil {
		return ncZone{}, err
	}
	answer, err := n.call(ctx, domain, "namecheap.domains.dns.getHosts", url.Values{"SLD": {sld}, "TLD": {tld}})
	if err != nil {
		return ncZone{}, err
	}
	// Without the list, nothing may be written back: it would be empty.
	if answer.Hosts == nil {
		return ncZone{}, fmt.Errorf("Namecheap's answer holds no list of records for %s", domain)
	}
	if strings.EqualFold(answer.Hosts.IsUsingOurDNS, "false") {
		return ncZone{}, ErrNotActive
	}
	return ncZone{emailType: answer.Hosts.EmailType, hosts: answer.Hosts.Hosts}, nil
}

// change reads the list, lets edit change it, writes it back and reads it
// again. edit returns false if there is nothing to write.
func (n *namecheap) change(ctx context.Context, domain string, edit func(hosts []ncHost) ([]ncHost, bool, error)) error {
	namecheapWrites.Lock()
	defer namecheapWrites.Unlock()
	sld, tld, err := split(domain)
	if err != nil {
		return err
	}
	zone, err := n.read(ctx, domain)
	if err != nil {
		return err
	}
	next, write, err := edit(slices.Clone(zone.hosts))
	if err != nil || !write {
		return err
	}
	form := url.Values{"SLD": {sld}, "TLD": {tld}}
	if zone.emailType != "" {
		form.Set("EmailType", zone.emailType)
	}
	for i, h := range next {
		at := strconv.Itoa(i + 1)
		form.Set("HostName"+at, h.Name)
		form.Set("RecordType"+at, h.Type)
		form.Set("Address"+at, h.Address)
		if h.MXPref != "" {
			form.Set("MXPref"+at, h.MXPref)
		}
		if h.TTL != "" {
			form.Set("TTL"+at, h.TTL)
		}
	}
	answer, err := n.call(ctx, domain, "namecheap.domains.dns.setHosts", form)
	if err != nil {
		return err
	}
	if answer.Set == nil || !strings.EqualFold(answer.Set.IsSuccess, "true") {
		return &Refusal{Message: "Namecheap did not say that it took the list of records for " + domain}
	}
	after, err := n.read(ctx, domain)
	if err != nil {
		return fmt.Errorf("Namecheap took the list of records for %s, and it could not be read again to check it: %w", domain, err)
	}
	if !sameHosts(after.hosts, next) || !strings.EqualFold(after.emailType, zone.emailType) {
		return &Refusal{Message: "Namecheap's list of records for " + domain + " is not what SGC wrote: it may have been changed at the same moment, at namecheap.com. Look at the domain's records there"}
	}
	return nil
}

// sameHosts compares two lists the way Namecheap's SDK does: names in lower
// case ("" is "@"), types in upper case, an address's final dot dropped, a
// missing time-to-live as Namecheap's automatic 1799.
func sameHosts(a, b []ncHost) bool {
	key := func(h ncHost) string {
		name := strings.ToLower(strings.TrimSpace(h.Name))
		if name == "" {
			name = "@"
		}
		ttl := h.TTL
		if ttl == "" || ttl == "0" {
			ttl = "1799"
		}
		return strings.Join([]string{name, strings.ToUpper(strings.TrimSpace(h.Type)), strings.TrimSuffix(h.Address, "."), h.MXPref, ttl}, "\x00")
	}
	keys := func(hosts []ncHost) []string {
		out := make([]string, len(hosts))
		for i, h := range hosts {
			out[i] = key(h)
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(keys(a), keys(b))
}

// host is a full name as Namecheap's list names it, relative to the domain.
func host(name, domain string) (string, error) {
	sub, ok := relative(name, domain)
	if !ok {
		return "", fmt.Errorf("%s is not under %s", name, domain)
	}
	if sub == "" {
		return "@", nil
	}
	return sub, nil
}

func fullName(h, domain string) string {
	if h == "@" || h == "" {
		return domain
	}
	return strings.ToLower(h) + "." + domain
}

func (n *namecheap) Check(ctx context.Context, domain string) error {
	_, err := n.read(ctx, domain)
	return err
}

func (n *namecheap) AddTXT(ctx context.Context, domain, name, value string) (Record, error) {
	h, err := host(name, domain)
	if err != nil {
		return Record{}, err
	}
	err = n.change(ctx, domain, func(hosts []ncHost) ([]ncHost, bool, error) {
		// MXPref 10 on every row, as getHosts gives it and lego sends it.
		return append(hosts, ncHost{Name: h, Type: "TXT", Address: value, MXPref: "10", TTL: namecheapTXTTTL}), true, nil
	})
	if err != nil {
		return Record{}, err
	}
	return Record{ID: "txt|" + strings.ToLower(h) + "|" + value, Name: name, Value: value}, nil
}

func (n *namecheap) DeleteTXT(ctx context.Context, domain, id string) error {
	kind, rest, _ := strings.Cut(id, "|")
	h, value, ok := strings.Cut(rest, "|")
	if kind != "txt" || !ok || h == "" {
		return fmt.Errorf("%q is not one of SGC's names for a Namecheap record", id)
	}
	return n.change(ctx, domain, func(hosts []ncHost) ([]ncHost, bool, error) {
		kept := slices.DeleteFunc(hosts, func(r ncHost) bool {
			return strings.EqualFold(r.Type, "TXT") && strings.EqualFold(r.Name, h) && r.Address == value
		})
		// Nothing to remove (already gone): nothing is written.
		return kept, len(kept) != len(hosts), nil
	})
}

func (n *namecheap) ARecords(ctx context.Context, domain string) ([]Record, error) {
	zone, err := n.read(ctx, domain)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, r := range zone.hosts {
		if strings.EqualFold(r.Type, "A") {
			out = append(out, Record{ID: "a|" + strings.ToLower(r.Name), Name: fullName(r.Name, domain), Value: r.Address})
		}
	}
	return out, nil
}

func (n *namecheap) AddA(ctx context.Context, domain, name, address string) (Record, error) {
	h, err := host(name, domain)
	if err != nil {
		return Record{}, err
	}
	err = n.change(ctx, domain, func(hosts []ncHost) ([]ncHost, bool, error) {
		return append(hosts, ncHost{Name: h, Type: "A", Address: address, MXPref: "10", TTL: namecheapATTL}), true, nil
	})
	if err != nil {
		return Record{}, err
	}
	return Record{ID: "a|" + strings.ToLower(h), Name: name, Value: address}, nil
}

// DeleteA removes SGC's A record: the whole list is written back without it.
func (n *namecheap) DeleteA(ctx context.Context, domain, id string) error {
	kind, h, _ := strings.Cut(id, "|")
	if kind != "a" || h == "" {
		return fmt.Errorf("%q is not one of SGC's names for a Namecheap record", id)
	}
	return n.change(ctx, domain, func(hosts []ncHost) ([]ncHost, bool, error) {
		kept := slices.DeleteFunc(hosts, func(r ncHost) bool {
			return strings.EqualFold(r.Type, "A") && strings.EqualFold(r.Name, h)
		})
		// Nothing to remove (already gone): nothing is written.
		return kept, len(kept) != len(hosts), nil
	})
}

func (n *namecheap) UpdateA(ctx context.Context, domain, id, name, address string) error {
	kind, h, _ := strings.Cut(id, "|")
	if kind != "a" || h == "" {
		return fmt.Errorf("%q is not one of SGC's names for a Namecheap record", id)
	}
	return n.change(ctx, domain, func(hosts []ncHost) ([]ncHost, bool, error) {
		found := false
		for i := range hosts {
			if strings.EqualFold(hosts[i].Type, "A") && strings.EqualFold(hosts[i].Name, h) {
				hosts[i].Address, found = address, true
			}
		}
		if !found {
			return nil, false, ErrNotFound
		}
		return hosts, true, nil
	})
}
