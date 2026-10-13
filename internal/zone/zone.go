// Package zone talks to Zone.eu's API (version 2), where the owner's domain
// has its DNS. SGC needs it to prove to Let's Encrypt that the domain is the
// owner's (a later part of milestone 8) and to keep the VPN's name pointing
// at the house (milestone 12).
//
// What is here is what SGC uses, written against Zone.eu's documentation at
// https://api.zone.eu/v2 as read on 2026-10-13:
//
//   - every request carries the ZoneID username and an API key (HTTP Basic);
//   - a domain's DNS zone is at dns/<domain>, as a list with one entry;
//   - a refusal says why in the header X-Status-Message;
//   - 60 requests a minute are allowed per address, 429 says that was passed.
//
// The documentation does not say what a wrong key is answered with. 401 and
// 403 are read as that, which is what HTTP says they mean. (The real API was
// seen to answer a made-up account with one of the two.)
//
// The API key opens the whole Zone.eu account, not only DNS (accepted risk
// R4). It is sent to the address in Endpoint and nowhere else, and it never
// appears in an error or a log line made here.
package zone

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// DefaultEndpoint is Zone.eu's API.
const DefaultEndpoint = "https://api.zone.eu/v2/"

// An answer is a short list of records. More than this is not one.
const maxAnswer = 1 << 20

var (
	// ErrCredentials: Zone.eu does not accept the username and API key.
	ErrCredentials = errors.New("Zone.eu does not accept the username and API key")
	// ErrNotFound: what was asked for is not in this account.
	ErrNotFound = errors.New("Zone.eu does not have this in the account")
	// ErrRateLimited: too many requests in the last minute.
	ErrRateLimited = errors.New("Zone.eu's limit of requests per minute is reached")
)

// StatusError is any other refusal, with Zone.eu's own words for it if it
// gave any.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("Zone.eu answered with an error (%d)", e.Code)
	}
	return fmt.Sprintf("Zone.eu answered with an error (%d: %s)", e.Code, e.Message)
}

// Client makes requests for one Zone.eu account.
type Client struct {
	endpoint  *url.URL
	username  string
	apiKey    string
	userAgent string
	http      *http.Client
}

// NewClient returns a client for the account. endpoint is DefaultEndpoint
// except in tests. The HTTP client's timeout bounds every request.
func NewClient(endpoint, username, apiKey, userAgent string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("%q is not the address of an API", endpoint)
	}
	return &Client{endpoint: parsed, username: username, apiKey: apiKey, userAgent: userAgent, http: httpClient}, nil
}

// Zone is a domain's DNS zone at Zone.eu.
type Zone struct {
	Name   string `json:"identificator"`
	Active bool   `json:"active"`
	IPv6   bool   `json:"ipv6"`
}

// Zone asks for the DNS zone of a domain. It is also the test of the
// account: an answer means that the username and key are accepted and that
// the domain's DNS is in this account.
func (c *Client) Zone(ctx context.Context, domain string) (Zone, error) {
	var zones []Zone
	if err := c.do(ctx, http.MethodGet, nil, &zones, "dns", domain); err != nil {
		return Zone{}, err
	}
	if len(zones) != 1 {
		return Zone{}, fmt.Errorf("Zone.eu answered with %d zones where one was asked for", len(zones))
	}
	return zones[0], nil
}

// TXTRecord is a TXT record in a zone: a piece of text published under a
// name. A certificate authority asks for one to see that whoever wants a
// certificate for the domain can change the domain's DNS.
type TXTRecord struct {
	// ID is Zone.eu's number for the record, which removing it takes.
	ID string
	// Name is the full name the record is published under.
	Name  string
	Value string
}

// txtRecord is a record as Zone.eu writes it.
type txtRecord struct {
	ID          flexibleID `json:"id,omitempty"`
	Name        string     `json:"name"`
	Destination string     `json:"destination"`
}

// flexibleID reads a record's number whether it comes as a number or as
// text. Zone.eu's description of the format says "integer"; its examples,
// and the client other programs use, have it in quotes.
type flexibleID string

func (id *flexibleID) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*id = flexibleID(text)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return fmt.Errorf("a record's id is neither a number nor text: %s", data)
	}
	*id = flexibleID(number.String())
	return nil
}

// TXTRecords returns the TXT records of a domain's zone.
func (c *Client) TXTRecords(ctx context.Context, domain string) ([]TXTRecord, error) {
	var found []txtRecord
	if err := c.do(ctx, http.MethodGet, nil, &found, "dns", domain, "txt"); err != nil {
		return nil, err
	}
	records := make([]TXTRecord, 0, len(found))
	for _, r := range found {
		records = append(records, TXTRecord{ID: string(r.ID), Name: r.Name, Value: r.Destination})
	}
	return records, nil
}

// AddTXT publishes a TXT record under the full name given, which must be in
// the domain's zone, and returns it with the number Zone.eu gave it.
func (c *Client) AddTXT(ctx context.Context, domain, name, value string) (TXTRecord, error) {
	var created []txtRecord
	if err := c.do(ctx, http.MethodPost, txtRecord{Name: name, Destination: value}, &created, "dns", domain, "txt"); err != nil {
		return TXTRecord{}, err
	}
	if len(created) != 1 || created[0].ID == "" {
		return TXTRecord{}, errors.New("Zone.eu did not say which record it made")
	}
	return TXTRecord{ID: string(created[0].ID), Name: created[0].Name, Value: created[0].Destination}, nil
}

// DeleteTXT removes a TXT record. A record that is already gone is not an
// error: gone is what was asked for.
func (c *Client) DeleteTXT(ctx context.Context, domain, id string) error {
	err := c.do(ctx, http.MethodDelete, nil, nil, "dns", domain, "txt", id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// do makes one request. path is joined to the endpoint piece by piece, each
// piece escaped, so that nothing in a name can change where the request goes.
func (c *Client) do(ctx context.Context, method string, body, answer any, path ...string) error {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(data)
	}
	escaped := make([]string, len(path))
	for i, piece := range path {
		// These three would be taken as steps in the address, not as names.
		if piece == "" || piece == "." || piece == ".." {
			return fmt.Errorf("%q cannot be part of an address at Zone.eu", piece)
		}
		escaped[i] = url.PathEscape(piece)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint.JoinPath(escaped...).String(), payload)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.username, c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// The error of the HTTP client names the address, never the key.
		return fmt.Errorf("reach Zone.eu: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return fmt.Errorf("read Zone.eu's answer: %w", err)
	}
	if len(data) > maxAnswer {
		return errors.New("Zone.eu's answer is larger than any answer SGC asks for")
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrCredentials
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return &StatusError{Code: resp.StatusCode, Message: plain(resp.Header.Get("X-Status-Message"))}
	}
	if answer == nil {
		return nil
	}
	if err := json.Unmarshal(data, answer); err != nil {
		return fmt.Errorf("Zone.eu's answer could not be read: %w", err)
	}
	return nil
}

// plain makes words from outside fit to show: printable, on one line, short.
func plain(message string) string {
	message = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, message)
	if runes := []rune(message); len(runes) > 200 {
		message = string(runes[:200]) + "…"
	}
	return strings.TrimSpace(message)
}

// NormalizeDomain returns a domain name as SGC stores it (lower case, no dot
// at the end), or an error saying what is wrong with it. It accepts what can
// be a registered domain or a name under one: letters, digits and hyphens in
// two or more parts. A name with other letters has to be given in its
// "xn--" form.
//
// The result goes into addresses and, later, into settings files: nothing
// but these characters gets through.
func NormalizeDomain(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return "", errors.New("the domain name is missing")
	}
	if len(name) > 253 {
		return "", errors.New("the domain name is too long")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", errors.New("a domain name has at least two parts, like domain.tld")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", errors.New("every part of a domain name has 1 to 63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("a part of a domain name cannot begin or end with a hyphen")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("a domain name has letters, digits and hyphens only; %q is none of these", c)
			}
		}
	}
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return "", errors.New("the last part of a domain name is not a number")
	}
	return name, nil
}
