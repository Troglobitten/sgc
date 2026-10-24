package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cloudflare's API v4, as lego's provider for it uses it (lego v4.35.2,
// read on 2026-10-24): an API token as a bearer token, zones looked up by
// name, records under zones/<id>/dns_records, every answer in an envelope
// with "success" and "errors". The token needs Zone · Zone · Read (to find
// the zone) and Zone · DNS · Edit.
const cloudflareAPI = "https://api.cloudflare.com/client/v4"

func init() {
	Register(Kind{
		ID:          "cloudflare",
		Name:        "Cloudflare",
		Credentials: "API token",
		Fields: []Field{
			{Key: "apiToken", Label: "API token", Secret: true, Max: 200,
				Help: "Made at dash.cloudflare.com, under My Profile, API Tokens, Create Token: with the permissions Zone · Zone · Read and Zone · DNS · Edit, for this domain only. SGC keeps it to itself: it is saved on this device, travels in an export, and is never shown again."},
		},
		Before: "Make an API token at Cloudflare (My Profile, API Tokens) with Zone · Zone · Read and Zone · DNS · Edit for this domain only. SGC makes the VPN's name without Cloudflare's proxy (the grey cloud): WireGuard cannot pass through that proxy.",
		// Cloudflare's own name servers show a change within seconds; lego
		// waits up to two minutes.
		Propagation: 5 * time.Minute,
		open: func(values map[string]string, opt Options) (Provider, error) {
			base := cloudflareAPI
			if opt.Endpoint != "" {
				base = opt.Endpoint
			}
			return &cloudflare{base: base, token: values["apiToken"], opt: opt, zones: map[string]string{}}, nil
		},
	})
}

type cloudflare struct {
	base  string
	token string
	opt   Options

	mu    sync.Mutex
	zones map[string]string // domain: zone id
}

type cfMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied,omitempty"`
}

func (c *cloudflare) do(ctx context.Context, method, path string, query url.Values, body, result any) error {
	target := c.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	status, data, err := send(c.opt, "Cloudflare", req)
	if err != nil {
		return err
	}
	var envelope struct {
		Success bool            `json:"success"`
		Errors  []cfMessage     `json:"errors"`
		Result  json.RawMessage `json:"result"`
	}
	json.Unmarshal(data, &envelope)
	switch {
	case status == http.StatusUnauthorized, status < 500 && status >= 400 && tokenRefused(envelope.Errors):
		return ErrCredentials
	case status == http.StatusForbidden:
		return &Refusal{Message: "Cloudflare does not let the token do this (" + cfText(envelope.Errors) + "). It needs Zone · Zone · Read and Zone · DNS · Edit for this domain"}
	case status == http.StatusTooManyRequests:
		return ErrRateLimited
	case status == http.StatusNotFound:
		return ErrNotFound
	case status >= 300 || !envelope.Success:
		return &Refusal{Message: fmt.Sprintf("Cloudflare answered with an error (%d: %s)", status, cfText(envelope.Errors))}
	}
	if result != nil {
		if err := json.Unmarshal(envelope.Result, result); err != nil {
			return fmt.Errorf("Cloudflare's answer could not be read: %w", err)
		}
	}
	return nil
}

// tokenRefused: Cloudflare's codes for a token it does not take at all
// (9109 "Invalid access token", 6003 "Invalid request headers", which is
// what a token with a typing error gets, 10000 "Authentication error").
func tokenRefused(errs []cfMessage) bool {
	for _, e := range errs {
		if e.Code == 9109 || e.Code == 6003 || e.Code == 10000 {
			return true
		}
	}
	return false
}

func cfText(errs []cfMessage) string {
	var parts []string
	for _, e := range errs {
		parts = append(parts, plainText(e.Message))
	}
	if len(parts) == 0 {
		return "no reason given"
	}
	return strings.Join(parts, "; ")
}

func (c *cloudflare) zoneID(ctx context.Context, domain string) (string, error) {
	c.mu.Lock()
	id, ok := c.zones[domain]
	c.mu.Unlock()
	if ok {
		return id, nil
	}
	var zones []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones", url.Values{"name": {domain}}, nil, &zones); err != nil {
		return "", err
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, domain) && z.ID != "" {
			if z.Status != "active" {
				return "", ErrNotActive
			}
			c.mu.Lock()
			c.zones[domain] = z.ID
			c.mu.Unlock()
			return z.ID, nil
		}
	}
	// An empty list: the zone is not in the account, or the token may not
	// see it.
	return "", ErrNotFound
}

func (c *cloudflare) records(id string) string {
	return "/zones/" + url.PathEscape(id) + "/dns_records"
}

func (c *cloudflare) Check(ctx context.Context, domain string) error {
	id, err := c.zoneID(ctx, domain)
	if err != nil {
		return err
	}
	// Reading the records tells a token that may see the zone but not its
	// DNS.
	var records []cfRecord
	return c.do(ctx, http.MethodGet, c.records(id), url.Values{"type": {"TXT"}, "per_page": {"5"}}, nil, &records)
}

func (c *cloudflare) AddTXT(ctx context.Context, domain, name, value string) (Record, error) {
	id, err := c.zoneID(ctx, domain)
	if err != nil {
		return Record{}, err
	}
	var created cfRecord
	// In quotes, as Cloudflare wants a TXT record's text (and lego sends it).
	err = c.do(ctx, http.MethodPost, c.records(id), nil, cfRecord{Type: "TXT", Name: name, Content: `"` + value + `"`, TTL: 120}, &created)
	if err != nil {
		return Record{}, err
	}
	if created.ID == "" {
		return Record{}, fmt.Errorf("Cloudflare did not say which record it made")
	}
	return Record{ID: created.ID, Name: name, Value: value}, nil
}

func (c *cloudflare) DeleteTXT(ctx context.Context, domain, recordID string) error {
	id, err := c.zoneID(ctx, domain)
	if err != nil {
		return err
	}
	err = c.do(ctx, http.MethodDelete, c.records(id)+"/"+url.PathEscape(recordID), nil, nil, nil)
	if err == ErrNotFound {
		return nil // already gone
	}
	return err
}

func (c *cloudflare) ARecords(ctx context.Context, domain string) ([]Record, error) {
	id, err := c.zoneID(ctx, domain)
	if err != nil {
		return nil, err
	}
	var out []Record
	// A hundred to a page; a zone with more than 5000 A records is not a home.
	for page := 1; page <= 50; page++ {
		var records []cfRecord
		query := url.Values{"type": {"A"}, "per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if err := c.do(ctx, http.MethodGet, c.records(id), query, nil, &records); err != nil {
			return nil, err
		}
		for _, r := range records {
			out = append(out, Record{ID: r.ID, Name: r.Name, Value: r.Content})
		}
		if len(records) < 100 {
			break
		}
	}
	return out, nil
}

// unproxied is the VPN's record as Cloudflare is to keep it: TTL 1 is
// Cloudflare's "automatic", and without its proxy, which takes web traffic
// only and would swallow WireGuard's.
func unproxied(name, address string) cfRecord {
	off := false
	return cfRecord{Type: "A", Name: name, Content: address, TTL: 1, Proxied: &off}
}

func (c *cloudflare) AddA(ctx context.Context, domain, name, address string) (Record, error) {
	id, err := c.zoneID(ctx, domain)
	if err != nil {
		return Record{}, err
	}
	var created cfRecord
	if err := c.do(ctx, http.MethodPost, c.records(id), nil, unproxied(name, address), &created); err != nil {
		return Record{}, err
	}
	if created.ID == "" {
		return Record{}, fmt.Errorf("Cloudflare did not say which record it made")
	}
	return Record{ID: created.ID, Name: name, Value: address}, nil
}

func (c *cloudflare) UpdateA(ctx context.Context, domain, recordID, name, address string) error {
	id, err := c.zoneID(ctx, domain)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPatch, c.records(id)+"/"+url.PathEscape(recordID), nil, unproxied(name, address), nil)
}
