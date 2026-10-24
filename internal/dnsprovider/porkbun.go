package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Porkbun's API v3, as the client lego uses for it calls it
// (github.com/nrdcg/porkbun v0.4.0, read on 2026-10-24): every call is a
// POST to api.porkbun.com/api/json/v3/<what>/<domain>, with the two keys in
// the JSON body ("apikey", "secretapikey"), and is answered with
// {"status": "SUCCESS" or "ERROR", "message": ...}. A new record's name is
// relative to the domain; a listed record's is the full name. The shortest
// time-to-live Porkbun takes is 300 seconds.
//
// Porkbun answers for a domain only once "API Access" is switched on for
// it, in the domain's details; until then every request about it is refused.
const porkbunAPI = "https://api.porkbun.com/api/json/v3"

func init() {
	Register(Kind{
		ID:          "porkbun",
		Name:        "Porkbun",
		Credentials: "API key and secret key",
		Fields: []Field{
			{Key: "apiKey", Label: "API key", Max: 200, Secret: true,
				Help: "Made at porkbun.com, under Account, API Access: it starts with pk1_."},
			{Key: "secretKey", Label: "secret key", Max: 200, Secret: true,
				Help: "Shown with the API key, only once: it starts with sk1_. Together they open your Porkbun account, so SGC keeps them to itself: they are saved on this device, travel in an export, and are never shown again."},
		},
		Before: "At porkbun.com: make an API key under Account, API Access. Then switch on API Access for this domain: Domain Management, the domain's Details, API Access. Porkbun refuses SGC until both are done.",
		// lego waits up to ten minutes for Porkbun.
		Propagation: 10 * time.Minute,
		open: func(values map[string]string, opt Options) (Provider, error) {
			base := porkbunAPI
			if opt.Endpoint != "" {
				base = opt.Endpoint
			}
			return &porkbun{base: base, apiKey: values["apiKey"], secretKey: values["secretKey"], opt: opt}, nil
		},
	})
}

type porkbun struct {
	base              string
	apiKey, secretKey string
	opt               Options
}

type pbRecord struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl,omitempty"`
}

// call posts to one of Porkbun's calls and reads the answer into result.
func (p *porkbun) call(ctx context.Context, domain string, path []string, fields map[string]string, result any) error {
	body := map[string]string{"apikey": p.apiKey, "secretapikey": p.secretKey}
	for k, v := range fields {
		body[k] = v
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	escaped := make([]string, len(path))
	for i, part := range path {
		escaped[i] = url.PathEscape(part)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/"+strings.Join(escaped, "/"), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	status, answer, err := send(p.opt, "Porkbun", req)
	if err != nil {
		return err
	}
	var outcome struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Code    string `json:"code"`
	}
	json.Unmarshal(answer, &outcome)
	if status == http.StatusOK && outcome.Status == "SUCCESS" {
		if result != nil {
			if err := json.Unmarshal(answer, result); err != nil {
				return fmt.Errorf("Porkbun's answer could not be read: %w", err)
			}
		}
		return nil
	}
	return porkbunRefusal(status, domain, outcome.Code, outcome.Message)
}

// porkbunRefusal reads Porkbun's refusals. Its documentation names codes
// (INVALID_API_KEYS_001 and so on); older answers carry only a message
// ("Invalid API key. (002)"), so both are looked at.
func porkbunRefusal(status int, domain, code, message string) error {
	words := strings.ToLower(message)
	switch {
	case status == http.StatusTooManyRequests || code == "RATE_LIMIT_EXCEEDED":
		return ErrRateLimited
	case strings.HasPrefix(code, "INVALID_API_KEY") || code == "API_KEY_REQUIRED" || strings.Contains(words, "invalid api key"):
		return ErrCredentials
	case code == "API_ACCESS_DISABLED" || strings.Contains(words, "opted in") || strings.Contains(words, "api access"):
		return &Refusal{Message: "Porkbun does not let SGC manage " + domain + " yet: switch on API Access for it at porkbun.com (Domain Management, the domain's Details, API Access)"}
	case code == "DOMAIN_NOT_FOUND" || strings.Contains(words, "domain not found") || strings.Contains(words, "invalid domain"):
		return ErrNotFound
	case code == "DOMAIN_NOT_ALLOWED" || code == "INSUFFICIENT_SCOPE":
		return &Refusal{Message: "Porkbun does not let this API key manage " + domain + " (" + plainText(message) + ")"}
	case status >= 500:
		return fmt.Errorf("%w: Porkbun: it answered %d", ErrUnreachable, status)
	}
	if message == "" {
		message = "no reason given"
	}
	return &Refusal{Message: fmt.Sprintf("Porkbun answered with an error (%d: %s)", status, plainText(message))}
}

func (p *porkbun) list(ctx context.Context, domain string) ([]pbRecord, error) {
	var answer struct {
		Records []pbRecord `json:"records"`
	}
	if err := p.call(ctx, domain, []string{"dns", "retrieve", domain}, nil, &answer); err != nil {
		return nil, err
	}
	return answer.Records, nil
}

func (p *porkbun) Check(ctx context.Context, domain string) error {
	_, err := p.list(ctx, domain)
	return err
}

// create makes a record and returns its ID, which Porkbun gives as a number.
func (p *porkbun) create(ctx context.Context, domain, kind, name, content string) (string, error) {
	sub, ok := relative(name, domain)
	if !ok {
		return "", fmt.Errorf("%s is not under %s", name, domain)
	}
	var answer struct {
		ID json.Number `json:"id"`
	}
	err := p.call(ctx, domain, []string{"dns", "create", domain},
		map[string]string{"name": sub, "type": kind, "content": content, "ttl": "300"}, &answer)
	if err != nil {
		return "", err
	}
	if answer.ID == "" {
		return "", fmt.Errorf("Porkbun did not say which record it made")
	}
	return answer.ID.String(), nil
}

func (p *porkbun) AddTXT(ctx context.Context, domain, name, value string) (Record, error) {
	id, err := p.create(ctx, domain, "TXT", name, value)
	if err != nil {
		return Record{}, err
	}
	return Record{ID: id, Name: name, Value: value}, nil
}

func (p *porkbun) DeleteTXT(ctx context.Context, domain, id string) error {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return fmt.Errorf("%q is not one of Porkbun's record IDs", id)
	}
	err := p.call(ctx, domain, []string{"dns", "delete", domain, id}, nil, nil)
	var refusal *Refusal
	if errors.As(err, &refusal) {
		// Porkbun's words for a record that is already gone are not
		// documented; the list says whether it is.
		if records, listErr := p.list(ctx, domain); listErr == nil && !slices.ContainsFunc(records, func(r pbRecord) bool { return r.ID == id }) {
			return nil
		}
	}
	return err
}

func (p *porkbun) ARecords(ctx context.Context, domain string) ([]Record, error) {
	records, err := p.list(ctx, domain)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, r := range records {
		if strings.EqualFold(r.Type, "A") {
			out = append(out, Record{ID: r.ID, Name: r.Name, Value: r.Content})
		}
	}
	return out, nil
}

func (p *porkbun) AddA(ctx context.Context, domain, name, address string) (Record, error) {
	id, err := p.create(ctx, domain, "A", name, address)
	if err != nil {
		return Record{}, err
	}
	return Record{ID: id, Name: name, Value: address}, nil
}

func (p *porkbun) UpdateA(ctx context.Context, domain, id, name, address string) error {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return fmt.Errorf("%q is not one of Porkbun's record IDs", id)
	}
	sub, ok := relative(name, domain)
	if !ok {
		return fmt.Errorf("%s is not under %s", name, domain)
	}
	return p.call(ctx, domain, []string{"dns", "edit", domain, id},
		map[string]string{"name": sub, "type": "A", "content": address, "ttl": "300"}, nil)
}
