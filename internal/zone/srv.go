package zone

import (
	"context"
	"errors"
	"net/http"
)

// SRVRecord is a service record: under a name like
// "_minecraft._tcp.mc.domain.tld" it says on which host and port a service
// is found, so that a program that reads SRV records (Minecraft Java does)
// needs no port typed in. SGC makes one per public service the owner gives
// a service name (docs/design.md §14).
//
// Zone.eu's API (its description, read on 2026-10-25): /dns/{zone}/srv, the
// target in "destination", with "priority", "weight" and "port".
type SRVRecord struct {
	ID       string
	Name     string
	Target   string
	Priority int
	Weight   int
	Port     int
}

// srvRecord is a service record as Zone.eu writes it.
type srvRecord struct {
	ID          flexibleID `json:"id,omitempty"`
	Name        string     `json:"name"`
	Destination string     `json:"destination"`
	Priority    int        `json:"priority"`
	Weight      int        `json:"weight"`
	Port        int        `json:"port"`
}

func (r srvRecord) record() SRVRecord {
	return SRVRecord{ID: string(r.ID), Name: r.Name, Target: r.Destination, Priority: r.Priority, Weight: r.Weight, Port: r.Port}
}

// SRVRecords returns the service records of a domain's zone.
func (c *Client) SRVRecords(ctx context.Context, domain string) ([]SRVRecord, error) {
	var found []srvRecord
	if err := c.do(ctx, http.MethodGet, nil, &found, "dns", domain, "srv"); err != nil {
		return nil, err
	}
	records := make([]SRVRecord, 0, len(found))
	for _, r := range found {
		records = append(records, r.record())
	}
	return records, nil
}

// AddSRV publishes a service record under the full name given.
func (c *Client) AddSRV(ctx context.Context, domain string, r SRVRecord) (SRVRecord, error) {
	var created []srvRecord
	body := srvRecord{Name: r.Name, Destination: r.Target, Priority: r.Priority, Weight: r.Weight, Port: r.Port}
	if err := c.do(ctx, http.MethodPost, body, &created, "dns", domain, "srv"); err != nil {
		return SRVRecord{}, err
	}
	if len(created) != 1 || created[0].ID == "" {
		return SRVRecord{}, errors.New("Zone.eu did not say which record it made")
	}
	return created[0].record(), nil
}

// DeleteSRV removes a service record; one already gone is not an error.
func (c *Client) DeleteSRV(ctx context.Context, domain, id string) error {
	err := c.do(ctx, http.MethodDelete, nil, nil, "dns", domain, "srv", id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
