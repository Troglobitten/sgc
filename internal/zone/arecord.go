package zone

import (
	"context"
	"errors"
	"net/http"
)

// ARecord is an address record in a zone: a name and the IPv4 address it
// points at. SGC makes one: the VPN's public name (docs/design.md §10).
//
// Zone.eu's API has no time-to-live per record (its description of the
// ARecord schema, read on 2026-10-23, has only name and destination); the
// zone's own applies.
type ARecord struct {
	ID      string
	Name    string
	Address string
}

// ARecords returns the A records of a domain's zone.
func (c *Client) ARecords(ctx context.Context, domain string) ([]ARecord, error) {
	var found []txtRecord // the same three fields
	if err := c.do(ctx, http.MethodGet, nil, &found, "dns", domain, "a"); err != nil {
		return nil, err
	}
	records := make([]ARecord, 0, len(found))
	for _, r := range found {
		records = append(records, ARecord{ID: string(r.ID), Name: r.Name, Address: r.Destination})
	}
	return records, nil
}

// AddA publishes an A record under the full name given.
func (c *Client) AddA(ctx context.Context, domain, name, address string) (ARecord, error) {
	var created []txtRecord
	if err := c.do(ctx, http.MethodPost, txtRecord{Name: name, Destination: address}, &created, "dns", domain, "a"); err != nil {
		return ARecord{}, err
	}
	if len(created) != 1 || created[0].ID == "" {
		return ARecord{}, errors.New("Zone.eu did not say which record it made")
	}
	return ARecord{ID: string(created[0].ID), Name: created[0].Name, Address: created[0].Destination}, nil
}

// UpdateA points an existing A record at another address.
func (c *Client) UpdateA(ctx context.Context, domain, id, name, address string) error {
	return c.do(ctx, http.MethodPut, txtRecord{Name: name, Destination: address}, nil, "dns", domain, "a", id)
}

// DeleteA removes an A record; one already gone is not an error.
func (c *Client) DeleteA(ctx context.Context, domain, id string) error {
	err := c.do(ctx, http.MethodDelete, nil, nil, "dns", domain, "a", id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
