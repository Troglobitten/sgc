package dnsprovider

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/zone"
)

// ZoneID is Zone.eu, SGC's first provider. Its client is internal/zone; an
// account saved before 0.18.0 is a Zone.eu account (domaincontrol).
const ZoneID = "zone"

func init() {
	Register(Kind{
		ID:          ZoneID,
		Name:        "Zone.eu",
		Credentials: "username and API key",
		Fields: []Field{
			{Key: "username", Label: "ZoneID username", Help: "The name you sign in with at Zone.eu.", Max: 100},
			{Key: "apiKey", Label: "API key", Secret: true, Max: 200,
				Help: "It opens your whole Zone.eu account, so SGC keeps it to itself: it is saved on this device, travels in an export, and is never shown again."},
		},
		Before: "Make an API key in your ZoneID account management at Zone.eu.",
		// Zone.eu's name servers show a change within minutes at most.
		Propagation: 10 * time.Minute,
		open:        openZone,
	})
}

type zoneProvider struct{ c *zone.Client }

func openZone(values map[string]string, opt Options) (Provider, error) {
	if strings.Contains(values["username"], ":") {
		return nil, &Refusal{Message: "That is not a ZoneID username: it is the name you sign in with at Zone.eu"}
	}
	endpoint := opt.ZoneEndpoint
	if endpoint == "" {
		endpoint = zone.DefaultEndpoint
	}
	c, err := zone.NewClient(endpoint, values["username"], values["apiKey"], opt.UserAgent, opt.HTTP)
	if err != nil {
		return nil, err
	}
	return zoneProvider{c}, nil
}

// zoneError puts Zone.eu's errors in this package's terms.
func zoneError(err error) error {
	var refusal *zone.StatusError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, zone.ErrCredentials):
		return ErrCredentials
	case errors.Is(err, zone.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, zone.ErrRateLimited):
		return ErrRateLimited
	case errors.As(err, &refusal):
		return &Refusal{Message: refusal.Error()}
	case strings.HasPrefix(err.Error(), "reach Zone.eu"):
		return transportError("Zone.eu", errors.Unwrap(err))
	}
	return err
}

func (z zoneProvider) Check(ctx context.Context, domain string) error {
	found, err := z.c.Zone(ctx, domain)
	if err != nil {
		return zoneError(err)
	}
	if !found.Active {
		return ErrNotActive
	}
	return nil
}

func (z zoneProvider) AddTXT(ctx context.Context, domain, name, value string) (Record, error) {
	r, err := z.c.AddTXT(ctx, domain, name, value)
	if err != nil {
		return Record{}, zoneError(err)
	}
	return Record{ID: r.ID, Name: r.Name, Value: r.Value}, nil
}

func (z zoneProvider) DeleteTXT(ctx context.Context, domain, id string) error {
	return zoneError(z.c.DeleteTXT(ctx, domain, id))
}

func (z zoneProvider) ARecords(ctx context.Context, domain string) ([]Record, error) {
	found, err := z.c.ARecords(ctx, domain)
	if err != nil {
		return nil, zoneError(err)
	}
	out := make([]Record, 0, len(found))
	for _, r := range found {
		out = append(out, Record{ID: r.ID, Name: r.Name, Value: r.Address})
	}
	return out, nil
}

func (z zoneProvider) AddA(ctx context.Context, domain, name, address string) (Record, error) {
	r, err := z.c.AddA(ctx, domain, name, address)
	if err != nil {
		return Record{}, zoneError(err)
	}
	return Record{ID: r.ID, Name: r.Name, Value: r.Address}, nil
}

func (z zoneProvider) UpdateA(ctx context.Context, domain, id, name, address string) error {
	return zoneError(z.c.UpdateA(ctx, domain, id, name, address))
}
