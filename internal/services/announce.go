package services

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/gateway"
)

// Announcement is one service a server announced: "name:port", with the
// call's optional fields.
type Announcement struct {
	Name     string
	Port     int
	Kind     string
	Scheme   string
	Mode     string
	Category string
}

// AnnounceResult is what became of one announced service.
type AnnounceResult struct {
	Name string `json:"name"`
	// URL is where it is now found, "" if it was refused.
	URL string `json:"url,omitempty"`
	// Refused says why, "" if it was accepted.
	Refused string `json:"refused,omitempty"`
	// New: it was not known before. Pending: it waits for the owner's approval.
	New     bool `json:"new"`
	Pending bool `json:"pending"`
	// Conflict: another server or the owner already has the name, which is
	// worth an alert (docs/design.md §4.6).
	Conflict bool `json:"conflict"`
}

// Announce takes up what a server announced. The address is the one the
// request came from, never one from the request (docs/design.md §4.6); the
// caller has checked the token. Nothing an announcement says can make a
// service protected or change who may reach it.
func (c *Catalog) Announce(ctx context.Context, tokenID int64, tokenLabel, ip string, items []Announcement) ([]AnnounceResult, error) {
	domain, err := c.domain(ctx)
	if err != nil {
		return nil, err
	}
	reserved, err := c.cfg.Reserved(ctx)
	if err != nil {
		return nil, err
	}
	approve, err := c.ApproveNew(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]AnnounceResult, 0, len(items))
	changed := false
	now := c.cfg.Now().Unix()
	actor := "token:" + tokenLabel
	for _, item := range items {
		result := AnnounceResult{Name: item.Name}
		refuse := func(reason string) {
			result.Refused = reason
			results = append(results, result)
			c.record(ctx, actor, audit.ActionServiceAnnounceRefused, item.Name+": "+reason, ip)
		}
		in := Input{Name: item.Name, Kind: item.Kind, Mode: item.Mode, UpstreamIP: ip, UpstreamPort: item.Port,
			Scheme: item.Scheme, Category: item.Category, Enabled: true}
		if !gateway.ValidLabel(in.Name) {
			refuse("not a valid name (lower-case letters, digits and hyphens)")
			continue
		}
		if holder, ok := reserved[in.Name]; ok {
			result.Conflict = true
			refuse("the name is used by " + holder)
			continue
		}
		var existingID int64
		var existingToken sql.NullInt64
		var existing Input
		err := c.cfg.DB.QueryRowContext(ctx, `SELECT id, token_id, kind, mode, upstream_ip, upstream_port, scheme, listen_port, category
			FROM service WHERE name = ?`, in.Name).Scan(&existingID, &existingToken, &existing.Kind, &existing.Mode,
			&existing.UpstreamIP, &existing.UpstreamPort, &existing.Scheme, &existing.ListenPort, &existing.Category)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// New: first claim wins.
			normal, err := c.normalise(ctx, in, 0)
			if err != nil {
				refuse(errorWords(err))
				continue
			}
			res, err := c.cfg.DB.ExecContext(ctx, `INSERT INTO service (name, kind, mode, upstream_ip, upstream_port, scheme,
				listen_port, category, enabled, pending, token_id, created_at, updated_at, announced_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
				normal.Name, normal.Kind, normal.Mode, normal.UpstreamIP, normal.UpstreamPort, normal.Scheme,
				normal.ListenPort, normal.Category, approve, tokenID, now, now, now)
			if err != nil {
				return nil, err
			}
			id, _ := res.LastInsertId()
			result.New, result.Pending = true, approve
			result.URL = urlOf(Service{Name: normal.Name, Kind: normal.Kind, Mode: normal.Mode, ListenPort: normal.ListenPort, UpstreamPort: normal.UpstreamPort}, domain)
			detail := describe(normal)
			if approve {
				detail += " (waits for approval)"
			}
			c.record(ctx, actor, audit.ActionServiceAnnounced, detail, ip)
			c.fetchIconSoon(id)
			changed = true
		case err != nil:
			return nil, err
		case !existingToken.Valid || existingToken.Int64 != tokenID:
			result.Conflict = true
			if existingToken.Valid {
				refuse("another server already announced this name")
			} else {
				refuse("a service with this name was added in SGC's page")
			}
			continue
		default:
			// The same server again: the port (and the kind) may change; the
			// owner's settings for it stay.
			if in.Kind == "" {
				in.Kind = existing.Kind
			}
			if in.Mode == "" && in.Kind == existing.Kind {
				in.Mode = existing.Mode
			}
			if in.Scheme == "" {
				in.Scheme = existing.Scheme
			}
			if in.Category == "" {
				in.Category = existing.Category
			}
			if in.Kind == existing.Kind && in.Mode == existing.Mode && in.Mode == ModeProxied && existing.ListenPort != 0 && existing.UpstreamPort == in.UpstreamPort {
				in.ListenPort = existing.ListenPort
			}
			normal, err := c.normalise(ctx, in, existingID)
			if err != nil {
				refuse(errorWords(err))
				continue
			}
			same := normal.Kind == existing.Kind && normal.Mode == existing.Mode && normal.UpstreamIP == existing.UpstreamIP &&
				normal.UpstreamPort == existing.UpstreamPort && normal.Scheme == existing.Scheme && normal.ListenPort == existing.ListenPort &&
				normal.Category == existing.Category
			if !same {
				if _, err := c.cfg.DB.ExecContext(ctx, `UPDATE service SET kind = ?, mode = ?, upstream_ip = ?, upstream_port = ?,
					scheme = ?, listen_port = ?, category = ?, updated_at = ?, announced_at = ? WHERE id = ?`,
					normal.Kind, normal.Mode, normal.UpstreamIP, normal.UpstreamPort, normal.Scheme, normal.ListenPort,
					normal.Category, now, now, existingID); err != nil {
					return nil, err
				}
				c.cfg.DB.ExecContext(ctx, "DELETE FROM service_health WHERE service_id = ?", existingID)
				c.record(ctx, actor, audit.ActionServiceAnnounced, describe(normal)+" (changed)", ip)
				changed = true
			} else if _, err := c.cfg.DB.ExecContext(ctx, "UPDATE service SET announced_at = ? WHERE id = ?", now, existingID); err != nil {
				return nil, err
			}
			result.URL = urlOf(Service{Name: normal.Name, Kind: normal.Kind, Mode: normal.Mode, ListenPort: normal.ListenPort, UpstreamPort: normal.UpstreamPort}, domain)
		}
		results = append(results, result)
	}
	if changed {
		c.cfg.Changed()
	}
	return results, nil
}

func errorWords(err error) string {
	if words := err.Error(); words != "" {
		return words
	}
	return "refused"
}

// TokenServices counts the services each token announced.
func (c *Catalog) TokenServices(ctx context.Context) (map[int64][]string, error) {
	rows, err := c.cfg.DB.QueryContext(ctx, "SELECT token_id, name FROM service WHERE token_id IS NOT NULL ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = append(out[id], name)
	}
	return out, rows.Err()
}

// ReleaseToken handles a removed token's services: switched off, or kept as
// services of the page's own.
func (c *Catalog) ReleaseToken(ctx context.Context, tokenID int64, keep bool) error {
	query := "UPDATE service SET enabled = 0, token_id = NULL, updated_at = ? WHERE token_id = ?"
	if keep {
		query = "UPDATE service SET token_id = NULL, updated_at = ? WHERE token_id = ?"
	}
	if _, err := c.cfg.DB.ExecContext(ctx, query, c.cfg.Now().Unix(), tokenID); err != nil {
		return err
	}
	c.cfg.Changed()
	return nil
}

// ParseService reads "name:port".
func ParseService(s string) (string, int, bool) {
	for i := len(s) - 1; i > 0; i-- {
		if s[i] == ':' {
			port, err := strconv.Atoi(s[i+1:])
			if err != nil || port < 1 || port > 65535 {
				return "", 0, false
			}
			return s[:i], port, true
		}
	}
	return "", 0, false
}
