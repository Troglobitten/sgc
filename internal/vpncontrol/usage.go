package vpncontrol

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// How long usage is kept per resolution (docs/design.md §4.9): per minute
// for 48 hours, per hour for 90 days, per day for good.
var keepFor = map[string]time.Duration{"minute": 48 * time.Hour, "hour": 90 * 24 * time.Hour}

// sampleUsage turns WireGuard's counters into usage: what each device sent
// and received since the last look, added to its minute, hour and day.
func (s *Service) sampleUsage(ctx context.Context) {
	if !s.On(ctx) {
		return
	}
	status, err := s.cfg.Helper.VPNStatus(ctx)
	if err != nil || !status.Stats.Up {
		return
	}
	rows, err := s.devices(ctx)
	if err != nil {
		return
	}
	byKey := map[string]int64{}
	for _, r := range rows {
		byKey[r.PublicKey] = r.ID
	}
	now := s.cfg.Now().UTC()
	for _, peer := range status.Stats.Peers {
		id, ok := byKey[peer.PublicKey]
		if !ok {
			continue
		}
		var rx, tx int64
		err := s.cfg.DB.QueryRowContext(ctx, "SELECT rx, tx FROM vpn_peer_state WHERE device_id = ?", id).Scan(&rx, &tx)
		deltaRX, deltaTX := peer.RX-rx, peer.TX-tx
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// The first look: what came before is not known per period.
			deltaRX, deltaTX = 0, 0
		case err != nil:
			continue
		case deltaRX < 0 || deltaTX < 0:
			// The counters started again (the interface was made anew).
			deltaRX, deltaTX = peer.RX, peer.TX
		}
		s.cfg.DB.ExecContext(ctx, `INSERT INTO vpn_peer_state (device_id, rx, tx, last_handshake, endpoint, seen_at)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (device_id) DO UPDATE SET rx = excluded.rx, tx = excluded.tx,
			last_handshake = CASE WHEN excluded.last_handshake > 0 THEN excluded.last_handshake ELSE vpn_peer_state.last_handshake END,
			endpoint = CASE WHEN excluded.endpoint != '' THEN excluded.endpoint ELSE vpn_peer_state.endpoint END,
			seen_at = excluded.seen_at`, id, peer.RX, peer.TX, peer.LatestHandshake, peer.Endpoint, now.Unix())
		if deltaRX == 0 && deltaTX == 0 {
			continue
		}
		for resolution, start := range map[string]time.Time{
			"minute": now.Truncate(time.Minute),
			"hour":   now.Truncate(time.Hour),
			"day":    time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC),
		} {
			s.cfg.DB.ExecContext(ctx, `INSERT INTO vpn_usage (device_id, resolution, at, rx, tx) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT (device_id, resolution, at) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx`,
				id, resolution, start.Unix(), deltaRX, deltaTX)
		}
	}
	s.mu.Lock()
	tidy := now.Sub(s.lastUsage) > time.Hour
	if tidy {
		s.lastUsage = now
	}
	s.mu.Unlock()
	if tidy {
		for resolution, keep := range keepFor {
			s.cfg.DB.ExecContext(ctx, "DELETE FROM vpn_usage WHERE resolution = ? AND at < ?", resolution, now.Add(-keep).Unix())
		}
	}
}

// UsagePoint is what a device (or all of them) sent and received in one
// period.
type UsagePoint struct {
	At time.Time `json:"at"`
	RX int64     `json:"rx"`
	TX int64     `json:"tx"`
}

// Usage returns the usage of one device (or all, for id 0) at a
// resolution: "minute" (48 hours), "hour" (90 days) or "day".
func (s *Service) Usage(ctx context.Context, id int64, resolution string) ([]UsagePoint, error) {
	if _, ok := map[string]bool{"minute": true, "hour": true, "day": true}[resolution]; !ok {
		resolution = "hour"
	}
	query := "SELECT at, SUM(rx), SUM(tx) FROM vpn_usage WHERE resolution = ?"
	args := []any{resolution}
	if id > 0 {
		query += " AND device_id = ?"
		args = append(args, id)
	}
	query += " GROUP BY at ORDER BY at"
	rows, err := s.cfg.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UsagePoint{}
	for rows.Next() {
		var at, rx, tx int64
		if err := rows.Scan(&at, &rx, &tx); err != nil {
			return nil, err
		}
		out = append(out, UsagePoint{At: time.Unix(at, 0).UTC(), RX: rx, TX: tx})
	}
	return out, rows.Err()
}

// Totals is what each device used in all, by device ID.
func (s *Service) Totals(ctx context.Context) (map[int64]UsagePoint, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, "SELECT device_id, SUM(rx), SUM(tx) FROM vpn_usage WHERE resolution = 'day' GROUP BY device_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]UsagePoint{}
	for rows.Next() {
		var id, rx, tx int64
		if err := rows.Scan(&id, &rx, &tx); err != nil {
			return nil, err
		}
		out[id] = UsagePoint{RX: rx, TX: tx}
	}
	return out, rows.Err()
}
