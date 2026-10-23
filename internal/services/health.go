package services

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/proxy"
)

const (
	probeEvery   = 30 * time.Second
	probeTimeout = 3 * time.Second
	// A service is reported down after this many failed probes in a row,
	// so that one lost packet does not raise an alarm.
	downAfter = 2
)

// Transition is a service that went up or down, for notifications.
type Transition struct {
	Service Service
	Up      bool
}

// Run probes every service every 30 seconds and fetches missing icons,
// until ctx ends. Each change between up and down is passed to changed.
func (c *Catalog) Run(ctx context.Context, changed func(Transition)) {
	if changed == nil {
		changed = func(Transition) {}
	}
	ticker := time.NewTicker(probeEvery)
	defer ticker.Stop()
	// Icons are fetched in the background, at most a few at a time.
	go c.iconLoop(ctx)
	for {
		c.ProbeAll(ctx, changed)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Catalog) probe(ctx context.Context, address string) error {
	if c.cfg.Probe != nil {
		return c.cfg.Probe(ctx, address)
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return conn.Close()
}

// ProbeAll probes every service once.
func (c *Catalog) ProbeAll(ctx context.Context, changed func(Transition)) {
	all, err := c.List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			c.cfg.Log.Error("list services for probing", "error", err)
		}
		return
	}
	var wg sync.WaitGroup
	limit := make(chan struct{}, 16)
	for _, s := range all {
		if !s.Enabled || s.Pending || s.Kind == proxy.KindUDP {
			continue
		}
		wg.Add(1)
		limit <- struct{}{}
		go func(s Service) {
			defer wg.Done()
			defer func() { <-limit }()
			err := c.probe(ctx, net.JoinHostPort(s.UpstreamIP, strconv.Itoa(s.UpstreamPort)))
			if ctx.Err() != nil {
				return
			}
			if t, ok := c.recordProbe(ctx, s, err == nil); ok {
				changed(t)
			}
		}(s)
	}
	wg.Wait()
}

// recordProbe keeps the result and reports whether the service changed
// between up and down.
func (c *Catalog) recordProbe(ctx context.Context, s Service, ok bool) (Transition, bool) {
	now := c.cfg.Now().Unix()
	var up, failures int
	var since, lastUp int64
	err := c.cfg.DB.QueryRowContext(ctx, "SELECT up, failures, since, last_up_at FROM service_health WHERE service_id = ?", s.ID).
		Scan(&up, &failures, &since, &lastUp)
	known := err == nil
	if !known {
		// The first probe decides at once.
		up, failures, since = 0, 0, now
		if ok {
			up = 1
		}
	}
	wasUp := up == 1
	if ok {
		failures, lastUp = 0, now
		if !wasUp {
			up, since = 1, now
		}
	} else {
		failures++
		if wasUp && failures >= downAfter {
			up, since = 0, now
		}
	}
	if _, err := c.cfg.DB.ExecContext(context.WithoutCancel(ctx), `INSERT INTO service_health (service_id, up, failures, since, checked_at, last_up_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (service_id) DO UPDATE SET up = excluded.up, failures = excluded.failures,
		since = excluded.since, checked_at = excluded.checked_at, last_up_at = excluded.last_up_at`,
		s.ID, up, failures, since, now, lastUp); err != nil {
		c.cfg.Log.Error("keep a probe's result", "service", s.Name, "error", err)
		return Transition{}, false
	}
	if known && wasUp != (up == 1) {
		return Transition{Service: s, Up: up == 1}, true
	}
	return Transition{}, false
}
