package notify

import (
	"context"
	"strings"
	"time"
)

// Finding is a problem a condition sees now.
type Finding struct {
	// Key names the thing within the condition ("12" for service 12).
	Key      string
	Event    string
	Severity string
	Title    string
	Body     string
	// Resolved is what to say once it is over ("" to say nothing).
	Resolved string
}

// Condition looks at one part of SGC and says what is wrong with it now. An
// error means it could not look; nothing is raised or resolved then.
type Condition func(ctx context.Context) ([]Finding, error)

// Watch looks at every condition once a minute, raises what is new and
// resolves what is over, until ctx ends. A condition's findings are kept
// under "<name>:<key>".
func (s *Service) Watch(ctx context.Context, conditions map[string]Condition) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	first := time.NewTimer(90 * time.Second) // after start-up has settled
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-ticker.C:
		}
		for name, look := range conditions {
			s.look(ctx, name, look)
		}
	}
}

func (s *Service) look(ctx context.Context, name string, look Condition) {
	findings, err := look(ctx)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	resolved := map[string]string{}
	for _, f := range findings {
		key := name + ":" + f.Key
		seen[key] = true
		s.Raise(ctx, key, f.Event, f.Severity, f.Title, f.Body)
		resolved[key] = f.Resolved
	}
	rows, err := s.cfg.DB.QueryContext(ctx, "SELECT ongoing_key FROM notification WHERE resolved_at = 0 AND ongoing_key LIKE ? ESCAPE '\\'",
		strings.NewReplacer("%", "\\%", "_", "\\_").Replace(name)+":%")
	if err != nil {
		return
	}
	var open []string
	for rows.Next() {
		var key string
		if rows.Scan(&key) == nil {
			open = append(open, key)
		}
	}
	rows.Close()
	for _, key := range open {
		if !seen[key] {
			s.Resolve(ctx, key, "Resolved")
		}
	}
}
