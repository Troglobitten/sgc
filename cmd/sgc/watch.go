package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Troglobitten/sgc/internal/backups"
	"github.com/Troglobitten/sgc/internal/certcontrol"
	"github.com/Troglobitten/sgc/internal/dnscontrol"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
	"github.com/Troglobitten/sgc/internal/eol"
	"github.com/Troglobitten/sgc/internal/health"
	"github.com/Troglobitten/sgc/internal/notify"
	"github.com/Troglobitten/sgc/internal/oscontrol"
	"github.com/Troglobitten/sgc/internal/update"
)

// watched is everything the notifications look at.
type watched struct {
	cert    *certcontrol.Service
	domain  *domaincontrol.Service
	dns     *dnscontrol.Service
	named   *parts
	monitor *health.Monitor
	updates *update.Checker
	os      *oscontrol.Service
	eol     *eol.Service
	backups *backups.Service
}

// conditions are what SGC tells the owner about while it lasts, each
// looked at once a minute (internal/notify).
func (w watched) conditions() map[string]notify.Condition {
	return map[string]notify.Condition{
		"certificate": func(ctx context.Context) ([]notify.Finding, error) {
			status, err := w.cert.Status(ctx)
			if err != nil {
				return nil, err
			}
			var out []notify.Finding
			if c := status.Certificate; c != nil && c.ForDomain {
				if days := int(time.Until(c.NotAfter).Hours() / 24); days < 14 {
					out = append(out, notify.Finding{Key: "expiring", Event: notify.EventCertificate, Severity: notify.Problem,
						Title: fmt.Sprintf("The certificate runs out in %d days", days),
						Body:  "SGC has not managed to renew it. The System page, Certificate, says why."})
				}
			}
			if a := status.LastAttempt; a != nil && !a.OK && a.Kind != "first" && status.Certificate != nil {
				out = append(out, notify.Finding{Key: "renewal", Event: notify.EventCertificate, Severity: notify.Warning,
					Title: "Renewing the certificate failed", Body: a.Message + " SGC tries again by itself."})
			}
			return out, nil
		},
		"domain": func(ctx context.Context) ([]notify.Finding, error) {
			status, err := w.domain.Status(ctx)
			if err != nil {
				return nil, err
			}
			if status.Configured && status.CheckedAt != nil && !status.OK {
				return []notify.Finding{{Key: "zone", Event: notify.EventDomain, Severity: notify.Problem,
					Title: "Zone.eu no longer accepts SGC's key for " + status.Domain,
					Body:  status.Problem + " Without it the certificate cannot be renewed. Enter a new key on the System page."}}, nil
			}
			return nil, nil
		},
		"core": func(ctx context.Context) ([]notify.Finding, error) {
			var out []notify.Finding
			if status, err := w.dns.Status(ctx); err == nil && status.Available && status.Enabled && !status.Running {
				out = append(out, notify.Finding{Key: "dns", Event: notify.EventCoreDown, Severity: notify.Problem,
					Title: "DNS (AdGuard Home) is not running", Body: "Devices that use this device for DNS get no answers. sudo sgc doctor on the device says more."})
			}
			if status, err := w.named.proxy.Status(ctx); err == nil && status.Wanted && status.Installed && !status.Running {
				out = append(out, notify.Finding{Key: "proxy", Event: notify.EventCoreDown, Severity: notify.Problem,
					Title: "The proxy (Traefik) is not running", Body: "The services' names do not open. sudo sgc doctor on the device says more."})
			}
			if status, err := w.named.vpn.Status(ctx); err == nil && status.Enabled && !status.Up {
				out = append(out, notify.Finding{Key: "vpn", Event: notify.EventCoreDown, Severity: notify.Problem,
					Title: "The VPN is not running", Body: "Devices cannot connect from outside. " + status.Problem})
			}
			return out, nil
		},
		"public-ip": func(ctx context.Context) ([]notify.Finding, error) {
			status, err := w.named.vpn.Status(ctx)
			if err != nil || !status.Enabled || status.PublicState == nil || status.PublicState.Problem == "" {
				return nil, err
			}
			return []notify.Finding{{Key: "endpoint", Event: notify.EventPublicIP, Severity: notify.Warning,
				Title: "The VPN's public name needs a look", Body: status.PublicState.Problem}}, nil
		},
		"service": func(ctx context.Context) ([]notify.Finding, error) {
			list, err := w.named.catalog.List(ctx)
			if err != nil {
				return nil, err
			}
			var out []notify.Finding
			for _, s := range list {
				if !s.Enabled || s.Pending || s.Health.State != "down" {
					continue
				}
				name := s.Title
				if name == "" {
					name = s.Name
				}
				if s.Health.Abandoned {
					out = append(out, notify.Finding{Key: "abandoned-" + strconv.FormatInt(s.ID, 10), Event: notify.EventAbandoned, Severity: notify.Info,
						Title: name + " looks abandoned", Body: "It has not answered for a long time. Remove it on the Services page if it is gone for good."})
					continue
				}
				out = append(out, notify.Finding{Key: strconv.FormatInt(s.ID, 10), Event: notify.EventServiceDown, Severity: notify.Warning,
					Title: name + " does not answer", Body: fmt.Sprintf("%s at %s:%d stopped answering. Is it switched on?", name, s.UpstreamIP, s.UpstreamPort)})
			}
			return out, nil
		},
		"health": func(context.Context) ([]notify.Finding, error) {
			snap := w.monitor.Snapshot()
			var out []notify.Finding
			if snap.DiskTotalBytes > 0 && float64(snap.DiskUsedBytes)/float64(snap.DiskTotalBytes) > 0.9 {
				out = append(out, notify.Finding{Key: "disk", Event: notify.EventHealth, Severity: notify.Warning,
					Title: "The disk is nearly full", Body: fmt.Sprintf("%d%% of it is used. Updates and logs need room.", 100*snap.DiskUsedBytes/snap.DiskTotalBytes)})
			}
			if snap.TemperatureC != nil && *snap.TemperatureC > 80 {
				out = append(out, notify.Finding{Key: "temperature", Event: notify.EventHealth, Severity: notify.Warning,
					Title: "The device is running hot", Body: fmt.Sprintf("%.0f °C. A Raspberry Pi slows itself down above 80 °C; check its cooling.", *snap.TemperatureC)})
			}
			return out, nil
		},
		"updates": func(ctx context.Context) ([]notify.Finding, error) {
			var out []notify.Finding
			if status, err := w.updates.Status(ctx); err == nil && status.UpdateAvailable {
				out = append(out, notify.Finding{Key: "sgc-" + status.Latest, Event: notify.EventUpdates, Severity: notify.Info,
					Title: "SGC " + status.Latest + " is available", Body: "The dashboard shows what is new, and installs it."})
			}
			if status, err := w.os.Status(ctx); err == nil {
				if status.RestartNeeded {
					out = append(out, notify.Finding{Key: "restart", Event: notify.EventUpdates, Severity: notify.Info,
						Title: "The device needs a restart for an update", Body: "Restart it from the dashboard, or let the maintenance window do it."})
				}
				if status.Mode == "by-hand" && len(status.Waiting) > 0 {
					out = append(out, notify.Finding{Key: "waiting", Event: notify.EventUpdates, Severity: notify.Info,
						Title: fmt.Sprintf("%d updates for the device are waiting", len(status.Waiting)), Body: "Install them on the System page."})
				}
			}
			return out, nil
		},
		"eol": func(ctx context.Context) ([]notify.Finding, error) {
			var out []notify.Finding
			for _, item := range w.eol.State(ctx).Items {
				if item.Warning != "" {
					out = append(out, notify.Finding{Key: item.Product + "-" + item.Cycle, Event: notify.EventEndOfLife, Severity: notify.Warning,
						Title: item.Label + " " + item.Cycle + " reaches its end of life", Body: item.Warning})
				}
			}
			return out, nil
		},
		"backup": func(ctx context.Context) ([]notify.Finding, error) {
			status, err := w.backups.Status(ctx)
			if err != nil || !status.Overdue {
				return nil, err
			}
			body := "There has been no good backup for more than three days."
			if status.Last != nil && !status.Last.OK {
				body += " The last attempt: " + status.Last.Message
			}
			return []notify.Finding{{Key: "overdue", Event: notify.EventBackup, Severity: notify.Warning, Title: "Backups are overdue", Body: body}}, nil
		},
	}
}
