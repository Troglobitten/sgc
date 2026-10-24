package gateway

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsnames"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/problem"
)

// ControlConfig is what Control needs.
type ControlConfig struct {
	DB    *sql.DB
	Audit *audit.Log
	// Domain returns the owner's domain, if one is set up.
	Domain func(ctx context.Context) (string, bool, error)
	// LAN finds the device in the home network.
	LAN func() (netinfo.LAN, error)
	// Names is what keeps names in AdGuard Home.
	Names *dnsnames.Service
	// Taken says what already uses a label under the domain ("" if
	// nothing): a service, the VPN's name.
	Taken func(ctx context.Context, label string) (string, error)
	// WebPort is where SGC's page listens.
	WebPort int
	// ProxyOn reports whether the proxy is on, which gives AdGuard Home's
	// page a name of its own.
	ProxyOn func(ctx context.Context) bool
	Log     *slog.Logger
}

// Control is the gateway's own name: keeping it, and what the page shows
// about the names SGC hands out.
type Control struct{ cfg ControlConfig }

func NewControl(cfg ControlConfig) *Control { return &Control{cfg: cfg} }

// Status is what the page shows.
type Status struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	// FQDN and URL are "" until a domain is set up. URL is without a port
	// while the proxy is on (Traefik passes the name through to SGC's page),
	// and with :8443 otherwise. DirectURL always has the port: it does not
	// depend on Traefik, so it is the way in when Traefik does not run.
	FQDN      string `json:"fqdn"`
	URL       string `json:"url"`
	DirectURL string `json:"directUrl"`
	// LAN is where the device is in the home network; LANProblem says why
	// that could not be found.
	LAN        *netinfo.LAN    `json:"lan"`
	LANProblem string          `json:"lanProblem"`
	DNS        dnsnames.Status `json:"dns"`
}

func (c *Control) Status(ctx context.Context) (Status, error) {
	name, err := Name(ctx, c.cfg.DB)
	if err != nil {
		return Status{}, err
	}
	domain, configured, err := c.cfg.Domain(ctx)
	if err != nil {
		return Status{}, err
	}
	status := Status{Name: name, DNS: c.cfg.Names.Status()}
	if configured {
		status.Domain = domain
		status.FQDN = FQDN(name, domain)
		status.DirectURL = "https://" + status.FQDN + ":" + strconv.Itoa(c.cfg.WebPort)
		status.URL = status.DirectURL
		if c.cfg.ProxyOn != nil && c.cfg.ProxyOn(ctx) {
			status.URL = "https://" + status.FQDN
		}
	}
	if lan, err := c.cfg.LAN(); err != nil {
		status.LANProblem = err.Error()
	} else {
		status.LAN = &lan
	}
	return status, nil
}

// SetName gives the gateway another label.
func (c *Control) SetName(ctx context.Context, actor, remote, name string) error {
	if !ValidLabel(name) {
		return problem.New("A name is 1 to 63 lower-case letters, digits and hyphens, and does not start or end with a hyphen.")
	}
	current, err := Name(ctx, c.cfg.DB)
	if err != nil {
		return err
	}
	if name == current {
		return nil
	}
	if name == AdGuardName {
		return problem.New(`"` + AdGuardName + `" is where AdGuard Home's page is found. Choose another name.`)
	}
	if holder, err := c.cfg.Taken(ctx, name); err != nil {
		return err
	} else if holder != "" {
		return problem.Newf("%q is already used by %s.", name, holder)
	}
	if err := SetName(ctx, c.cfg.DB, name); err != nil {
		return err
	}
	if err := c.cfg.Audit.Record(context.WithoutCancel(ctx), actor, audit.ActionGatewayRenamed, current+" → "+name, remote); err != nil {
		c.cfg.Log.Error("write audit log", "error", err)
	}
	c.cfg.Names.Kick()
	return nil
}

// Desired is the gateway's own part of the names in AdGuard Home: its page,
// and AdGuard Home's page once the proxy is on to show it there.
func (c *Control) Desired(ctx context.Context) ([]dnsnames.Name, error) {
	domain, configured, err := c.cfg.Domain(ctx)
	if err != nil || !configured {
		return nil, err
	}
	lan, err := c.cfg.LAN()
	if err != nil {
		return nil, err
	}
	name, err := Name(ctx, c.cfg.DB)
	if err != nil {
		return nil, err
	}
	answer := lan.Address.String()
	names := []dnsnames.Name{{Domain: FQDN(name, domain), Answer: answer, For: "SGC's page"}}
	if c.cfg.ProxyOn != nil && c.cfg.ProxyOn(ctx) {
		names = append(names, dnsnames.Name{Domain: FQDN(AdGuardName, domain), Answer: answer, For: "AdGuard Home's page"})
	}
	return names, nil
}

// UseNames gives Control the service that keeps the names. It is made after
// Control, because that service asks Control which names there are.
func (c *Control) UseNames(names *dnsnames.Service) { c.cfg.Names = names }
