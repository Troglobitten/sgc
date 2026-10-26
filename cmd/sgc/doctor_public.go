package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/public"
)

// checkInternet: with internet access on, the public door is in place at
// Traefik, the firewall lets in what the table for the internet marks, that
// table is loaded, fail2ban runs when it is switched on (and Debian's SSH
// jail does not), the public names point at home and the lists are fresh.
// It also says what the router must forward.
func checkInternet(stateDir string) doctor.Check {
	return func(ctx context.Context) []doctor.Result {
		report, err := readParts(ctx, stateDir)
		if err != nil {
			return one(doctor.Warn("Internet access could not be read: "+err.Error(), ""))
		}
		status := report.Internet
		if !status.Wanted {
			return one(doctor.Good("Internet access is off: nothing at home is reachable from the internet through SGC"))
		}
		var results []doctor.Result
		applied := proxy.ReadApplied(proxy.DefaultPaths())
		if !applied.Door {
			results = append(results, doctor.Bad("Internet access is on, but the proxy has no public door",
				"Switch the proxy off and on again on the Services page (Settings), or restart SGC: sudo systemctl restart sgc"))
		} else if err := doorAnswers(ctx); err != nil {
			results = append(results, doctor.Bad(fmt.Sprintf("The public door (port %d) does not answer: %v", public.DoorPort, err),
				"Its log: sudo journalctl -u sgc-traefik --no-pager -n 30"))
		} else {
			results = append(results, doctor.Good(fmt.Sprintf("The public door answers on port %d", public.DoorPort)))
		}

		confirmed, err := os.ReadFile(firewall.DefaultPaths().ConfirmedFile)
		cfg, parseErr := firewall.ParseConfig(confirmed)
		switch {
		case err != nil || parseErr != nil || !cfg.Enabled:
			results = append(results, doctor.Warn("Internet access is on while SGC's firewall is off",
				"Switch the firewall on (System, Security): without it more than the services you made public may be reachable."))
		case !cfg.Door:
			results = append(results, doctor.Bad("The firewall does not let visitors from the internet in yet",
				"Bring the firewall's rules up to date on the System page (Security), and confirm."))
		default:
			results = append(results, doctor.Good("The firewall lets in what the rules for the internet allow"))
		}

		if out, err := exec.CommandContext(ctx, "/usr/sbin/nft", "list", "chain", "inet", public.TableName, "input").CombinedOutput(); err != nil {
			results = append(results, doctor.Bad("The rules for the internet are not loaded: "+strings.TrimSpace(string(out)),
				"Load them again: sudo systemctl restart sgc-public"))
		} else {
			results = append(results, doctor.Good("The rules for the internet are loaded"))
		}

		if status.Settings.Fail2ban.Enabled {
			state, _ := ask(ctx, "/usr/bin/systemctl", "is-active", "fail2ban.service")
			if state != "active" {
				results = append(results, doctor.Bad("fail2ban is switched on but does not run ("+state+")",
					"Start it: sudo systemctl start fail2ban\nIts log: sudo journalctl -u fail2ban --no-pager -n 30"))
			} else {
				results = append(results, doctor.Good("fail2ban runs and bans repeat offenders from the internet"))
			}
		}
		if public.Fail2banInstalled() {
			if jails, err := exec.CommandContext(ctx, "/usr/bin/fail2ban-client", "status").CombinedOutput(); err == nil && strings.Contains(string(jails), "sshd") {
				results = append(results, doctor.Warn("fail2ban's SSH jail is on: a few wrong SSH logins from home could lock that address out",
					"SGC switches it off in /etc/fail2ban/jail.d/zz-sgc.local; switch internet access's settings off and on again to write it anew."))
			}
		}

		if status.Problem != "" {
			results = append(results, doctor.Warn(status.Problem, "The System page (Internet) shows each public name."))
		}
		if len(report.StaleLists) > 0 {
			results = append(results, doctor.Warn("Lists not fetched for days: "+strings.Join(report.StaleLists, ", "),
				"Check that this device can reach github.com and db-ip.com. The last lists SGC has stay in use."))
		}
		if len(status.Services) == 0 {
			results = append(results, doctor.Good("No service is public yet (open one on the Services page)"))
		} else {
			var forwards []string
			for _, s := range status.Services {
				if s.Kind == proxy.KindHTTP {
					forwards = append(forwards, fmt.Sprintf("%s (port 443/tcp → %s:%d)", s.Name, status.LANAddress, s.LocalPort))
				} else {
					forwards = append(forwards, fmt.Sprintf("%s (port %d/%s → %s:%d)", s.Name, s.Port, s.Kind, status.LANAddress, s.LocalPort))
				}
			}
			results = append(results, doctor.Good("Public, if your router forwards them: "+strings.Join(forwards, ", ")))
		}
		return results
	}
}

// doorAnswers checks that something speaks TLS on the public door.
func doorAnswers(ctx context.Context) error {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 4 * time.Second},
		Config: &tls.Config{ServerName: "doctor.invalid", InsecureSkipVerify: true}} //nolint:gosec // only whether it answers
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", public.DoorPort))
	if err != nil {
		return err
	}
	return conn.Close()
}
