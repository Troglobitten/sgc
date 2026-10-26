package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/backup"
	"github.com/Troglobitten/sgc/internal/backups"
	"github.com/Troglobitten/sgc/internal/components"
	"github.com/Troglobitten/sgc/internal/eol"
	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/fwcontrol"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/guide"
	"github.com/Troglobitten/sgc/internal/health"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/maintenance"
	"github.com/Troglobitten/sgc/internal/notify"
	"github.com/Troglobitten/sgc/internal/oscontrol"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/sshcontrol"
	"github.com/Troglobitten/sgc/internal/sshd"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/tlscert"
	"github.com/Troglobitten/sgc/internal/updater"
	"github.com/Troglobitten/sgc/internal/web"
	webui "github.com/Troglobitten/sgc/web"
)

type serveOptions struct {
	listen        string
	stateDir      string
	helperSocket  string
	updateWorkDir string
	// Where the root side keeps the firewall's state (internal/firewall).
	firewallFile   string
	firewallRunDir string
	// The same for SSH keys and settings (internal/sshd).
	sshStateFile string
	sshRunDir    string
	// And for updates for the device (internal/osupdate).
	osUpdatesFile   string
	osUpdatesRunDir string
	devHTTP         bool
	// internalListen is SGC's second listener, for Traefik ("" for none).
	internalListen string
	// gatewayListen is where Traefik hands over connections for the
	// gateway's name, unopened ("" for none).
	gatewayListen string
}

// serve runs the web UI and API until ctx is cancelled, which is how systemd
// asks the service to stop.
func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var opts serveOptions
	flags := flag.NewFlagSet("sgc serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.listen, "listen", ":"+strconv.Itoa(layout.WebPort), "address to listen on")
	flags.StringVar(&opts.stateDir, "state-dir", defaultStateDir(), "folder for the database and certificate")
	flags.StringVar(&opts.helperSocket, "helper-socket", layout.HelperSocket, "socket of the root helper")
	flags.StringVar(&opts.updateWorkDir, "update-work-dir", layout.UpdateWorkDir, "folder where the updater records its outcome")
	flags.StringVar(&opts.firewallFile, "firewall-file", firewall.DefaultPaths().ConfirmedFile, "file in which the root side keeps the confirmed firewall rules")
	flags.StringVar(&opts.firewallRunDir, "firewall-run-dir", firewall.DefaultPaths().RunDir, "folder in which the root side keeps a firewall change that waits for confirmation")
	flags.StringVar(&opts.sshStateFile, "ssh-state-file", sshd.DefaultPaths().StateFile, "file in which the root side keeps the confirmed SSH keys and settings")
	flags.StringVar(&opts.sshRunDir, "ssh-run-dir", sshd.DefaultPaths().RunDir, "folder in which the root side keeps an SSH change that waits for a key login")
	flags.StringVar(&opts.osUpdatesFile, "os-updates-file", osupdate.DefaultPaths().ConfigFile, "SGC's file among apt's settings, written by the root side")
	flags.StringVar(&opts.osUpdatesRunDir, "os-updates-run-dir", osupdate.DefaultPaths().RunDir, "folder in which the root side keeps its report on updates for the device")
	flags.BoolVar(&opts.devHTTP, "dev-insecure-http", false, "development only: plain http, reachable from this machine only")
	flags.StringVar(&opts.internalListen, "internal-listen", proxy.SGCInternal, "address of the listener for the proxy (this machine only; empty for none)")
	flags.StringVar(&opts.gatewayListen, "gateway-listen", proxy.SGCGateway, "address where the proxy hands over connections for the gateway's name (this machine only; empty for none)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	log := slog.New(slog.NewTextHandler(stdout, nil))

	// Everything SGC writes (database, certificate key) is private to its user.
	syscall.Umask(0o077)

	// Normally this loop runs once. Restoring from an export replaces the
	// database, which can only be done while nothing has it open: the web
	// server then winds down, and the next round starts on the restored one.
	for {
		code, again := serveOnce(ctx, opts, log, stdout)
		if !again || ctx.Err() != nil {
			return code
		}
	}
}

// serveOnce opens the database and serves until asked to stop (again is
// false) or to start over on a restored database (again is true).
func serveOnce(ctx context.Context, opts serveOptions, log *slog.Logger, stdout io.Writer) (code int, again bool) {
	fail := func(what string, err error) (int, bool) {
		log.Error(what, "error", err)
		return exitFailed, false
	}

	// A restore confirmed before the last stop is put in place now, while
	// the database is closed.
	restored, err := backup.ApplyStaged(opts.stateDir)
	if err != nil {
		return fail("apply restore", err)
	}

	db, err := store.Open(ctx, filepath.Join(opts.stateDir, layout.DatabaseFile))
	if err != nil {
		return fail("open database", err)
	}
	// Everything running in the background uses the database. When this
	// round ends they are told to stop and waited for before it is closed.
	runCtx, endRun := context.WithCancel(ctx)
	var background sync.WaitGroup
	defer func() {
		endRun()
		background.Wait()
		db.Close()
	}()

	authService, err := auth.NewService(db)
	if err != nil {
		return fail("prepare sign-in", err)
	}
	auditLog := audit.New(db)
	if restored != nil {
		detail := fmt.Sprintf("from an export of %s, made %s by SGC %s",
			restored.Hostname, restored.CreatedAt.Format(time.DateOnly), restored.SGCVersion)
		if err := auditLog.Record(ctx, audit.ActorSystem, audit.ActionRestoreCompleted, detail, ""); err != nil {
			log.Error("record restore", "error", err)
		}
		log.Info("restored from an export", "detail", detail)
	}

	monitor := health.NewMonitor()
	updates, err := newUpdateChecker(db, opts.stateDir, log)
	if err != nil {
		return fail("prepare updates", err)
	}
	// Whatever was downloaded for an earlier update has served its purpose.
	updates.ClearSpool()

	background.Go(func() { monitor.Run(runCtx, 2*time.Second) })
	background.Go(func() { deleteExpiredSessionsHourly(runCtx, authService, log) })
	background.Go(func() { updates.Run(runCtx) })
	// Right after an update this has to wait for the updater to record the
	// outcome, and start-up must not wait with it.
	background.Go(func() { reportUpdateOutcome(runCtx, db, auditLog, opts.updateWorkDir, log) })

	helperClient := helper.NewClient(opts.helperSocket)
	firewallControl := fwcontrol.New(fwcontrol.Config{
		DB:        db,
		Helper:    helperClient,
		Audit:     auditLog,
		Paths:     firewall.Paths{ConfirmedFile: opts.firewallFile, RunDir: opts.firewallRunDir},
		Installed: func() bool { _, err := os.Stat(firewall.NftProgram); return err == nil },
		// What the root side would let in now: the same facts it goes by.
		Expected: func(ctx context.Context) fwcontrol.Expected {
			expected := fwcontrol.Expected{DNS: adguard.Installed(adguard.DefaultPaths())}
			if status, err := helperClient.ProxyStatus(ctx); err == nil && status.On {
				expected.Proxy, expected.ProxyPorts, expected.Door = true, status.ListenPorts, status.Door
			}
			if status, err := helperClient.VPNStatus(ctx); err == nil && status.On {
				expected.VPNPort = status.Port
			}
			return expected
		},
		Uptime: firewall.Uptime,
		Log:    log,
	})
	// Writes down how firewall changes ended that nobody ended by hand.
	background.Go(func() { firewallControl.Run(runCtx) })

	sshControl := sshcontrol.New(sshcontrol.Config{
		DB:     db,
		Helper: helperClient,
		Audit:  auditLog,
		Paths:  sshd.Paths{StateFile: opts.sshStateFile, RunDir: opts.sshRunDir},
		Uptime: sshd.Uptime,
		Now:    time.Now,
		Log:    log,
	})
	// Catches up with SSH changes that the root side confirmed or undid.
	background.Go(func() { sshControl.Run(runCtx) })

	osUpdatePaths := osupdate.DefaultPaths()
	osUpdatePaths.ConfigFile, osUpdatePaths.RunDir = opts.osUpdatesFile, opts.osUpdatesRunDir
	osControl := oscontrol.New(oscontrol.Config{
		DB:     db,
		Helper: helperClient,
		Audit:  auditLog,
		Paths:  osUpdatePaths,
		Uptime: sshd.Uptime,
		Now:    time.Now,
		Log:    log,
	})
	// Looks for Debian's updates once a day, and writes down how
	// installations started in the page ended.
	background.Go(func() { osControl.Run(runCtx) })

	maintenanceWindow := maintenance.New(maintenance.Config{
		DB:            db,
		Updates:       updates,
		Helper:        helperClient,
		Audit:         auditLog,
		RestartNeeded: func() (bool, []string) { return osupdate.RestartNeeded(osUpdatePaths) },
		Installing:    osControl.Installing,
		Uptime:        sshd.Uptime,
		// systemd's time service leaves this file once it has set the clock
		// from the network. /run starts empty, so it means: since start-up.
		ClockSynchronised: func() bool { _, err := os.Stat("/run/systemd/timesync/synchronized"); return err == nil },
		Now:               time.Now,
		Log:               log,
	})
	// Restarts the device, and updates SGC, in the owner's maintenance window.
	background.Go(func() { maintenanceWindow.Run(runCtx) })

	domainControl := newDomainControl(db, auditLog, log)
	// Asks the DNS provider every few hours whether it still accepts the
	// saved key.
	background.Go(func() { domainControl.Run(runCtx) })

	certControl := newCertControl(db, auditLog, log, domainControl)
	// Renews the certificate when it is time, and is what an attempt started
	// from the page runs under.
	background.Go(func() { certControl.Run(runCtx) })

	// The names SGC hands out: the gateway's, the services', and how they
	// reach AdGuard Home and Traefik.
	// Notifications: the bell in the page, and email and ntfy where the
	// owner set them up.
	hostname, _ := os.Hostname()
	notifier := notify.New(notify.Config{DB: db, Audit: auditLog, Hostname: hostname, Log: log})
	alertAs := func(event string) func(context.Context, string, string) {
		return func(ctx context.Context, title, body string) {
			notifier.Notify(ctx, event, notify.Warning, title, body)
		}
	}

	named := newParts(partsDeps{db: db, stateDir: opts.stateDir, helper: helperClient, audit: auditLog, auth: authService, log: log,
		domain: domainControl, cert: certControl, alert: alertAs(notify.EventAnnounce),
		alertInternet: alertAs(notify.EventInternet), alertLogins: alertAs(notify.EventLogins),
		firewallOn: func(ctx context.Context) bool {
			status, err := firewallControl.Status(ctx)
			return err == nil && status.State == fwcontrol.StateOn
		}})
	if restored != nil {
		// Nothing is opened to the internet by itself on a restored device.
		if err := named.public.MarkRestored(ctx); err != nil {
			return fail("note the restore for internet access", err)
		}
	}
	named.run(runCtx, background.Go)

	dnsControl := newDNSControl(db, opts.stateDir, helperClient, auditLog, log)

	// The software SGC stands on, and when it stops getting security fixes.
	endOfLife := eol.New(eol.Config{DB: db, HTTP: &http.Client{Timeout: 20 * time.Second}, TraefikCycle: minorOf(components.Traefik.Version),
		Programs: []eol.Program{
			{Name: "AdGuard Home", Repo: "AdguardTeam/AdGuardHome", Pinned: components.AdGuardHome.Version},
			{Name: "Traefik", Repo: "traefik/traefik", Pinned: components.Traefik.Version},
		},
		Log: log})
	background.Go(func() { endOfLife.Run(runCtx) })

	// Daily backups to another device, encrypted to the backup key.
	scheduled := backups.New(backups.Config{
		DB:    db,
		Audit: auditLog,
		Export: func(ctx context.Context, w io.Writer, publicKey string) (*backup.Manifest, error) {
			if err := dnsControl.SaveForExport(ctx); err != nil {
				return nil, fmt.Errorf("AdGuard Home's settings could not be read: %w", err)
			}
			return backup.ExportToKey(ctx, db, w, publicKey, backup.Source{SGCVersion: sgc.Version(), Hostname: hostname}, filepath.Join(opts.stateDir, "tmp"))
		},
		Hostname: hostname,
		Alert:    alertAs(notify.EventBackup),
		Log:      log,
	})
	background.Go(func() { scheduled.Run(runCtx) })
	if restored != nil {
		// The export's DNS part is put in place below. Until that is done,
		// the page says that it is still to do.
		if err := dnsControl.MarkRestored(ctx); err != nil {
			return fail("note the restore for DNS", err)
		}
	}
	// After a restore, AdGuard Home gets the settings from the export and is
	// on or off as it was. At any other start this finds nothing to do.
	background.Go(func() {
		if err := dnsControl.FinishRestore(runCtx, audit.ActorSystem, ""); err != nil {
			log.Error("put the DNS part of the restored export in place", "error", err)
		}
	})

	conditions := watched{cert: certControl, domain: domainControl, dns: dnsControl, named: named, monitor: monitor,
		updates: updates, os: osControl, eol: endOfLife, backups: scheduled}.conditions()
	background.Go(func() { notifier.Watch(runCtx, conditions) })

	ui, err := fs.Sub(webui.Dist, "dist")
	if err != nil {
		return fail("load web interface", err)
	}

	startOver := make(chan struct{}, 1)
	server := &web.Server{
		Auth:             authService,
		Audit:            auditLog,
		Health:           monitor,
		Helper:           helperClient,
		Updates:          updates,
		LastUpdate:       func() (*updater.Status, error) { return updater.ReadStatus(opts.updateWorkDir) },
		Backups:          exports{db: db, stateDir: opts.stateDir, beforeExport: dnsControl.SaveForExport},
		DNS:              dnsControl,
		Log2ram:          newLogControl(db, helperClient, auditLog, log),
		Domain:           domainControl,
		Certificate:      certControl,
		Names:            named.gateway,
		Services:         named.catalog,
		Icons:            named.icons,
		Guide:            guide.Store{DB: db},
		Proxy:            named.proxy,
		Public:           named.public,
		Announcer:        named.announcer,
		People:           named.people,
		VPN:              named.vpn,
		VPNEndpoint:      named.endpoint,
		Gate:             &web.GateStore{DB: db},
		Notifications:    notifier,
		Journal:          helperClient,
		Alert:            alertAs(notify.EventLogins),
		ScheduledBackups: scheduled,
		EndOfLife:        endOfLife,
		AdguardAddress:   adguard.WebAddress,
		Firewall:         firewallControl,
		SSH:              sshControl,
		OSUpdates:        osControl,
		Maintenance:      maintenanceWindow,
		StartOver: func() {
			select {
			case startOver <- struct{}{}:
			default: // already asked
			}
		},
		Version:         sgc.Version(),
		UI:              ui,
		InsecureCookies: opts.devHTTP,
		Log:             log,
	}
	httpServer := &http.Server{
		Handler: server.Handler(),
		// Needed to tell whether a firewall confirmation proves anything.
		ConnContext: web.ConnContext,
		// Limits that stop a slow or stuck client from holding a connection
		// (and its memory) forever.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Browsers refusing the self-signed certificate produce a handshake
		// error per attempt; that is expected noise, not a warning.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}

	address := opts.listen
	if opts.devHTTP {
		// Without TLS the admin password would cross the network readable.
		// Whatever was asked for, only this machine may connect.
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return fail("read --listen", err)
		}
		address = net.JoinHostPort("127.0.0.1", port)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fail("listen", err)
	}

	var tlsConfig *tls.Config
	if opts.devHTTP {
		log.Warn("development mode: plain http, this machine only", "address", listener.Addr().String())
	} else {
		cert, err := tlscert.LoadOrCreate(filepath.Join(opts.stateDir, "tls"))
		if err != nil {
			listener.Close()
			return fail("prepare certificate", err)
		}
		tlsConfig = &tls.Config{
			// The certificate from Let's Encrypt for a name under the
			// domain (the gateway's), the self-signed one for everything
			// else: by address, and until there is a real one. That way
			// there is always a way in.
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if pair, err := certControl.Serving(hello.Context()); err == nil && pair != nil {
					if _, ok := gateway.UnderDomain(hello.ServerName, pair.Domain); ok {
						return pair.TLS, nil
					}
				}
				return &cert, nil
			},
			MinVersion: tls.VersionTLS12,
		}
		listener = tls.NewListener(listener, tlsConfig)
	}

	// The second listener: what Traefik asks SGC for. It may only ever be
	// on this machine. Without it the page works all the same, so failing
	// to listen is reported, not fatal.
	var internalServer *http.Server
	if opts.internalListen != "" {
		if host, _, err := net.SplitHostPort(opts.internalListen); err != nil || !net.ParseIP(host).IsLoopback() {
			listener.Close()
			return fail("read --internal-listen", fmt.Errorf("%q is not an address on this machine", opts.internalListen))
		}
		if internal, err := net.Listen("tcp", opts.internalListen); err != nil {
			log.Error("listen for the proxy", "address", opts.internalListen, "error", err)
		} else {
			internalServer = &http.Server{
				Handler:           server.InternalHandler(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       120 * time.Second,
				ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
			}
			go internalServer.Serve(internal)
		}
	}

	// The third: connections for the gateway's name, which Traefik passes on
	// unopened (proxy.SGCGateway), so that https://sgc.domain is this page
	// without a port. On this machine only, and nothing is taken without a
	// PROXY protocol header: that is where the visitor's own address comes
	// from, for the lock-out, the history and "inside". The same server as
	// port 8443, so every rule of the page holds here too, the firewall's
	// confirmation included (each visitor's connection is a new one here).
	// Not in development mode, which has no TLS. Failing to listen is
	// reported, not fatal: port 8443 still works.
	if opts.gatewayListen != "" && tlsConfig != nil {
		if host, _, err := net.SplitHostPort(opts.gatewayListen); err != nil || !net.ParseIP(host).IsLoopback() {
			listener.Close()
			return fail("read --gateway-listen", fmt.Errorf("%q is not an address on this machine", opts.gatewayListen))
		}
		if plain, err := net.Listen("tcp", opts.gatewayListen); err != nil {
			log.Error("listen for the gateway's name", "address", opts.gatewayListen, "error", err)
		} else {
			go httpServer.Serve(tls.NewListener(withVisitorAddress(plain), tlsConfig))
		}
	}

	// Wind down cleanly when asked: stop accepting, let running requests finish.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			fmt.Fprintln(stdout, "sgc stopping")
		case <-startOver:
			again = true
			fmt.Fprintln(stdout, "sgc starting over on the restored database")
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if internalServer != nil {
			internalServer.Shutdown(shutdownCtx)
		}
		httpServer.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(stdout, "sgc %s started, listening on %s\n", sgc.Version(), listener.Addr())
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail("serve", err)
	}
	<-stopped
	return exitOK, again
}

// exports connects the web interface to export and restore.
type exports struct {
	db       *sql.DB
	stateDir string
	// beforeExport brings into the database what lives in files and has to
	// travel: AdGuard Home's settings.
	beforeExport func(context.Context) error
}

func (b exports) Export(ctx context.Context, w io.Writer, passphrase string) (*backup.Manifest, error) {
	hostname, _ := os.Hostname()
	source := backup.Source{SGCVersion: sgc.Version(), Hostname: hostname}
	// An export that silently lacked the DNS settings would be worse than none.
	if err := b.beforeExport(ctx); err != nil {
		return nil, fmt.Errorf("AdGuard Home's settings could not be read, so nothing was exported: %w", err)
	}
	return backup.Export(ctx, b.db, w, passphrase, source, filepath.Join(b.stateDir, "tmp"))
}

func (b exports) Stage(ctx context.Context, r io.Reader, passphrase string) (*backup.Manifest, error) {
	return backup.Stage(ctx, r, passphrase, b.stateDir)
}

func (b exports) Confirm(manifest *backup.Manifest) error {
	return backup.Confirm(b.stateDir, manifest)
}

func deleteExpiredSessionsHourly(ctx context.Context, authService *auth.Service, log *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if err := authService.DeleteExpiredSessions(ctx); err != nil && ctx.Err() == nil {
			log.Error("delete expired sessions", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// minorOf is "3.7" for "3.7.16".
func minorOf(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1]
}
