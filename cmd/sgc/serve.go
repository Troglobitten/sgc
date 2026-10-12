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
	"sync"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/backup"
	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/fwcontrol"
	"github.com/Troglobitten/sgc/internal/health"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/oscontrol"
	"github.com/Troglobitten/sgc/internal/osupdate"
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
		Uptime:    firewall.Uptime,
		Log:       log,
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

	ui, err := fs.Sub(webui.Dist, "dist")
	if err != nil {
		return fail("load web interface", err)
	}

	startOver := make(chan struct{}, 1)
	server := &web.Server{
		Auth:       authService,
		Audit:      auditLog,
		Health:     monitor,
		Helper:     helperClient,
		Updates:    updates,
		LastUpdate: func() (*updater.Status, error) { return updater.ReadStatus(opts.updateWorkDir) },
		Backups:    backups{db: db, stateDir: opts.stateDir},
		Firewall:   firewallControl,
		SSH:        sshControl,
		OSUpdates:  osControl,
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

	if opts.devHTTP {
		log.Warn("development mode: plain http, this machine only", "address", listener.Addr().String())
	} else {
		cert, err := tlscert.LoadOrCreate(filepath.Join(opts.stateDir, "tls"))
		if err != nil {
			listener.Close()
			return fail("prepare certificate", err)
		}
		listener = tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
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
		httpServer.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(stdout, "sgc %s started, listening on %s\n", sgc.Version(), listener.Addr())
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail("serve", err)
	}
	<-stopped
	return exitOK, again
}

// backups connects the web interface to export and restore.
type backups struct {
	db       *sql.DB
	stateDir string
}

func (b backups) Export(ctx context.Context, w io.Writer, passphrase string) (*backup.Manifest, error) {
	hostname, _ := os.Hostname()
	source := backup.Source{SGCVersion: sgc.Version(), Hostname: hostname}
	return backup.Export(ctx, b.db, w, passphrase, source, filepath.Join(b.stateDir, "tmp"))
}

func (b backups) Stage(ctx context.Context, r io.Reader, passphrase string) (*backup.Manifest, error) {
	return backup.Stage(ctx, r, passphrase, b.stateDir)
}

func (b backups) Confirm(manifest *backup.Manifest) error {
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
