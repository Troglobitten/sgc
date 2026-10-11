package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/health"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/tlscert"
	"github.com/Troglobitten/sgc/internal/web"
	webui "github.com/Troglobitten/sgc/web"
)

const databaseFile = "sgc.db"

// serve runs the web UI and API until ctx is cancelled, which is how systemd
// asks the service to stop.
func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sgc serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", ":"+strconv.Itoa(web.DefaultPort), "address to listen on")
	stateDir := flags.String("state-dir", defaultStateDir(), "folder for the database and certificate")
	helperSocket := flags.String("helper-socket", helper.SocketPath, "socket of the root helper")
	devHTTP := flags.Bool("dev-insecure-http", false, "development only: plain http, reachable from this machine only")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	log := slog.New(slog.NewTextHandler(stdout, nil))
	fail := func(what string, err error) int {
		log.Error(what, "error", err)
		return exitFailed
	}

	// Everything SGC writes (database, certificate key) is private to its user.
	syscall.Umask(0o077)

	db, err := store.Open(ctx, filepath.Join(*stateDir, databaseFile))
	if err != nil {
		return fail("open database", err)
	}
	defer db.Close()

	authService, err := auth.NewService(db)
	if err != nil {
		return fail("prepare sign-in", err)
	}
	monitor := health.NewMonitor()
	go monitor.Run(ctx, 2*time.Second)
	go deleteExpiredSessionsHourly(ctx, authService, log)

	ui, err := fs.Sub(webui.Dist, "dist")
	if err != nil {
		return fail("load web interface", err)
	}

	server := &web.Server{
		Auth:            authService,
		Audit:           audit.New(db),
		Health:          monitor,
		Helper:          helper.NewClient(*helperSocket),
		Version:         sgc.Version(),
		UI:              ui,
		InsecureCookies: *devHTTP,
		Log:             log,
	}
	httpServer := &http.Server{
		Handler: server.Handler(),
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

	address := *listen
	if *devHTTP {
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

	if *devHTTP {
		log.Warn("development mode: plain http, this machine only", "address", listener.Addr().String())
	} else {
		cert, err := tlscert.LoadOrCreate(filepath.Join(*stateDir, "tls"))
		if err != nil {
			return fail("prepare certificate", err)
		}
		listener = tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
	}

	// Shut down cleanly when asked: stop accepting, let running requests finish.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		fmt.Fprintln(stdout, "sgc stopping")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(stdout, "sgc %s started, listening on %s\n", sgc.Version(), listener.Addr())
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail("serve", err)
	}
	<-stopped
	return exitOK
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
