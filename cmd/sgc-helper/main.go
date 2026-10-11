// Command sgc-helper performs the few SGC operations that need root.
//
// It is started by systemd when the web process first connects to its socket
// (sgc-helper.socket), and offers only the fixed list of operations in
// internal/helper. See that package for why this is a separate program.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/helper"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sgc-helper:", err)
		os.Exit(1)
	}
}

func run() error {
	allowUser := flag.String("allow-user", "sgc", "the user whose requests are accepted")
	flag.Parse()

	allowed, err := user.Lookup(*allowUser)
	if err != nil {
		return fmt.Errorf("look up user %q: %w", *allowUser, err)
	}
	uid, err := strconv.ParseUint(allowed.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("user %q has an unusable ID %q", *allowUser, allowed.Uid)
	}

	listener, err := systemdListener()
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler: (&helper.Server{
			AllowedUID: uint32(uid),
			Version:    sgc.Version(),
			Restart:    restartDevice,
		}).Handler(),
		ConnContext:       helper.ConnContext,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("sgc-helper %s started\n", sgc.Version())
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// systemdListener returns the socket systemd opened for this service.
//
// The helper never creates its own socket: systemd creates it with the right
// owner and permissions before any SGC code runs, and hands it over as file
// descriptor 3 (the socket-activation convention).
func systemdListener() (net.Listener, error) {
	const firstPassedFD = 3
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, errors.New("this program is started by systemd through sgc-helper.socket; it cannot be run by hand")
	}
	file := os.NewFile(firstPassedFD, "sgc-helper.socket")
	listener, err := net.FileListener(file)
	file.Close() // FileListener made its own copy
	if err != nil {
		return nil, fmt.Errorf("use the socket passed by systemd: %w", err)
	}
	return listener, nil
}

// restartDevice asks systemd for a clean restart. The command and its
// arguments are fixed; nothing from a request ever reaches them.
func restartDevice() error {
	// --no-block returns as soon as the restart is queued, so the answer
	// still reaches the browser before the machine goes down.
	cmd := exec.Command("/usr/bin/systemctl", "--no-block", "reboot")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
