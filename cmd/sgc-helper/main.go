// Command sgc-helper performs the few SGC operations that need root.
//
// It has two modes, both started by systemd and never by hand:
//
//   - With no arguments it is the helper service: started when the web
//     process first connects to its socket (sgc-helper.socket), it offers the
//     fixed list of operations in internal/helper. See that package for why
//     this is a separate program.
//
//   - "sgc-helper update <version>" installs an already downloaded release
//     and rolls it back if it does not come up (sgc-update@.service). It runs
//     as its own unit so that it survives SGC itself being stopped and
//     restarted during the update.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/Troglobitten/sgc/internal/layout"
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

const systemctl = "/usr/bin/systemctl"

func main() {
	var err error
	if len(os.Args) >= 2 && os.Args[1] == "update" {
		err = runUpdate(os.Args[2:])
	} else {
		err = runService()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sgc-helper:", err)
		os.Exit(1)
	}
}

func runService() error {
	allowUser := flag.String("allow-user", layout.ServiceUser, "the user whose requests are accepted")
	flag.Parse()

	uid, _, err := lookupUser(*allowUser)
	if err != nil {
		return err
	}
	listener, err := systemdListener()
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler: (&helper.Server{
			AllowedUID:  uint32(uid),
			Version:     sgc.Version(),
			Restart:     restartDevice,
			StartUpdate: startUpdate,
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

func lookupUser(name string) (uid, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("look up user %q: %w", name, err)
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, fmt.Errorf("user %q has an unusable ID %q", name, u.Uid)
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return 0, 0, fmt.Errorf("user %q has an unusable group ID %q", name, u.Gid)
	}
	return uid, gid, nil
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

// runSystemctl runs systemctl with fixed arguments. Nothing from a request
// reaches it except a version number that has been checked to be one.
func runSystemctl(args ...string) error {
	cmd := exec.Command(systemctl, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// restartDevice asks systemd for a clean restart.
func restartDevice() error {
	// --no-block returns as soon as the restart is queued, so the answer
	// still reaches the browser before the machine goes down.
	return runSystemctl("--no-block", "reboot")
}

// startUpdate starts the unit that installs the given version. The caller
// (internal/helper) guarantees that version is a plain version number.
func startUpdate(version string) error {
	// --no-block: the update stops and restarts SGC, so nobody can wait for it here.
	return runSystemctl("--no-block", "start", "sgc-update@"+version+".service")
}
