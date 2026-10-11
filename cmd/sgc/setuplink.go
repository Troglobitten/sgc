package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/tlscert"
	"github.com/Troglobitten/sgc/internal/web"
)

const (
	serviceUser    = "sgc"
	setupLinkValid = time.Hour
)

// setupLink prints a fresh one-time link for creating the admin account.
// The installer runs it at the end; `sudo sgc setup-link` gives a new link if
// the first one expired.
func setupLink(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sgc setup-link", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", defaultStateDir(), "folder for the database and certificate")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "sgc: "+format+"\n", a...)
		return exitFailed
	}

	// The database belongs to the service user. Writing to it as root would
	// leave root-owned files behind that the service can no longer open, so
	// root steps down to that user first.
	if os.Geteuid() == 0 {
		if err := becomeUser(serviceUser); err != nil {
			return fail("could not switch to the %s user: %v", serviceUser, err)
		}
	}
	syscall.Umask(0o077)

	db, err := store.Open(ctx, filepath.Join(*stateDir, databaseFile))
	if err != nil {
		return fail("%v\nRun this command with sudo.", err)
	}
	defer db.Close()

	authService, err := auth.NewService(db)
	if err != nil {
		return fail("%v", err)
	}
	address := "https://" + net.JoinHostPort(primaryAddress(), strconv.Itoa(web.DefaultPort))

	token, err := authService.NewSetupToken(ctx, setupLinkValid)
	if errors.Is(err, auth.ErrAlreadySetUp) {
		fmt.Fprintf(stdout, "SGC is already set up. Sign in at:\n\n  %s\n", address)
		return exitOK
	}
	if err != nil {
		return fail("%v", err)
	}

	cert, err := tlscert.LoadOrCreate(filepath.Join(*stateDir, "tls"))
	if err != nil {
		return fail("%v", err)
	}
	if err := audit.New(db).Record(ctx, audit.ActorConsole, audit.ActionSetupLinkCreated, "", ""); err != nil {
		return fail("%v", err)
	}

	// The secret goes after the "#": browsers keep that part to themselves and
	// never send it in a request, so it stays out of server and proxy logs.
	fmt.Fprintf(stdout, `Open this link in a browser on your network to create the admin account:

  %s/setup#%s

Your browser will warn that the connection is not trusted. That is expected
at this stage: SGC has no certificate from Let's Encrypt yet. Before you
continue, check that the certificate fingerprint your browser shows is:

  SHA-256  %s

The link works once and expires in %d minutes. For a new one: sudo sgc setup-link
`, address, token, tlscert.Fingerprint(cert), int(setupLinkValid.Minutes()))
	return exitOK
}

// becomeUser permanently switches this process to the given user.
func becomeUser(name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	// Groups first, then the group, then the user: after the user ID changes
	// the process may no longer change the others.
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	return syscall.Setuid(uid)
}

// primaryAddress returns the address other devices on the network use to
// reach this machine.
func primaryAddress() string {
	// "Connecting" a UDP socket sends nothing; it only makes the kernel pick
	// the local address it would use for the default route. 192.0.2.1 is an
	// address reserved for documentation that never exists.
	if conn, err := net.Dial("udp", "192.0.2.1:9"); err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return addr.IP.String()
		}
	}
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "localhost"
}
