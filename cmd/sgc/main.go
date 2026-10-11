// Command sgc is the Server Gateway Control program: the web UI, the API and
// the command-line tools in one binary.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Troglobitten/sgc"
)

// Exit codes. 2 for misuse follows the common Unix convention, so scripts can
// tell "you called me wrongly" apart from "something failed".
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

func main() {
	// systemd stops a service with SIGTERM; Ctrl+C sends an interrupt.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole program behind main, with its inputs and outputs passed in
// so that tests can call it directly.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "sgc %s (%s/%s)\n", sgc.Version(), runtime.GOOS, runtime.GOARCH)
		return exitOK
	case "serve":
		return serve(ctx, args[1:], stdout, stderr)
	case "setup-link":
		return setupLink(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "sgc: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return exitUsage
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: sgc <command>

Commands:
  serve        Run SGC as a service (started by systemd)
  setup-link   Print a new one-time link for creating the admin account
  version      Print the installed SGC version
  help         Show this help
`)
}

// defaultStateDir is where SGC keeps its database and certificate. systemd
// passes the folder it prepared for the service in STATE_DIRECTORY.
func defaultStateDir() string {
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return dir
	}
	return "/var/lib/sgc"
}
