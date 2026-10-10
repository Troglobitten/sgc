// Command sgc is the Server Gateway Control program: the web UI, the API,
// the scheduler and the command-line tools in one binary.
//
// At this stage it only knows how to report its version.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/Troglobitten/sgc"
)

// Exit codes. 2 for misuse follows the common Unix convention, so scripts can
// tell "you called me wrongly" apart from "something failed".
const (
	exitOK    = 0
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole program behind main, with its inputs and outputs passed in
// so that tests can call it directly.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "sgc %s (%s/%s)\n", sgc.Version(), runtime.GOOS, runtime.GOARCH)
		return exitOK
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
  version   Print the installed SGC version
  help      Show this help
`)
}
