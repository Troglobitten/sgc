// Command iconpack builds the pack of service icons SGC keeps on the device
// (internal/iconpack) from a checkout of homarr-labs/dashboard-icons, with
// every icon drawn anew by SGC's own code (services.Redraw). Run by
// .github/workflows/icons.yml once a week; never part of a release, never
// run on a device.
//
//	go run ./tools/iconpack --source <checkout> --commit <sha> --out <dir>
//
// It reads the checkout as data only: nothing in it is run.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Troglobitten/sgc/internal/iconpack"
	"github.com/Troglobitten/sgc/internal/services"
)

func main() {
	source := flag.String("source", "", "checkout of homarr-labs/dashboard-icons")
	commit := flag.String("commit", "", "the commit it is at")
	out := flag.String("out", "", "folder for the pack and its manifest")
	flag.Parse()
	if *source == "" || *out == "" || !iconpack.ValidCommit(*commit) {
		fmt.Fprintln(os.Stderr, "usage: iconpack --source <checkout> --commit <40 hex characters> --out <dir>")
		os.Exit(2)
	}
	built, err := iconpack.Build(*source, *commit, *out, time.Now(), services.Redraw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iconpack:", err)
		os.Exit(1)
	}
	m := built.Manifest
	// Fewer than this is a collection that changed its layout, not a pack.
	if m.Count < 1000 {
		fmt.Fprintf(os.Stderr, "iconpack: only %d icons; not published\n", m.Count)
		os.Exit(1)
	}
	fmt.Printf("%s: %d icons (%d skipped), %.1f MB\n", m.File, m.Count, built.Skipped, float64(m.Size)/(1<<20))
}
