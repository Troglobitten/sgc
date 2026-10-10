package main

import (
	"context"
	"fmt"
	"io"

	"github.com/Troglobitten/sgc"
)

// serve runs SGC as a long-lived service until ctx is cancelled, which is how
// systemd asks it to stop.
//
// There is nothing to serve yet. This exists so the installer can already
// install and supervise a real service, and later milestones only have to add
// behaviour to it.
func serve(ctx context.Context, stdout io.Writer) int {
	fmt.Fprintf(stdout, "sgc %s started\n", sgc.Version())
	<-ctx.Done()
	fmt.Fprintln(stdout, "sgc stopping")
	return exitOK
}
