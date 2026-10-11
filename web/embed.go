// Package web carries the built browser interface inside the SGC binary.
//
// The interface is built from the sources in this folder (`make web`) into
// dist/, and embedded from there, so an installation is a single file with
// nothing to unpack or serve from disk.
package web

import "embed"

// Dist holds the built interface under "dist/". Before the interface has been
// built it contains only a placeholder, and SGC answers that the web
// interface is not included.
//
//go:embed all:dist
var Dist embed.FS
