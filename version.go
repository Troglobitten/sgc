// Package sgc holds the few things that belong to the repository root.
//
// The VERSION file is the single source of truth for the version number.
// It is embedded here, in the root package, because Go can only embed files
// from a package's own directory or below.
package sgc

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version returns the SGC version, for example "0.1.0".
func Version() string {
	return strings.TrimSpace(versionFile)
}
