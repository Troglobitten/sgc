package sgc

import (
	"regexp"
	"testing"
)

// The self-updater compares release tags against this value, so a malformed
// VERSION file must fail the build checks rather than ship.
func TestVersionIsSemanticVersion(t *testing.T) {
	semver := regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)
	if got := Version(); !semver.MatchString(got) {
		t.Fatalf("VERSION file contains %q, want MAJOR.MINOR.PATCH", got)
	}
}
