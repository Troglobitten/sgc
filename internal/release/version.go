package release

import (
	"fmt"
	"regexp"
	"strconv"
)

// Version is an SGC version: MAJOR.MINOR.PATCH, nothing else. Pre-release
// labels are deliberately not accepted; SGC only updates to full releases.
type Version struct {
	Major, Minor, Patch int
}

// Digits only, no leading zeros, and short enough that the numbers always
// fit. Being this strict matters: a version string from the network ends up
// in file names and in a systemd unit name.
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

// ParseVersion reads a version such as "0.5.1".
func ParseVersion(s string) (Version, error) {
	m := versionPattern.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("%q is not a version of the form 1.2.3", s)
	}
	var v Version
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	return v, nil
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// NewerThan reports whether v is a later version than other.
func (v Version) NewerThan(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch > other.Patch
}
