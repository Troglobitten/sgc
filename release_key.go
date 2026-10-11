package sgc

import _ "embed"

// The public half of the release signing key, built into every SGC binary.
// An installed SGC only accepts updates signed with the matching private key.
//
// It is the same file the installer is built from (installer/release-key.pem),
// embedded here because Go can only embed files from this package's own
// directory or below.
//
//go:embed installer/release-key.pem
var releasePublicKeyPEM []byte

// ReleasePublicKeyPEM returns the trusted release key in PEM form.
func ReleasePublicKeyPEM() []byte {
	return releasePublicKeyPEM
}
