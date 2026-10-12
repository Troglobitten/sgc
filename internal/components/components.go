// Package components lists the programs SGC installs that are not its own
// and not Debian's: which version, from where, and what the file must be.
//
// A component is pinned per SGC release. The checksum is compiled into both
// of SGC's programs: the web process checks what it downloaded, and the root
// side checks again before it installs anything, without trusting the web
// process. A newer version of a component arrives with a newer SGC, which
// has been tested with it.
//
// This package only knows and checks; it downloads nothing.
package components

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// File is one downloadable file of a component.
type File struct {
	URL    string
	SHA256 string
	Size   int64
}

// Component is a program in one version, with its file per processor type
// (Go's names: amd64, arm64).
type Component struct {
	Name    string
	Version string
	Files   map[string]File
}

// AdGuardHome is the DNS server with filtering. The checksums are those of
// the project's own checksums.txt for this release.
var AdGuardHome = Component{
	Name:    "adguardhome",
	Version: "0.107.79",
	Files: map[string]File{
		"amd64": {
			URL:    "https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.79/AdGuardHome_linux_amd64.tar.gz",
			SHA256: "c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f",
			Size:   12384479,
		},
		"arm64": {
			URL:    "https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.79/AdGuardHome_linux_arm64.tar.gz",
			SHA256: "3f7893c18e8aaadc456d0452839190561c306ca95175a2254958be80a769c1ae",
			Size:   11332212,
		},
	},
}

var (
	ErrNoFile      = errors.New("this component has no file for this device's processor type")
	ErrWrongFile   = errors.New("the file is not the one SGC expects (size or checksum differ)")
	errNotOrdinary = errors.New("not an ordinary file")
)

// File returns the component's file for a processor type.
func (c Component) File(arch string) (File, error) {
	file, ok := c.Files[arch]
	if !ok {
		return File{}, ErrNoFile
	}
	return file, nil
}

// SpoolName is the name under which the downloaded file is handed from the
// web process to the root side.
func (c Component) SpoolName(arch string) string {
	return c.Name + "-" + c.Version + "-" + arch + ".tar.gz"
}

// Verify checks that the file at path is exactly the pinned one: an ordinary
// file (no link) of the right size and checksum.
func Verify(path string, want File) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errNotOrdinary
	}
	if info.Size() != want.Size {
		return ErrWrongFile
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, io.LimitReader(f, want.Size+1)); err != nil {
		return fmt.Errorf("read the file: %w", err)
	}
	if hex.EncodeToString(sum.Sum(nil)) != want.SHA256 {
		return ErrWrongFile
	}
	return nil
}
