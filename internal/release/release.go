// Package release decides whether a downloaded SGC release is genuine.
//
// Every release carries SHA256SUMS, a list of checksums of its files, and
// SHA256SUMS.sig, an Ed25519 signature over that list made with the release
// key. A file is accepted only if the list's signature verifies against a
// trusted key AND the file's checksum is in the list under the expected name.
//
// The installer script performs the same two checks with openssl; this is
// the same logic for the built-in updater. Nothing here touches the network
// or the disk, so both the unprivileged downloader and the root installer
// can use it on bytes they hold in memory.
package release

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	ChecksumsFile = "SHA256SUMS"
	SignatureFile = "SHA256SUMS.sig"
)

var (
	ErrBadSignature = errors.New("the checksum list is not signed by the SGC release key")
	ErrNotListed    = errors.New("the signed checksum list does not mention this file")
	ErrBadChecksum  = errors.New("the download does not match its signed checksum")
)

// ArchiveName is the name of the release archive for a version and processor
// type. The version is part of the name, and the name is looked up in the
// signed list, so an older genuinely signed release cannot be passed off as
// a newer one.
func ArchiveName(version, arch string) string {
	return fmt.Sprintf("sgc-%s-linux-%s.tar.gz", version, arch)
}

// ParsePublicKeys reads one or more PEM-encoded Ed25519 public keys.
// More than one is allowed so that a key can be replaced over time: a
// release then ships both the old and the new key.
func ParsePublicKeys(pemData []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("read release key: %w", err)
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("release key is not an Ed25519 key")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("no release key found")
	}
	return keys, nil
}

// VerifyChecksums reports whether signature is a valid signature over the
// checksum list by any of the trusted keys.
func VerifyChecksums(checksums, signature []byte, trusted []ed25519.PublicKey) error {
	for _, key := range trusted {
		if ed25519.Verify(key, checksums, signature) {
			return nil
		}
	}
	return ErrBadSignature
}

// VerifyFile reports whether data is the file listed under name in the
// checksum list. Call it only with a list that passed VerifyChecksums.
func VerifyFile(checksums []byte, name string, data []byte) error {
	want, err := listedChecksum(checksums, name)
	if err != nil {
		return err
	}
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return ErrBadChecksum
	}
	return nil
}

// listedChecksum finds name in a list in the format written by sha256sum:
// "<64 hex digits>  <name>" per line.
func listedChecksum(checksums []byte, name string) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(checksums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// sha256sum marks binary mode with a "*" before the name.
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		sum, err := hex.DecodeString(fields[0])
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("the checksum list has an unreadable entry for %s", name)
		}
		return sum, nil
	}
	return nil, ErrNotListed
}
