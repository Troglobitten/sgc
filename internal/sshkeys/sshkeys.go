// Package sshkeys reads an SSH public key the way a person pastes it, and
// refuses everything that is not exactly one plain public key.
//
// A key accepted here ends up in a file the SSH server trusts for logins, so
// the rules are strict and the same on both sides: the web process applies
// them to give the owner a useful message, and the root side applies them
// again before writing anything, because it does not trust the web process.
//
// The key is never copied through as text. It is parsed, and what is written
// out is built from the parsed key, so nothing that was pasted along with it
// (login options, a second line, a comment) can ride along.
package sshkeys

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// maxLength bounds what is parsed. The largest accepted key, a long RSA
// one, is well under a kilobyte.
const maxLength = 8 * 1024

// minRSABits is the shortest RSA key accepted. Shorter ones can be broken
// with enough effort and no current tool creates them any more.
const minRSABits = 2048

// The kinds of key accepted, with the name the SSH server uses for each in
// its log ("Accepted publickey for alex ... ED25519 SHA256:...").
var kinds = map[string]string{
	ssh.KeyAlgoED25519:    "ED25519",
	ssh.KeyAlgoECDSA256:   "ECDSA",
	ssh.KeyAlgoECDSA384:   "ECDSA",
	ssh.KeyAlgoECDSA521:   "ECDSA",
	ssh.KeyAlgoRSA:        "RSA",
	ssh.KeyAlgoSKED25519:  "ED25519-SK", // a key kept on a hardware token
	ssh.KeyAlgoSKECDSA256: "ECDSA-SK",
}

var (
	// ErrPrivateKey is worth its own message: the owner has just pasted the
	// one thing that must never be pasted anywhere.
	ErrPrivateKey = errors.New("this is a private key, which must never leave your computer. Paste the public key instead: the file that ends in .pub")
	ErrNotAKey    = errors.New("this is not an SSH public key. A public key is one long line that starts with ssh-ed25519, ssh-rsa or ecdsa-sha2")
)

// Key is one SSH public key.
type Key struct {
	// Type is the key's kind as SSH writes it, for example "ssh-ed25519".
	Type string `json:"type"`
	// Blob is the key itself, in the base64 form of an authorized_keys line.
	Blob string `json:"blob"`
	// Fingerprint is the short form the SSH server logs: "SHA256:...".
	Fingerprint string `json:"fingerprint"`
}

// Parse reads one pasted public key. The second result is the comment that
// followed the key (often "name@computer"), offered as a label; it is not
// part of the key.
func Parse(text string) (Key, string, error) {
	text = strings.TrimSpace(text)
	switch {
	case text == "":
		return Key{}, "", ErrNotAKey
	case strings.Contains(text, "PRIVATE KEY"):
		return Key{}, "", ErrPrivateKey
	case len(text) > maxLength:
		return Key{}, "", ErrNotAKey
	case strings.ContainsAny(text, "\r\n"):
		return Key{}, "", errors.New("this is more than one line. Paste one public key: a single long line")
	}

	public, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return Key{}, "", ErrNotAKey
	}
	// Options ("command=...", "from=...") change what a key may do. A key
	// with options is refused rather than stripped, so that nobody believes
	// a restriction is in place that is not.
	if len(options) > 0 || len(rest) > 0 || !strings.HasPrefix(text, public.Type()+" ") {
		return Key{}, "", errors.New("paste the public key alone, without options in front of it")
	}
	if _, ok := kinds[public.Type()]; !ok {
		return Key{}, "", fmt.Errorf("keys of the kind %s are not accepted. Use an Ed25519 key (ssh-keygen -t ed25519)", public.Type())
	}
	if public.Type() == ssh.KeyAlgoRSA {
		crypto, ok := public.(ssh.CryptoPublicKey)
		if !ok {
			return Key{}, "", ErrNotAKey
		}
		key, ok := crypto.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return Key{}, "", ErrNotAKey
		}
		if key.N.BitLen() < minRSABits {
			return Key{}, "", fmt.Errorf("this RSA key has %d bits, which is too short to be safe. Make a new key (ssh-keygen -t ed25519)", key.N.BitLen())
		}
	}
	return Key{
		Type:        public.Type(),
		Blob:        base64.StdEncoding.EncodeToString(public.Marshal()),
		Fingerprint: ssh.FingerprintSHA256(public),
	}, strings.TrimSpace(comment), nil
}

// Check parses a key that is already in parts, as it arrives from the
// database or from the web process, and returns it in checked form. The
// fingerprint is always recomputed, never believed.
func Check(key Key) (Key, error) {
	checked, _, err := Parse(key.Type + " " + key.Blob)
	if err != nil {
		return Key{}, err
	}
	if checked.Type != key.Type || checked.Blob != key.Blob {
		return Key{}, ErrNotAKey
	}
	return checked, nil
}

// Line is the key as one line of an authorized keys file: the kind and the
// key, nothing else.
func (k Key) Line() string { return k.Type + " " + k.Blob }

// Kind is the name the SSH server's log uses for this key's type.
func (k Key) Kind() string { return kinds[k.Type] }
