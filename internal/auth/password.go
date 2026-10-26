package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id settings. 64 MiB and 3 passes is the "second recommended" setting
// of RFC 9106, chosen because the gateway may be a Raspberry Pi with limited
// memory. The values are stored inside each hash, so they can be raised later
// without invalidating existing passwords.
type hashParams struct {
	memoryKiB uint32
	passes    uint32
	threads   uint8
}

var defaultParams = hashParams{memoryKiB: 64 * 1024, passes: 3, threads: 2}

const (
	saltLength = 16
	keyLength  = 32
)

// hashPassword returns the password hashed in the standard encoded form:
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func hashPassword(password string, p hashParams) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	if !acquireCheck() {
		return "", ErrBusy
	}
	key := argon2.IDKey([]byte(password), salt, p.passes, p.memoryKiB, p.threads, keyLength)
	releaseCheck()
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memoryKiB, p.passes, p.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword reports whether password matches the encoded hash.
func verifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("stored password hash is not in a known format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("stored password hash uses an unknown argon2 version")
	}
	var p hashParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memoryKiB, &p.passes, &p.threads); err != nil {
		return false, errors.New("stored password hash has unreadable settings")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("stored password hash has an unreadable salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("stored password hash is unreadable")
	}

	if !acquireCheck() {
		return false, ErrBusy
	}
	got := argon2.IDKey([]byte(password), salt, p.passes, p.memoryKiB, p.threads, uint32(len(want)))
	releaseCheck()
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
