package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// What the admin's sign-in uses, for the other places that check a secret:
// people's sign-in at the login gate (internal/people) and servers'
// announcements (internal/announce). The same rules everywhere, so there is
// one place to get them right.

// Limiter counts failed attempts per address with the sign-in's rules: five
// within five minutes lock that address out for five minutes.
type Limiter struct {
	l   *limiter
	now func() time.Time
}

func NewLimiter() *Limiter { return &Limiter{l: newLimiter(), now: time.Now} }

// RetryAfter is how long the address must wait, 0 if it may try now.
func (l *Limiter) RetryAfter(addr string) time.Duration { return l.l.retryAfter(addr, l.now()) }

func (l *Limiter) Fail(addr string) { l.l.fail(addr, l.now()) }

func (l *Limiter) Succeed(addr string) { l.l.succeed(addr) }

// HashPassword hashes a password as the admin's is hashed (Argon2id).
func HashPassword(password string) (string, error) { return hashPassword(password, defaultParams) }

// VerifyPassword reports whether password matches a hash from HashPassword.
func VerifyPassword(encoded, password string) (bool, error) { return verifyPassword(encoded, password) }

// NewToken returns a random token and the hash to store for it.
func NewToken() (token string, hash []byte, err error) { return newToken() }

// HashToken is the stored form of a token.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// DecoyHash is a password hash nothing matches, to verify against when a
// name is unknown, so that an unknown name takes as long as a wrong password.
// It is made the first time it is needed: hashing takes a moment.
var DecoyHash = sync.OnceValue(func() string {
	h, _ := hashPassword("decoy-password-never-matches", defaultParams)
	return h
})

// ResetAdminPassword gives the admin a new password and ends every
// sign-in: what `sudo sgc reset-admin` does. It returns the admin's name.
//
// "Every sign-in" includes the passes the login gate gave the admin for
// services: the reset is what the owner does after a password got out, and
// a pass left behind would keep whoever has it in for up to 12 hours.
// People's passes are theirs and stay.
func (s *Service) ResetAdminPassword(ctx context.Context, password string) (string, error) {
	if err := validateCredentials("admin", password); err != nil {
		return "", err
	}
	var username string
	if err := s.db.QueryRowContext(ctx, "SELECT username FROM admin WHERE id = 1").Scan(&username); err != nil {
		return "", errors.New("there is no admin account yet: open the setup link instead (sudo sgc setup-link)")
	}
	hash, err := hashPassword(password, s.params)
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE admin SET password_hash = ? WHERE id = 1", hash); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM session"); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM gate_pass WHERE person_id IS NULL"); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return username, nil
}
