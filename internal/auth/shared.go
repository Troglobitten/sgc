package auth

import (
	"crypto/sha256"
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
