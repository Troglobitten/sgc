package auth

import (
	"sync"
	"time"
)

// Guessing limits: after maxFailures wrong attempts from one address within
// failureWindow, that address is refused for lockout. A correct password
// cannot be tried during the lockout either, so guessing is capped at
// maxFailures per lockout period no matter what.
const (
	maxFailures   = 5
	failureWindow = 5 * time.Minute
	lockout       = 5 * time.Minute

	// Upper bound on remembered addresses, so a flood of made-up source
	// addresses cannot grow the table without limit.
	maxTrackedAddresses = 10000
)

type attempts struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

type limiter struct {
	mu   sync.Mutex
	seen map[string]*attempts
}

func newLimiter() *limiter {
	return &limiter{seen: make(map[string]*attempts)}
}

// retryAfter returns how long addr must still wait, or zero if it may try.
func (l *limiter) retryAfter(addr string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.seen[addr]
	if !ok || !now.Before(a.lockedUntil) {
		return 0
	}
	return a.lockedUntil.Sub(now)
}

// fail records a wrong attempt from addr.
func (l *limiter) fail(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.seen[addr]
	if !ok {
		if len(l.seen) >= maxTrackedAddresses {
			l.forgetExpired(now)
		}
		a = &attempts{windowStart: now}
		l.seen[addr] = a
	}
	if now.Sub(a.windowStart) > failureWindow {
		a.failures = 0
		a.windowStart = now
	}
	a.failures++
	if a.failures >= maxFailures {
		a.lockedUntil = now.Add(lockout)
		a.failures = 0
		a.windowStart = now
	}
}

// succeed clears addr's record after a correct attempt.
func (l *limiter) succeed(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.seen, addr)
}

// forgetExpired drops records that no longer affect any decision.
// The caller holds the lock.
func (l *limiter) forgetExpired(now time.Time) {
	for addr, a := range l.seen {
		if now.After(a.lockedUntil) && now.Sub(a.windowStart) > failureWindow {
			delete(l.seen, addr)
		}
	}
}
