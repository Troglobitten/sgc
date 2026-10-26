package auth

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// Two guards for sign-ins that face the internet (SGC's login on a public
// service, docs/design.md §14), used by every sign-in all the same.

// ErrBusy: too many passwords are being checked at this moment.
var ErrBusy = errors.New("SGC is checking many sign-ins at once; try again in a moment")

// passwordChecks is how many passwords are hashed at once. Each check takes
// 64 MiB of memory on purpose (defaultParams), so a flood of sign-ins could
// otherwise take all of a Raspberry Pi's memory. Two at once keep a sign-in
// quick and the device standing; the rest wait their turn, up to checkWait.
var passwordChecks = make(chan struct{}, 2)

const checkWait = 10 * time.Second

func acquireCheck() bool {
	select {
	case passwordChecks <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(checkWait)
	defer timer.Stop()
	select {
	case passwordChecks <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

func releaseCheck() { <-passwordChecks }

// AccountThrottle slows down guessing one account's password from many
// addresses, which the limit per address (Limiter) does not catch: after
// accountFree wrong passwords for a name within accountWindow, each further
// attempt for it must wait: accountFirstWait after the last wrong one, twice
// as long after each further one, up to accountMaxWait. It slows rather
// than locks: someone who knows a username can make its owner wait a few
// minutes, not lock them out for good. Names
// are kept whether or not they exist, so the answer does not tell which do.
type AccountThrottle struct {
	mu   sync.Mutex
	seen map[string]*accountAttempts
	now  func() time.Time
}

type accountAttempts struct {
	failures int
	last     time.Time
}

const (
	accountFree      = 5
	accountWindow    = 15 * time.Minute
	accountFirstWait = 30 * time.Second
	accountMaxWait   = 5 * time.Minute
	maxAccounts      = 10000
)

func NewAccountThrottle() *AccountThrottle {
	return &AccountThrottle{seen: map[string]*accountAttempts{}, now: time.Now}
}

func accountKey(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// RetryAfter is how long the next attempt for this name must wait, 0 if it
// may go ahead.
func (t *AccountThrottle) RetryAfter(name string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.seen[accountKey(name)]
	now := t.now()
	if !ok || a.failures < accountFree || now.Sub(a.last) > accountWindow {
		return 0
	}
	wait := accountMaxWait
	if shift := a.failures - accountFree; shift < 4 {
		wait = min(accountFirstWait<<shift, accountMaxWait)
	}
	return max(a.last.Add(wait).Sub(now), 0)
}

// Fail counts a wrong password for the name. It reports whether this is the
// failure that starts the slowing down, which is worth telling the owner.
func (t *AccountThrottle) Fail(name string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	key := accountKey(name)
	a, ok := t.seen[key]
	if !ok {
		if len(t.seen) >= maxAccounts {
			for k, old := range t.seen {
				if now.Sub(old.last) > accountWindow {
					delete(t.seen, k)
				}
			}
			if len(t.seen) >= maxAccounts {
				// Full of names tried within the window: start over rather
				// than grow without bound.
				t.seen = map[string]*accountAttempts{}
			}
		}
		a = &accountAttempts{}
		t.seen[key] = a
	}
	if now.Sub(a.last) > accountWindow {
		a.failures = 0
	}
	a.failures++
	a.last = now
	return a.failures == accountFree
}

// Succeed forgets the name's failures.
func (t *AccountThrottle) Succeed(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.seen, accountKey(name))
}
