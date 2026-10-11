package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/store"
)

// Real hashing settings would make every test take seconds; correctness of the
// logic does not depend on the cost.
var cheapParams = hashParams{memoryKiB: 64, passes: 1, threads: 1}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestService(t *testing.T) (*Service, *clock) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s, err := newService(db, c.now, cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

const (
	goodUser     = "alex"
	goodPassword = "correct horse battery"
	addr         = "192.168.1.10"
)

func setUp(t *testing.T, s *Service) {
	t.Helper()
	ctx := context.Background()
	token, err := s.NewSetupToken(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteSetup(ctx, token, goodUser, goodPassword, addr); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := hashPassword(goodPassword, cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := verifyPassword(hash, goodPassword); err != nil || !ok {
		t.Errorf("correct password: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyPassword(hash, goodPassword+"x"); ok {
		t.Error("wrong password was accepted")
	}
	other, _ := hashPassword(goodPassword, cheapParams)
	if hash == other {
		t.Error("two hashes of the same password are identical; the salt is not random")
	}
	if _, err := verifyPassword("not-a-hash", goodPassword); err == nil {
		t.Error("a malformed stored hash did not produce an error")
	}
}

func TestSetupLinkWorksExactlyOnce(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)

	if required, _ := s.SetupRequired(ctx); !required {
		t.Fatal("a fresh install should require setup")
	}
	token, err := s.NewSetupToken(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.CompleteSetup(ctx, "wrong-token", goodUser, goodPassword, addr); !errors.Is(err, ErrBadSetupToken) {
		t.Errorf("wrong token: err = %v, want ErrBadSetupToken", err)
	}
	if err := s.CompleteSetup(ctx, token, goodUser, goodPassword, addr); err != nil {
		t.Fatalf("correct token: %v", err)
	}
	if required, _ := s.SetupRequired(ctx); required {
		t.Error("setup still required after it completed")
	}

	// Second use of the same link, and any attempt to mint a new one, must fail.
	if err := s.CompleteSetup(ctx, token, "mallory", goodPassword, addr); !errors.Is(err, ErrAlreadySetUp) {
		t.Errorf("reusing the link: err = %v, want ErrAlreadySetUp", err)
	}
	if _, err := s.NewSetupToken(ctx, time.Hour); !errors.Is(err, ErrAlreadySetUp) {
		t.Errorf("new link after setup: err = %v, want ErrAlreadySetUp", err)
	}
}

func TestSetupLinkExpires(t *testing.T) {
	ctx := context.Background()
	s, c := newTestService(t)
	token, _ := s.NewSetupToken(ctx, time.Hour)

	c.advance(time.Hour + time.Second)

	if err := s.CompleteSetup(ctx, token, goodUser, goodPassword, addr); !errors.Is(err, ErrBadSetupToken) {
		t.Errorf("err = %v, want ErrBadSetupToken", err)
	}
}

func TestNewSetupLinkReplacesTheOldOne(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	first, _ := s.NewSetupToken(ctx, time.Hour)
	second, _ := s.NewSetupToken(ctx, time.Hour)

	if err := s.CompleteSetup(ctx, first, goodUser, goodPassword, addr); !errors.Is(err, ErrBadSetupToken) {
		t.Errorf("old link: err = %v, want ErrBadSetupToken", err)
	}
	if err := s.CompleteSetup(ctx, second, goodUser, goodPassword, addr); err != nil {
		t.Errorf("new link: %v", err)
	}
}

func TestSetupRejectsBadUsernamesAndPasswords(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	token, _ := s.NewSetupToken(ctx, time.Hour)

	cases := []struct {
		name, username, password string
		want                     error
	}{
		{"empty username", "", goodPassword, ErrInvalidUsername},
		{"uppercase username", "Alex", goodPassword, ErrInvalidUsername},
		{"username with space", "da vy", goodPassword, ErrInvalidUsername},
		{"username starting with digit", "1alex", goodPassword, ErrInvalidUsername},
		{"short password", goodUser, "short", ErrWeakPassword},
		{"eleven characters", goodUser, "elevenchars", ErrWeakPassword},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.CompleteSetup(ctx, token, tc.username, tc.password, addr); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// None of those attempts may have used up the link.
	if err := s.CompleteSetup(ctx, token, goodUser, goodPassword, addr); err != nil {
		t.Errorf("valid setup after rejected ones: %v", err)
	}
}

func TestLoginAndSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	s, c := newTestService(t)
	setUp(t, s)

	if _, err := s.Login(ctx, goodUser, "wrong password!!", addr, "test"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v", err)
	}
	if _, err := s.Login(ctx, "nobody", goodPassword, addr, "test"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong username: err = %v", err)
	}

	session, err := s.Login(ctx, goodUser, goodPassword, addr, "test")
	if err != nil {
		t.Fatalf("correct login: %v", err)
	}
	if got, _ := s.Authenticate(ctx, session.Token); got == nil || got.Username != goodUser {
		t.Fatalf("fresh session not accepted: %+v", got)
	}
	if got, _ := s.Authenticate(ctx, "made-up-token"); got != nil {
		t.Error("a made-up token was accepted")
	}
	if got, _ := s.Authenticate(ctx, ""); got != nil {
		t.Error("an empty token was accepted")
	}

	// Regular use keeps the session alive past the idle limit...
	for i := 0; i < 3; i++ {
		c.advance(sessionIdle - time.Hour)
		if got, _ := s.Authenticate(ctx, session.Token); got == nil {
			t.Fatalf("session ended despite regular use (round %d)", i)
		}
	}
	// ...but leaving it idle ends it.
	c.advance(sessionIdle + time.Minute)
	if got, _ := s.Authenticate(ctx, session.Token); got != nil {
		t.Error("session survived being idle for longer than the limit")
	}
}

func TestSessionEndsAtAbsoluteLimitEvenWhenUsed(t *testing.T) {
	ctx := context.Background()
	s, c := newTestService(t)
	setUp(t, s)
	session, _ := s.Login(ctx, goodUser, goodPassword, addr, "test")

	deadline := c.now().Add(sessionMax)
	for c.now().Before(deadline.Add(-time.Hour)) {
		c.advance(time.Hour)
		if got, _ := s.Authenticate(ctx, session.Token); got == nil {
			t.Fatalf("session ended early, %v before its limit", deadline.Sub(c.now()))
		}
	}
	c.advance(2 * time.Hour)
	if got, _ := s.Authenticate(ctx, session.Token); got != nil {
		t.Error("session outlived its absolute limit")
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	setUp(t, s)
	session, _ := s.Login(ctx, goodUser, goodPassword, addr, "test")

	if err := s.Logout(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Authenticate(ctx, session.Token); got != nil {
		t.Error("session still valid after logout")
	}
}

func TestRepeatedWrongPasswordsLockTheAddressOut(t *testing.T) {
	ctx := context.Background()
	s, c := newTestService(t)
	setUp(t, s)

	for i := 0; i < maxFailures; i++ {
		if _, err := s.Login(ctx, goodUser, "wrong password!!", addr, "test"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: err = %v", i+1, err)
		}
	}

	// Locked out: even the correct password is refused now.
	var locked *TooManyAttemptsError
	if _, err := s.Login(ctx, goodUser, goodPassword, addr, "test"); !errors.As(err, &locked) {
		t.Fatalf("after %d failures: err = %v, want TooManyAttemptsError", maxFailures, err)
	}
	// Another address is unaffected.
	if _, err := s.Login(ctx, goodUser, goodPassword, "192.168.1.99", "test"); err != nil {
		t.Errorf("other address was locked out too: %v", err)
	}
	// And the lockout ends by itself.
	c.advance(lockout + time.Second)
	if _, err := s.Login(ctx, goodUser, goodPassword, addr, "test"); err != nil {
		t.Errorf("after the lockout period: %v", err)
	}
}

func TestCheckSetupTokenDoesNotUseTheLinkUp(t *testing.T) {
	ctx := context.Background()
	s, c := newTestService(t)
	token, _ := s.NewSetupToken(ctx, time.Hour)

	if err := s.CheckSetupToken(ctx, "wrong", addr); !errors.Is(err, ErrBadSetupToken) {
		t.Errorf("wrong token: err = %v", err)
	}
	// Checking twice, then using it: all three must work.
	for i := 0; i < 2; i++ {
		if err := s.CheckSetupToken(ctx, token, addr); err != nil {
			t.Fatalf("check %d: %v", i+1, err)
		}
	}
	if err := s.CompleteSetup(ctx, token, goodUser, goodPassword, addr); err != nil {
		t.Fatalf("the link was used up by checking it: %v", err)
	}
	if err := s.CheckSetupToken(ctx, token, addr); !errors.Is(err, ErrAlreadySetUp) {
		t.Errorf("after setup: err = %v, want ErrAlreadySetUp", err)
	}

	// An expired link fails the check too.
	s2, c2 := newTestService(t)
	expiring, _ := s2.NewSetupToken(ctx, time.Hour)
	c2.advance(2 * time.Hour)
	if err := s2.CheckSetupToken(ctx, expiring, addr); !errors.Is(err, ErrBadSetupToken) {
		t.Errorf("expired link: err = %v", err)
	}
	_ = c
}

func TestVerifyAdminPassword(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	setUp(t, s)

	if err := s.VerifyAdminPassword(ctx, goodPassword, addr); err != nil {
		t.Errorf("correct password: %v", err)
	}
	if err := s.VerifyAdminPassword(ctx, "not the password", addr); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: err = %v", err)
	}

	// Guessing here is limited exactly like guessing at the sign-in form.
	for i := 0; i < maxFailures; i++ {
		s.VerifyAdminPassword(ctx, "not the password", addr)
	}
	var locked *TooManyAttemptsError
	if err := s.VerifyAdminPassword(ctx, goodPassword, addr); !errors.As(err, &locked) {
		t.Errorf("after repeated wrong passwords: err = %v, want a lock-out", err)
	}

	if name, err := s.AdminUsername(ctx); err != nil || name != goodUser {
		t.Errorf("AdminUsername = %q, %v", name, err)
	}
}

func TestOverlongPasswordIsRejectedWithoutHashing(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	setUp(t, s)

	huge := make([]byte, maxPasswordLength+1)
	for i := range huge {
		huge[i] = 'a'
	}
	if _, err := s.Login(ctx, goodUser, string(huge), addr, "test"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}
