package auth

import (
	"context"
	"errors"
	"testing"
)

// The reset is what the owner does after the admin password got out, so it
// must end everything that password let anyone into: sign-ins on SGC's page
// and the passes the login gate gave the admin for services. People's
// passes are theirs and stay. Checked in the database, not through what the
// function reports.
func TestResetAdminPasswordEndsEverySignInOfTheAdmin(t *testing.T) {
	ctx := context.Background()
	s, c := newTestService(t)
	setUp(t, s)

	session, err := s.Login(ctx, goodUser, goodPassword, addr, "test")
	if err != nil {
		t.Fatal(err)
	}
	now := c.now().Unix()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO person (name, created_at, updated_at) VALUES ('kim', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		hash   string
		person any
		admin  string
	}{
		{"admin-pass", nil, goodUser},
		{"person-pass", 1, ""},
	} {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO gate_pass (token_hash, host, person_id, admin, created_at, expires_at)
			VALUES (?, 'media.domain.tld', ?, ?, ?, ?)`, row.hash, row.person, row.admin, now, now+3600); err != nil {
			t.Fatal(err)
		}
	}

	const newPassword = "a new and different password"
	name, err := s.ResetAdminPassword(ctx, newPassword)
	if err != nil || name != goodUser {
		t.Fatalf("ResetAdminPassword = %q, %v", name, err)
	}

	if still, err := s.Authenticate(ctx, session.Token); err != nil || still != nil {
		t.Errorf("the sign-in from before the reset: %+v, %v; want it gone", still, err)
	}
	var adminPasses, personPasses int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM gate_pass WHERE person_id IS NULL").Scan(&adminPasses)
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM gate_pass WHERE person_id IS NOT NULL").Scan(&personPasses)
	if adminPasses != 0 {
		t.Errorf("%d gate passes of the admin survived the reset", adminPasses)
	}
	if personPasses != 1 {
		t.Errorf("%d passes of people left, want their 1 untouched", personPasses)
	}
	if _, err := s.Login(ctx, goodUser, goodPassword, addr, "test"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the old password: err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.Login(ctx, goodUser, newPassword, addr, "test"); err != nil {
		t.Errorf("the new password: %v", err)
	}
}

func TestResetAdminPasswordWithoutAnAdmin(t *testing.T) {
	s, _ := newTestService(t)
	if _, err := s.ResetAdminPassword(context.Background(), "a new and different password"); err == nil {
		t.Error("a reset without an admin account succeeded")
	}
}
