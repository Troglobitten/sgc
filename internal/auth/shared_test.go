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

func TestChangeAdminPassword(t *testing.T) {
	ctx := context.Background()
	s, c := newTestService(t)
	setUp(t, s)
	here, _ := s.Login(ctx, goodUser, goodPassword, addr, "this browser")
	there, _ := s.Login(ctx, goodUser, goodPassword, "192.168.1.11", "another browser")
	now := c.now().Unix()
	s.db.ExecContext(ctx, `INSERT INTO person (name, created_at, updated_at) VALUES ('kim', ?, ?)`, now, now)
	s.db.ExecContext(ctx, `INSERT INTO gate_pass (token_hash, host, person_id, admin, created_at, expires_at) VALUES ('a', 'media.domain.tld', NULL, ?, ?, ?)`, goodUser, now, now+3600)
	s.db.ExecContext(ctx, `INSERT INTO gate_pass (token_hash, host, person_id, admin, created_at, expires_at) VALUES ('p', 'media.domain.tld', 1, '', ?, ?)`, now, now+3600)

	const next = "a new and different password"
	for _, refused := range []struct {
		current, next string
		want          error
	}{
		{"not the password", next, ErrWrongPassword},
		{goodPassword, "short", ErrWeakPassword},
		{goodPassword, goodPassword, ErrSamePassword},
	} {
		if err := s.ChangeAdminPassword(ctx, refused.current, refused.next, addr, here.Token); !errors.Is(err, refused.want) {
			t.Errorf("ChangeAdminPassword(%q, %q) = %v, want %v", refused.current, refused.next, err, refused.want)
		}
	}
	if err := s.ChangeAdminPassword(ctx, goodPassword, next, addr, here.Token); err != nil {
		t.Fatal(err)
	}
	if still, _ := s.Authenticate(ctx, here.Token); still == nil {
		t.Error("the sign-in the change was made from ended")
	}
	if still, _ := s.Authenticate(ctx, there.Token); still != nil {
		t.Error("another sign-in survived the change")
	}
	var adminPasses, personPasses int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM gate_pass WHERE person_id IS NULL").Scan(&adminPasses)
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM gate_pass WHERE person_id IS NOT NULL").Scan(&personPasses)
	if adminPasses != 0 || personPasses != 1 {
		t.Errorf("passes left: the admin's %d (want 0), people's %d (want 1)", adminPasses, personPasses)
	}
	if _, err := s.Login(ctx, goodUser, next, addr, "test"); err != nil {
		t.Errorf("the new password: %v", err)
	}
	// Guessing the current password is limited like signing in.
	for range maxFailures {
		s.ChangeAdminPassword(ctx, "a wrong guess", "another new password!", "192.168.1.66", here.Token)
	}
	var locked *TooManyAttemptsError
	if err := s.ChangeAdminPassword(ctx, next, "another new password!", "192.168.1.66", here.Token); !errors.As(err, &locked) {
		t.Errorf("after repeated wrong guesses: %v, want a lock-out", err)
	}
}

func TestResetAdminPasswordWithoutAnAdmin(t *testing.T) {
	s, _ := newTestService(t)
	if _, err := s.ResetAdminPassword(context.Background(), "a new and different password"); err == nil {
		t.Error("a reset without an admin account succeeded")
	}
}
