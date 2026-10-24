package people

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/store"
)

func service(t *testing.T) *Service {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(Config{DB: db, Audit: audit.New(db), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminUsername: func(context.Context) (string, error) { return "owner", nil }})
}

// A person changing their password ends their other sign-ins and the passes
// the gate gave them, so that a password that got out stops working; the
// sign-in they changed it from stays. Checked in the database.
func TestAPersonChangesTheirPassword(t *testing.T) {
	ctx := context.Background()
	s := service(t)
	const old, next = "kims-made-up-password", "kims-new-made-up-password"
	kim, err := s.Add(ctx, "owner", "", Input{Name: "Kim", Network: NetworkServices, AllServices: true, LoginEnabled: true, Username: "kim", Password: old})
	if err != nil {
		t.Fatal(err)
	}
	here, err := s.Login(ctx, "kim", old, "192.168.1.30", "phone")
	if err != nil {
		t.Fatal(err)
	}
	there, _ := s.Login(ctx, "kim", old, "192.168.1.31", "laptop")
	now := s.cfg.Now().Unix()
	s.cfg.DB.ExecContext(ctx, `INSERT INTO gate_pass (token_hash, host, person_id, admin, created_at, expires_at) VALUES ('x', 'media.domain.tld', ?, '', ?, ?)`, kim.ID, now, now+3600)

	if err := s.ChangePassword(ctx, kim.ID, "not the password", next, "192.168.1.30", here.Token); err == nil {
		t.Fatal("a change with a wrong current password")
	}
	if err := s.ChangePassword(ctx, kim.ID, old, old, "192.168.1.30", here.Token); err == nil {
		t.Error("the same password again was taken as a change")
	}
	if err := s.ChangePassword(ctx, kim.ID, old, next, "192.168.1.30", here.Token); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(ctx, here.Token); p == nil {
		t.Error("the sign-in the change was made from ended")
	}
	if p, _ := s.Authenticate(ctx, there.Token); p != nil {
		t.Error("another sign-in survived the change")
	}
	var passes int
	s.cfg.DB.QueryRowContext(ctx, "SELECT count(*) FROM gate_pass WHERE person_id = ?", kim.ID).Scan(&passes)
	if passes != 0 {
		t.Errorf("%d passes survived the change", passes)
	}
	if _, err := s.Login(ctx, "kim", next, "192.168.1.32", "tablet"); err != nil {
		t.Errorf("the new password: %v", err)
	}
	if _, err := s.Login(ctx, "kim", old, "192.168.1.33", "tablet"); err == nil {
		t.Error("the old password still works")
	}
}
