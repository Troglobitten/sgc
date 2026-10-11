package audit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Troglobitten/sgc/internal/store"
)

func TestRecentReturnsNewestFirstUpToLimit(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	log := New(db)

	if entries, err := log.Recent(ctx, 10); err != nil || len(entries) != 0 {
		t.Fatalf("empty log: entries=%v err=%v", entries, err)
	}

	for _, action := range []string{ActionSetupCompleted, ActionLogin, ActionLogout} {
		if err := log.Record(ctx, "davy", action, "", "192.168.1.10"); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := log.Recent(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Action != ActionLogout || entries[1].Action != ActionLogin {
		t.Errorf("order = %s, %s; want newest first", entries[0].Action, entries[1].Action)
	}
	if entries[0].Actor != "davy" || entries[0].RemoteAddr != "192.168.1.10" {
		t.Errorf("entry fields not preserved: %+v", entries[0])
	}
}
