package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/updater"
)

func writeUpdateStatus(t *testing.T, workDir string, status updater.Status) {
	t.Helper()
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "status.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateOutcomeIsWrittenToTheAuditLogOnce(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	auditLog := audit.New(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	workDir := t.TempDir()

	actions := func() []string {
		t.Helper()
		entries, err := auditLog.Recent(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range entries {
			out = append(out, e.Action+"|"+e.Actor+"|"+e.Detail)
		}
		return out
	}

	// Never updated: nothing to report.
	reportUpdateOutcome(ctx, db, auditLog, workDir, log)
	if got := actions(); len(got) != 0 {
		t.Fatalf("with no update ever attempted: %v", got)
	}

	// A finished update is reported, and only once however often SGC restarts.
	writeUpdateStatus(t, workDir, updater.Status{ID: 1, State: updater.StateSucceeded, Message: "SGC was updated from 1.0.0 to 1.1.0."})
	reportUpdateOutcome(ctx, db, auditLog, workDir, log)
	reportUpdateOutcome(ctx, db, auditLog, workDir, log)
	if got := actions(); len(got) != 1 || got[0] != "update.succeeded|system|SGC was updated from 1.0.0 to 1.1.0." {
		t.Fatalf("after a successful update: %v", got)
	}

	// A later attempt that was rolled back is a new entry.
	writeUpdateStatus(t, workDir, updater.Status{ID: 2, State: updater.StateRolledBack, Message: "went back"})
	reportUpdateOutcome(ctx, db, auditLog, workDir, log)
	if got := actions(); len(got) != 2 || got[0] != "update.rolled_back|system|went back" {
		t.Fatalf("after a rollback: %v", got)
	}
}

// SGC is started by the updater while the update is still running; the
// outcome only appears a moment later. This is the case that was missed at
// first: looking once at start found "running" and never looked again.
func TestUpdateOutcomeIsWaitedForWhileTheUpdateIsStillRunning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	auditLog := audit.New(db)
	workDir := t.TempDir()

	writeUpdateStatus(t, workDir, updater.Status{ID: 5, State: updater.StateRunning, To: "1.1.0"})
	done := make(chan struct{})
	go func() {
		reportUpdateOutcome(ctx, db, auditLog, workDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("reporting gave up while the update was still running")
	case <-time.After(300 * time.Millisecond):
	}

	writeUpdateStatus(t, workDir, updater.Status{ID: 5, State: updater.StateSucceeded, To: "1.1.0", Message: "done"})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the outcome was never picked up")
	}

	entries, err := auditLog.Recent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != audit.ActionUpdateSucceeded {
		t.Errorf("audit log = %+v, want the one success", entries)
	}
}
