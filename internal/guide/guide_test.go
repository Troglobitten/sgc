package guide

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Troglobitten/sgc/internal/store"
)

func TestTheGuidesState(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	g := Store{DB: db}

	// A device that was not set up through the guide has none.
	if state, err := g.State(ctx); err != nil || state.Active || len(state.Skipped) != 0 {
		t.Fatalf("before: %+v, %v", state, err)
	}
	if err := g.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if state, _ := g.State(ctx); !state.Active {
		t.Error("the guide did not start")
	}
	if err := g.Save(ctx, State{Active: true, Skipped: []string{"ssh", "ssh", "updates"}}); err != nil {
		t.Fatal(err)
	}
	if state, _ := g.State(ctx); len(state.Skipped) != 2 || state.Skipped[0] != "ssh" || state.Skipped[1] != "updates" {
		t.Errorf("skipped: %v", state.Skipped)
	}
	if err := g.Save(ctx, State{Active: true, Skipped: []string{"../../etc"}}); err == nil {
		t.Error("an unknown step was kept")
	}
	if err := g.Save(ctx, State{Active: false}); err != nil {
		t.Fatal(err)
	}
	if state, _ := g.State(ctx); state.Active {
		t.Error("the guide did not end")
	}
}
