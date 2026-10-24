// Package guide keeps the state of the guided setup (docs/design.md §11):
// whether it is still going, and which steps the owner skipped. Whether a
// step is done is not kept: the page asks the part itself (is a domain set
// up, is the firewall on), so the guide never says "done" about something
// that is not.
//
// The guide starts when an admin account is made on a fresh device. A device
// restored from an export does not get it (the state is not exported), nor
// does one that was set up before there was a guide.
package guide

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"

	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/store"
)

// Steps are the guide's steps, in their order: the domain before the
// certificate, the certificate before the proxy, and the firewall last, so
// that its rules let in what was switched on before.
var Steps = []string{"domain", "certificate", "name", "proxy", "ssh", "updates", "firewall"}

// Setting is where the state is kept; it is not exported
// (internal/backup/tables.go).
const Setting = "guide.state"

// State is the guide's state.
type State struct {
	Active  bool     `json:"active"`
	Skipped []string `json:"skipped"`
}

// Store keeps the state in the database.
type Store struct{ DB *sql.DB }

// State returns the state; a device without one has no guide.
func (s Store) State(ctx context.Context) (State, error) {
	raw, found, err := store.Setting(ctx, s.DB, Setting)
	if err != nil {
		return State{}, err
	}
	state := State{Skipped: []string{}}
	if found && raw != "" {
		if err := json.Unmarshal([]byte(raw), &state); err != nil {
			return State{Skipped: []string{}}, nil // an unreadable state is no guide
		}
	}
	if state.Skipped == nil {
		state.Skipped = []string{}
	}
	return state, nil
}

// Save keeps a state the page sends, after checking it names known steps.
func (s Store) Save(ctx context.Context, state State) error {
	var skipped []string
	for _, step := range state.Skipped {
		if !slices.Contains(Steps, step) {
			return problem.Newf("%q is not a step of the setup.", step)
		}
		if !slices.Contains(skipped, step) {
			skipped = append(skipped, step)
		}
	}
	if skipped == nil {
		skipped = []string{}
	}
	raw, err := json.Marshal(State{Active: state.Active, Skipped: skipped})
	if err != nil {
		return err
	}
	return store.SetSetting(ctx, s.DB, Setting, string(raw))
}

// Start begins the guide: what the setup of a fresh device does.
func (s Store) Start(ctx context.Context) error {
	return s.Save(ctx, State{Active: true})
}
