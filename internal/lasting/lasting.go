// Package lasting tells a passing failure from a lasting one, for the looks
// SGC takes every few minutes at something outside the home: the DNS
// provider, the services that tell the home's public address.
//
// One look that does not get through is no news. A home router's DNS that
// fails for a minute at night (seen by the owner on 2026-10-26: "server
// misbehaving", "i/o timeout") woke them with a warning that was gone five
// minutes later. Until a failure has lasted Grace, the page and the
// notifications leave it out; the record at the provider stays as it was,
// which is right unless the home's address changed in the meantime, and
// then the next look that gets through puts it right.
package lasting

import "time"

// Grace is how long looks must keep failing before the owner is told:
// six looks five minutes apart.
const Grace = 30 * time.Minute

// Failure is kept with a check's state, between looks.
type Failure struct {
	// Since is the first look of the run of failures; nil while looks get
	// through.
	Since *time.Time `json:"since,omitempty"`
	// Last is what the last failed look said.
	Last string `json:"last,omitempty"`
}

// Note records a look that did not get through at now, and reports whether
// the failures have lasted long enough to tell the owner.
func (f *Failure) Note(now time.Time, message string) bool {
	if f.Since == nil || now.Before(*f.Since) {
		since := now
		f.Since = &since
	}
	f.Last = message
	return now.Sub(*f.Since) >= Grace
}

// Clear records a look that got through.
func (f *Failure) Clear() {
	f.Since, f.Last = nil, ""
}
