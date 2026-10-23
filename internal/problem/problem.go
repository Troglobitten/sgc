// Package problem is how SGC's parts say "no" to the owner: an error whose
// message is meant for the page as it is, in words, as opposed to an error
// that means something broke (which the page shows as "something went wrong"
// and the log keeps in full).
package problem

import (
	"errors"
	"fmt"
)

// Error is a refusal or a failure the owner can do something about.
type Error struct {
	Message string
}

func (e *Error) Error() string { return e.Message }

// New returns a refusal with this message.
func New(message string) error { return &Error{Message: message} }

// Newf is New with formatting.
func Newf(format string, args ...any) error { return &Error{Message: fmt.Sprintf(format, args...)} }

// Message returns the words for the owner if err is (or wraps) such a
// refusal.
func Message(err error) (string, bool) {
	var p *Error
	if errors.As(err, &p) {
		return p.Message, true
	}
	return "", false
}
