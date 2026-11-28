// Package credgen is the one place that decides whether something derived from a
// first-factor check is still worth anything (P1 auth review round 5, rule
// credential-generation; spec 3.7, 5.5, 5.7, 10.2, 16.1).
//
// users and admin_users carry credential_gen, a counter that a trigger moves whenever
// a credential column changes, whoever writes (migrations/postgres/0022). What a
// password check, an OTP check or a TOTP step proved is worth what the credentials
// were when it ran, so an artefact derived from one (the session opened after Argon2,
// an mfa ticket, a rehash write, a device marker, a reauth) carries a Stamp: the
// subject it was derived for and the generation of that subject's row. Under the row
// lock the stamp is compared with the row's own, here, and with nothing else.
//
// Before this package every consumer compared a field list of its own (sameLock,
// sameCredentials, the rehash guard, the reauth hash lookup, the two markers), and
// each list had left out a field, the subject, or the whole check. A consumer that
// compares fields instead of stamps fails internal/lint's credential rule.
package credgen

import (
	"errors"

	"github.com/google/uuid"
)

// ErrStale says the credentials changed after the artefact was derived from them. A
// route maps it to the answer it already gives for a wrong credential or a spent
// ticket, so it tells a caller nothing a wrong password would not.
var ErrStale = errors.New("credgen: the credentials changed since this was derived")

// Stamp names the credentials of one subject at one moment.
type Stamp struct {
	// Tenant is the tenant of a user, and the nil uuid for an admin.
	Tenant uuid.UUID
	// Subject is the id of the user or the admin.
	Subject uuid.UUID
	// Gen is credential_gen of the row. Zero is not a generation (the column starts
	// at 1), so a zero Stamp holds for nothing.
	Gen int64
}

// Zero reports that there is no stamp: nothing was derived, or the value was lost.
func (s Stamp) Zero() bool { return s.Subject == uuid.Nil || s.Gen <= 0 }

// Holds reports whether an artefact stamped s is still good for the subject whose row
// now says current. Both the subject (and its tenant) and the generation must be
// those of the row, and a zero stamp is never good.
func (s Stamp) Holds(current Stamp) bool {
	return !s.Zero() && !current.Zero() && s == current
}

// Check is Holds as an error.
func (s Stamp) Check(current Stamp) error {
	if !s.Holds(current) {
		return ErrStale
	}
	return nil
}
