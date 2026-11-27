package password

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// One-time passwords are the passwords an operator hands over by hand: the first
// admin's, a reset admin's, a user made by POST /users, and the re-issue of
// T-536. One generator and one lifetime table keep them equal, so the two admin
// routes cannot drift apart (spec 10.6, 10.7).
const (
	// oneTimeBytes of entropy encode to exactly 24 base32 characters with no
	// padding (15 bytes = 120 bits = 24 groups of 5 bits).
	oneTimeBytes = 15
	// OneTimeLength is the number of characters NewOneTime returns.
	OneTimeLength = 24

	// UserOneTimeLife is how long a user's one-time password works (D31, 10.6).
	// An admin hands it over by hand, so it is longer than the admin's own.
	UserOneTimeLife = 72 * time.Hour
	// AdminOneTimeLife is how long an admin's one-time password works (10.1).
	AdminOneTimeLife = 24 * time.Hour
)

// ErrNoRandomness is returned when the system source of randomness fails. It
// carries no detail on purpose.
var ErrNoRandomness = errors.New("password: no randomness")

// NewOneTime returns a fresh one-time password: 24 characters of RFC 4648 base32
// (no padding) from crypto/rand, 120 bits. It is held as secret.String from the
// moment it exists, so a stray format verb prints the redaction marker. The
// alphabet has no symbols and no look-alike for a space, which keeps it easy to
// read out over a phone call and to type, and it passes the 14-character minimum
// of the admin password without needing the strength check (it is never typed
// into a form that runs it; the user must replace it before doing anything).
func NewOneTime() (secret.String, error) {
	var b [oneTimeBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return secret.String{}, ErrNoRandomness
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	clear(b[:])
	return secret.New(s), nil
}
