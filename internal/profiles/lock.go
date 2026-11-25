package profiles

import (
	"errors"
	"unicode/utf8"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The lock password (spec 7.1). It is the profile's own, chosen when the lock is set, so a user who signs in only by
// OTP can use it. 6 to 128 code points counted after the NFKC of AUTH 4.2, with no strength scoring: a parent's lock code
// is often short and the throttle bounds guessing (open question 2).
const (
	LockPasswordShortest = 6
	LockPasswordLongest  = password.MaxLength
)

// LockMessageLimit is how long the message shown on a locked profile may be (PS 4, 2.2 item 8).
const LockMessageLimit = 256

// NormalizeLockPassword applies the bound of spec 7.1 right after decode, on lock and on unlock, before any charge,
// read, hash or verify. A violation is a field at /password with too_short or too_long, spends no throttle scope and
// writes no audit row: no hash ran, and such a value can never be a lock password. The returned secret is the
// normalised text, which is what is hashed and verified.
func NormalizeLockPassword(pw secret.String) (secret.String, *Error) {
	n, err := password.Normalize(pw)
	switch {
	case errors.Is(err, password.ErrTooLong):
		return secret.String{}, invalid(Field{"/password", CodeTooLong})
	case err != nil:
		return secret.String{}, invalid(Field{"/password", CodeInvalid})
	}
	if utf8.RuneCountInString(n.Reveal()) < LockPasswordShortest {
		return secret.String{}, invalid(Field{"/password", CodeTooShort})
	}
	return n, nil
}

// CheckLockMessage is the bound of the message set with a lock.
func CheckLockMessage(m string) *Error {
	if tooLong(m, LockMessageLimit) {
		return invalid(Field{"/message", CodeTooLong})
	}
	return nil
}
