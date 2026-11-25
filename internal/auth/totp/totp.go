// Package totp is RFC 6238 for authenticator apps, and Check, the only way a
// handler verifies a code (spec 6.1 to 6.3).
//
// It is about forty lines of crypto instead of a library because replay
// rejection needs the matched step number, and the libraries seen return only a
// yes or no. The parameters are the ones every authenticator app supports:
// HMAC-SHA1, 6 digits, 30 seconds, a 20-byte secret, and a window of one step
// either side of now.
//
// Nothing outside this package computes or compares a code. Generate exists
// for tests and for the setup screen's sanity checks; it cannot verify, and the
// verifying functions are unexported, so a handler cannot skip the throttle or
// the replay rule by calling them directly.
package totp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Parameters of 6.1.
const (
	Digits     = 6
	PeriodSecs = 30
	SecretSize = 20
	// Window is how many steps either side of now are accepted: a phone whose
	// clock is half a minute off still works.
	Window = 1

	issuer = "Ctrl Z"
)

// Errors map to the API codes of 14.3.
var (
	// ErrInvalid is 401 totp_invalid: a wrong code, or text that is not a code.
	ErrInvalid = errors.New("totp: invalid code")
	// ErrStepReused is 401 totp_step_reused: the code matched but its step (or a
	// later one) was already spent.
	ErrStepReused = errors.New("totp: code already used")
	// ErrTooMany is 429 too_many_attempts. The concrete error is a
	// *TooManyError carrying Retry-After.
	ErrTooMany = errors.New("totp: too many attempts")
)

// TooManyError says how long the guard's window has left.
type TooManyError struct{ RetryAfter time.Duration }

func (*TooManyError) Error() string        { return ErrTooMany.Error() }
func (*TooManyError) Is(target error) bool { return target == ErrTooMany }

// Guard is what Check needs from the account it checks for. Two implementations
// exist (6.3): one over users, in a tenant transaction, and one over admin_users.
// Its throttle scope is the one the 4.5 table names for the route, and that table is the only place that
// does (round 10, primitives-r10-6; this comment still listed the scopes from before round 9): reauth_session
// on POST /auth/reauth, totp_session for a request that holds only a session cookie, admin_totp and
// admin_totp_session on admin routes, and for a ticket the scope of the door that proved the first step
// (totp_user for a password ticket, totp_sms for an SMS ticket, totp_marker for a device marker that holds),
// or recovery_user, recovery_sms and recovery_marker for a recovery code in place of the code.
type Guard interface {
	// Hit spends one attempt on the throttle scope, before anything is verified,
	// so a flood cannot reach the comparison. allowed false means refused.
	Hit(ctx context.Context) (allowed bool, retryAfter time.Duration, err error)
	// Spend records that a code of this step was used. It must be the atomic
	// UPDATE ... WHERE totp_last_step IS NULL OR totp_last_step < step of 6.3:
	// fresh false means the step was already spent, so two parallel requests with
	// one code cannot both pass.
	Spend(ctx context.Context, step int64) (fresh bool, err error)
	// Reset clears the throttle after a success, for the scopes that reset on
	// success (4.5).
	Reset(ctx context.Context) error
}

// Check verifies code against secret for the guard's account, in this order:
// hit the throttle, verify at the window, spend the step. It is the only way to
// verify a code.
//
// A wrong or malformed code costs an attempt and returns ErrInvalid. A
// throttled call returns *TooManyError before looking at the code. A code that
// matches but was used returns ErrStepReused and does not reset the throttle.
// A failure to reset after success is not an error: the user is authenticated
// and the next hit shows any real database fault.
func Check(ctx context.Context, g Guard, seed secret.Bytes, code secret.String) error {
	return CheckAt(ctx, g, seed, code, appclock.Now())
}

// CheckAt is Check at a given time, for tests of the window and of a clock step.
func CheckAt(ctx context.Context, g Guard, seed secret.Bytes, code secret.String, now time.Time) error {
	allowed, retry, err := g.Hit(ctx)
	if err != nil {
		return err
	}
	if !allowed {
		return &TooManyError{RetryAfter: retry}
	}
	step, ok := match(seed, code, now)
	if !ok {
		return ErrInvalid
	}
	fresh, err := g.Spend(ctx, step)
	if err != nil {
		return err
	}
	if !fresh {
		return ErrStepReused
	}
	_ = g.Reset(ctx)
	return nil
}

// NewSecret returns 20 random bytes.
func NewSecret() (secret.Bytes, error) {
	b := make([]byte, SecretSize)
	if _, err := rand.Read(b); err != nil {
		return secret.Bytes{}, errors.New("totp: no randomness")
	}
	s := secret.NewBytes(b)
	clear(b)
	return s, nil
}

// b32 is RFC 4648 base32 without padding. A function, not a variable: the
// workspace rule bans package-level mutable state.
func b32() *base32.Encoding { return base32.StdEncoding.WithPadding(base32.NoPadding) }

// Base32 is the secret as shown beside the QR code ("کلید پشتیبان" in Plan): RFC 4648
// upper case with no padding, which every authenticator accepts.
func Base32(seed secret.Bytes) secret.String {
	return secret.New(b32().EncodeToString(seed.Reveal()))
}

// URI is the otpauth:// URI for the QR code (6.4). The label is the masked phone,
// never the full number. The result holds the secret, hence secret.String. The
// client draws the QR with a bundled library; the URI goes to no third party.
//
// Every free-text part is escaped as a whole, so a "+" in the label stays a plus
// (%2B) instead of being read as a space by an app, and an "&" or "#" cannot
// start a new field.
func URI(seed secret.Bytes, label string) secret.String {
	var b strings.Builder
	b.WriteString("otpauth://totp/")
	b.WriteString(escape(issuer))
	b.WriteByte(':')
	b.WriteString(escape(label))
	b.WriteString("?secret=")
	b.WriteString(b32().EncodeToString(seed.Reveal()))
	b.WriteString("&issuer=")
	b.WriteString(escape(issuer))
	b.WriteString("&period=30&digits=6&algorithm=SHA1")
	return secret.New(b.String())
}

// escape is percent-encoding with a space as %20, which is what the otpauth
// format uses (url.QueryEscape would write "+").
func escape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

// Generate is the code for the step that contains t.
func Generate(seed secret.Bytes, t time.Time) string {
	return code(seed.Reveal(), step(t), Digits)
}

func step(t time.Time) int64 { return t.Unix() / PeriodSecs }

// code is HOTP (RFC 4226) over counter: HMAC-SHA1, dynamic truncation, then the
// last n digits. RFC 6238 is HOTP with the counter set to the time step.
func code(key []byte, counter int64, n int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return string(out)
}

// match finds the step in the window whose code equals the input. Every
// candidate is compared, in constant time and without stopping at the first, so
// the time taken does not say which step (if any) matched. If two steps ever
// matched, the later one is returned: it is the one the replay rule must spend.
func match(seed secret.Bytes, in secret.String, now time.Time) (int64, bool) {
	text, ok := clean(in.Reveal())
	if !ok || seed.Len() == 0 {
		return 0, false
	}
	cur := step(now)
	var found int64
	hit := 0
	for s := cur - Window; s <= cur+Window; s++ {
		eq := subtle.ConstantTimeCompare([]byte(text), []byte(code(seed.Reveal(), s, Digits)))
		hit |= eq
		if eq == 1 {
			found = s
		}
	}
	return found, hit == 1
}

// clean reduces what the user typed to six ASCII digits: spaces and hyphens
// dropped (apps show "123 456"), Persian and Arabic digits read as ASCII.
func clean(s string) (string, bool) {
	// The bound is on the raw bytes and is the one every typed code shares
	// (digits.MaxTypedBytes); it exists because NFKC runs next.
	if len(s) > digits.MaxTypedBytes {
		return "", false
	}
	var b strings.Builder
	for _, r := range digits.Typed(s) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-':
		default:
			return "", false
		}
	}
	if b.Len() != Digits {
		return "", false
	}
	return b.String(), true
}

// Plausible says whether a code matches the seed in the window, and nothing else: it counts no
// attempt and spends no step, so it is never a verification. Its one use is a route that must
// not do heavy work for a caller who cannot be right (a password reset whose caller holds the
// SMS ticket but not the authenticator, tenant-r5-6) and that still verifies with Check, in
// its transaction, before anything is changed. The caller has counted the attempt first. The
// lint of 6.3 holds every use outside this package to internal/api.
func Plausible(seed secret.Bytes, code secret.String) bool {
	_, ok := match(seed, code, appclock.Now())
	return ok
}
