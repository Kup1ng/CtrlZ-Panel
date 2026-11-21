// Package password hashes and verifies passwords with Argon2id (spec 4.1), holds
// the length rules of 4.2, and gives the login path the two things 4.5 asks for:
// one Argon2 run on every path, and a floor under the response time.
//
// No pepper and no key touch a password hash (4.1): a lost key must never lock
// out password login (D23). That is why this package imports neither keyring nor
// store.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Limits of spec 4.2, counted in code points after NFKC.
const (
	MinLengthUser  = 10
	MinLengthAdmin = 14
	MaxLength      = 128
	// MaxBytes is the cap after normalisation. 128 code points of 4 bytes would
	// be 512 bytes, so this is the same bound seen from the byte side, and it
	// is what the Argon2 input is checked against.
	MaxBytes = 512
	// maxRawBytes stops NFKC from working on a megabyte. Normalisation never
	// shrinks text by more than half (composition), so anything above 8 times
	// the limit is over the limit afterwards too.
	maxRawBytes = MaxBytes * 8
)

// Kind says whose password it is. Admins get the longer minimum (4.2).
type Kind int

// The two kinds of account.
const (
	User Kind = iota
	Admin
)

// MinLength is the minimum in code points for the kind.
func (k Kind) MinLength() int {
	if k == Admin {
		return MinLengthAdmin
	}
	return MinLengthUser
}

// Errors the handlers map to a response. They carry no password text.
var (
	ErrTooShort = errors.New("password: too short")
	ErrTooLong  = errors.New("password: too long")
	ErrInvalid  = errors.New("password: not valid UTF-8")
	// errMalformed is the reason a stored hash cannot be read. It is not exported on purpose: Verify turns
	// it into "wrong password" itself (round 8, primitives-r8-5), so no caller can forget to, and the
	// condition is reported through Unreadable and OnUnreadable, which cannot become an error.
	errMalformed = errors.New("password: stored hash is malformed")
)

// Normalize applies NFKC, so the same text typed on two keyboards matches (4.2).
// It does not fold Arabic ي and ك to Persian ی and ک: they are distinct code
// points, and folding would surprise users who chose them on purpose. It checks
// the upper bound and not the lower one: an existing password was set under the
// rules of its day, and login must still compare it.
func Normalize(pw secret.String) (secret.String, error) {
	raw := pw.Reveal()
	if len(raw) > maxRawBytes {
		return secret.String{}, ErrTooLong
	}
	if !utf8.ValidString(raw) {
		return secret.String{}, ErrInvalid
	}
	n := norm.NFKC.String(raw)
	if len(n) > MaxBytes || utf8.RuneCountInString(n) > MaxLength {
		return secret.String{}, ErrTooLong
	}
	return secret.New(n), nil
}

// Prepared is a password as a route holds it between the checks and the hash: what the person
// typed and the NFKC form of it, in one value whose fields are unexported. The strength gate
// needs both, and for different reasons. The minimum and the layout readings are about what was
// typed (NFKC expands one compatibility character into a phrase and reorders the combining marks
// of the Persian shifted top row, so a scorer that only sees the NFKC text scores a guess the
// guesser never makes, and misses the walk he does), and the hash is of the normalised text, so
// that the same password typed on two keyboards matches. When Prepare returned the NFKC text as a
// plain secret.String and the checker took a plain secret.String, every route passed the second
// half of the pair to a function that took the first, the typed reading was dead code in
// production and the corpus tested a path no route took (round 7, primitives-r7-5). Now the
// checker takes a Prepared, a route cannot hand it the normalised text alone, and the only door to
// the value in production is Prepare (internal/lint TestPreparedIsMadeOnlyByPrepare).
type Prepared struct {
	typed, norm secret.String
	counted     int
}

// Typed is Prepare without the minimum, for the callers that must look at a short password
// (the strength gate answers too_short for it) and for tests. A route calls Prepare: Typed is
// refused outside this package and tests by internal/lint.
func Typed(pw secret.String) (Prepared, error) {
	n, err := Normalize(pw)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{typed: pw, norm: n, counted: CountedLength(pw)}, nil
}

// Typed is what the person typed, for the layout readings of the strength gate.
func (p Prepared) Typed() secret.String { return p.typed }

// Normalized is the NFKC form, the text that is hashed.
func (p Prepared) Normalized() secret.String { return p.norm }

// Counted is the length the minimum was measured by (CountedLength).
func (p Prepared) Counted() int { return p.counted }

// IsZero reports a Prepared that was never made by Prepare or Typed.
func (p Prepared) IsZero() bool { return p.norm.IsZero() && p.typed.IsZero() }

// Prepare is Normalize plus the minimum for a new password. Callers that set a
// password run it first, then the strength check on the result, then Hash of
// Normalized.
func Prepare(pw secret.String, kind Kind) (Prepared, error) {
	p, err := Typed(pw)
	if err != nil {
		return Prepared{}, err
	}
	if p.counted < kind.MinLength() {
		return Prepared{}, ErrTooShort
	}
	return p, nil
}

// CountedLength is the length the minimum is measured by: the smaller of the visible code points
// the person typed and those of the NFKC form (review round 6, primitives-r6-1; round 16,
// primitives-r16-1 and -10). The minimum exists to count what a guesser has to guess.
// NFKC expands some single characters into many (U+FDFA becomes eighteen code
// points), so counting only the normalised text let one typed character stand
// for a 14-code-point admin password; it also composes (a letter and its mark
// become one), so the typed count alone would count marks that vanish.
//
// A code point that is typed and not shown (digits.Invisible: the zero-width non-joiner the
// Persian keyboard types on Shift+B, the zero-width space, the word joiner and the rest of the
// class) is not counted either. The strength gate scores the text with exactly those removed, so
// counting them let eight visible characters, which zxcvbn rates as random text and scores 3 or 4,
// be padded with six word joiners past the 14 of 4.2: the score guards strength and this count
// guards the floor, and the floor has to read the same text the score does. It asks the one
// predicate (digits.Invisible), so the class cannot drift from the scorer's.
//
// The maximum stays a limit of the stored form (Normalize). Strength checks and
// Prepare both call this, so the two cannot disagree. Invalid UTF-8 is counted
// as typed (it is refused by Normalize before the count matters).
func CountedLength(pw secret.String) int {
	raw := pw.Reveal()
	if !utf8.ValidString(raw) {
		return utf8.RuneCountInString(raw)
	}
	return min(visibleRunes(raw), visibleRunes(norm.NFKC.String(raw)))
}

// visibleRunes counts the code points of s that digits.Invisible does not name.
func visibleRunes(s string) int {
	n := 0
	for _, r := range s {
		if !digits.Invisible(r) {
			n++
		}
	}
	return n
}

// Params are the Argon2id cost parameters. Threads is 1 by design (4.1): memory
// and CPU per login stay predictable on a small host.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// DefaultParams is spec 4.1: m = 47104 KiB (46 MiB), t = 2, p = 1.
func DefaultParams() Params { return Params{MemoryKiB: 47104, Time: 2, Threads: 1} }

const (
	saltLen = 16
	hashLen = 32
	// Bounds on parameters read from a stored hash. They are far above what
	// this code writes, and far below what would exhaust a container if a row
	// were ever tampered with.
	maxStoredMemKiB = 256 << 10
	maxStoredTime   = 16
	maxStoredThread = 8
)

func (p Params) validate() error {
	if p.Threads < 1 || p.Time < 1 || p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxStoredMemKiB || p.Time > maxStoredTime {
		return errors.New("password: invalid argon2 parameters")
	}
	return nil
}

// Hasher hashes and verifies. It is safe for concurrent use; the Gate is what
// bounds the memory.
type Hasher struct {
	params Params
	gate   *Gate
	dummy  secret.String
	// oneTimeOnly marks the hasher of the console tools (NewOneTimeHasher).
	oneTimeOnly bool
	runs        atomic.Uint64
	// unreadable counts the stored hashes Verify could not read, and onUnreadable is told of each.
	unreadable   atomic.Uint64
	onUnreadable atomic.Pointer[func()]
}

// Unreadable counts the stored hashes that Verify and VerifyGateFree answered "wrong password" for
// because they could not be read. A test asserts it, and an operator who lowers the memory budget
// sees it move.
func (h *Hasher) Unreadable() uint64 { return h.unreadable.Load() }

// OnUnreadable sets the function called once for every stored hash that could not be read. It takes
// no argument on purpose: nothing about the hash, or the account it belongs to, reaches a log. Call
// it once, before the hasher serves requests (the wiring in internal/app does).
func (h *Hasher) OnUnreadable(f func()) { h.onUnreadable.Store(&f) }

func (h *Hasher) reportUnreadable() {
	h.unreadable.Add(1)
	if f := h.onUnreadable.Load(); f != nil && *f != nil {
		(*f)()
	}
}

// NewHasher makes a Hasher over a gate. It checks that the parameters fit one slot
// of the gate's budget and allocates no Argon2 memory: nothing is computed until
// the first hash or verify, which runs inside the gate (review round 5, rule
// argon2-memory-budget; before it the dummy was hashed here, at full cost, outside
// any gate, and the console tools paid for it inside the admin container).
//
// The floor of 4.1 is not checked here: it belongs to Settings, the only way a
// service gets a Hasher, and tests build hashers below it on purpose.
//
// The dummy is a parameter set and a random salt around a zero sum. It is never
// compared (verifyAgainst always reports a mismatch), so nobody needs it to be the
// result of a hash: a login for a phone with no account verifies against it, runs
// Argon2 once at the current cost, and so unknown and known phones cost the same
// (R44, 4.5 step 4).
func NewHasher(p Params, g *Gate) (*Hasher, error) {
	// A hash written with the one-time parameters is read back as a console one-time hash and verified
	// with no slot of the gate (VerifyGateFree), so no hasher of the normal path may write one, whatever
	// the environment lets its settings be (round 8, primitives-r8-1: CTRLZ_ENV=test with m=8, t=1 made
	// every ordinary admin hash look like one). NewOneTimeHasher is the one maker, through newHasher.
	if p == oneTimeParams() {
		return nil, errors.New("password: these parameters are the one-time hash's and are reserved for it")
	}
	return newHasher(p, g)
}

// newHasher is NewHasher without the reservation of the one-time parameters.
func newHasher(p Params, g *Gate) (*Hasher, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, errors.New("password: nil gate")
	}
	if p.MemoryKiB > g.CeilingKiB() {
		return nil, errors.New("password: argon2 memory does not fit one slot of the budget")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("password: no randomness")
	}
	return &Hasher{params: p, gate: g, dummy: secret.New(encode(p, salt, make([]byte, hashLen)))}, nil
}

// Gate is the gate every run of this hasher goes through.
func (h *Hasher) Gate() *Gate { return h.gate }

// Params returns the parameters new hashes are made with.
func (h *Hasher) Params() Params { return h.params }

// Runs counts Argon2 computations. A test asserts it moves by exactly one for
// every login path (4.5, 18.5).
func (h *Hasher) Runs() uint64 { return h.runs.Load() }

// derive runs Argon2id through the gate, which is where the budget is kept. The
// password bytes are wiped afterwards.
func (h *Hasher) derive(ctx context.Context, pw secret.String, salt []byte, p Params, n uint32, mode slotMode) ([]byte, error) {
	if h.oneTimeOnly && !isOneTimeHash(p) {
		return nil, ErrOneTimeOnly
	}
	b := []byte(pw.Reveal())
	defer clear(b)
	sum, err := h.gate.derive(ctx, b, salt, p, n, mode)
	if err != nil {
		return nil, err
	}
	h.runs.Add(1)
	return sum, nil
}

// Hash returns a PHC string for the password. It normalises first, so nothing
// un-normalised is ever stored, and it enforces the upper bound but not the
// minimum: callers that need the minimum call Prepare, which also gives them the
// text the strength check must see.
func (h *Hasher) Hash(ctx context.Context, pw secret.String) (secret.String, error) {
	if h.oneTimeOnly {
		// Its parameters are the one-time ones, so derive would let it through.
		return secret.String{}, ErrOneTimeOnly
	}
	n, err := Normalize(pw)
	if err != nil {
		return secret.String{}, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return secret.String{}, errors.New("password: no randomness")
	}
	sum, err := h.derive(ctx, n, salt, h.params, hashLen, inSlot)
	if err != nil {
		return secret.String{}, err
	}
	return secret.New(encode(h.params, salt, sum)), nil
}

// Verify checks pw against a stored PHC string. It runs Argon2 exactly once on
// every path: an empty stored hash (an unknown phone, or an account with no
// password), a malformed one and an over-long input are all verified against the
// dummy and fail, so timing and cost say nothing about which case it was.
//
// The error is for the machinery (ErrBusy from a full gate, a cancelled context), never for a
// wrong password: that is ok = false with a nil error. A stored hash nobody can read (damaged, or
// above the Argon2 ceiling after an operator lowered the budget, spec 4.1) is a wrong password too,
// for every caller of Verify and VerifyGateFree alike, and the owner resets the password. The
// mapping lives here and not in each route because two rounds in a row a caller forgot it and
// answered 500 (round 7 primitives-r7-2, round 8 primitives-r8-5); the condition is counted
// (Unreadable) and reported to the hook (OnUnreadable), so the operator still hears of it.
func (h *Hasher) Verify(ctx context.Context, pw, stored secret.String) (bool, error) {
	return h.verify(ctx, pw, stored, true)
}

// VerifyGateFree is Verify except that a console one-time hash is checked without
// taking a slot of the gate. It exists for exactly two callers, both in the admin
// service and both the same check of the same console password: AdminLogin
// (POST /auth/login, step 2) and changePassword (POST /me/password, the current
// password of an admin who still holds only a console one-time password). It is the
// declared exception of the known-or-unknown rule (spec 10.2 step 2, admin-r4-6):
// the owner's first login must not depend on a gate strangers can fill. Everything
// else, the tenant routes included, calls Verify, so whether a request reaches the
// gate never depends on how the account's password was made (review round 5, rule
// known-unknown-oracle). The two callers are the allow list of internal/lint
// TestGateFreeVerifyOnlyInTheAdminService, which fails for a third caller and for
// one of these two that no longer calls it; this comment and that list change
// together (round 9, admin-r9-1).
func (h *Hasher) VerifyGateFree(ctx context.Context, pw, stored secret.String) (bool, error) {
	return h.verify(ctx, pw, stored, false)
}

func (h *Hasher) verify(ctx context.Context, pw, stored secret.String, gateOneTime bool) (bool, error) {
	n, nerr := Normalize(pw)
	p, salt, want, perr := parse(stored.Reveal())
	if perr == nil && p.MemoryKiB > h.gate.CeilingKiB() {
		perr = errMalformed
	}
	if nerr != nil || perr != nil || stored.IsZero() {
		// Against the dummy, with the password if it is usable and with an empty
		// one if not, so the work is the same.
		_, err := h.verifyAgainst(ctx, n, h.dummy)
		if err != nil {
			return false, err
		}
		if perr != nil && !stored.IsZero() {
			h.reportUnreadable()
		}
		return false, nil
	}
	// The cheap one-time hash only makes the compare quick. Unless the caller is
	// the declared gate-free one, the request still waits for a slot as an unknown
	// phone does, so a full gate answers both alike.
	mode := inSlot
	if isOneTimeHash(p) && !gateOneTime {
		mode = tinyFree
	}
	sum, err := h.derive(ctx, n, salt, p, uint32(len(want)), mode)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(sum, want) == 1, nil
}

// verifyAgainst is the dummy path. It always reports a mismatch: the dummy is a
// hash of random bytes nobody holds, but "always false" does not rest on that.
func (h *Hasher) verifyAgainst(ctx context.Context, pw, stored secret.String) (bool, error) {
	p, salt, want, err := parse(stored.Reveal())
	if err != nil {
		return false, err
	}
	if _, err := h.derive(ctx, pw, salt, p, uint32(len(want)), inSlot); err != nil {
		return false, err
	}
	return false, nil
}

// NeedsRehash reports whether a stored hash differs from what Hash would write
// now, so the caller can store a fresh one after a successful Verify, in the
// same WithTenant (4.1). A malformed hash needs a rehash too, but it cannot have
// verified, so the question does not arise.
func (h *Hasher) NeedsRehash(stored secret.String) bool {
	p, salt, want, err := parse(stored.Reveal())
	if err != nil {
		return true
	}
	// A one-time hash is cheap on purpose (HashOneTime) and is replaced by the
	// password the account owner chooses; upgrading it would only spend the gate.
	if isOneTimeHash(p) {
		return false
	}
	return p != h.params || len(salt) != saltLen || len(want) != hashLen
}

// encode writes the PHC string: $argon2id$v=19$m=..,t=..,p=..$salt$hash, base64
// without padding.
func encode(p Params, salt, sum []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(sum))
}

// parse reads a PHC string strictly: Argon2id only, version 19, the parameters
// in the order m, t, p, and bounded values.
func parse(s string) (Params, []byte, []byte, error) {
	bad := func() (Params, []byte, []byte, error) { return Params{}, nil, nil, errMalformed }
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return bad()
	}
	kv := strings.Split(parts[3], ",")
	if len(kv) != 3 {
		return bad()
	}
	var vals [3]uint64
	for i, key := range []string{"m=", "t=", "p="} {
		v, ok := strings.CutPrefix(kv[i], key)
		if !ok {
			return bad()
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return bad()
		}
		vals[i] = n
	}
	if vals[2] < 1 || vals[2] > maxStoredThread {
		return bad()
	}
	p := Params{MemoryKiB: uint32(vals[0]), Time: uint32(vals[1]), Threads: uint8(vals[2])}
	if p.validate() != nil {
		return bad()
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return bad()
	}
	sum, err := b64.DecodeString(parts[5])
	if err != nil || len(sum) < 16 || len(sum) > 64 {
		return bad()
	}
	return p, salt, sum, nil
}
