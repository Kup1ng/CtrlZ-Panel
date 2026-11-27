// Package proof is the one shape of every route that takes a one-time proof: an OTP code,
// a reset, mfa or passkey ticket, an invite token, a sealed ceremony ticket or the console
// password of a first-factor login (P1 auth review round 5, rule proof-before-work; spec
// 4.3, 4.4, 5.6, 7.5, 10.2).
//
// The order is fixed because rounds 1 to 4 each chose it by local reasoning and each
// choice was wrong for the next route. Two aims pull apart: do not burn the proof on a
// weak password, and do not spend CPU, memory or rows before the caller has shown the
// proof is real. The shape serves both:
//
//  1. Shape: O(1) checks of the request itself (a length, a locale, a phone that parses).
//     No database, no gate.
//  2. Charge: the proof's budget is spent. The budget is keyed on the proof or its
//     subject, never on a network alone (rule budget-keying).
//  3. Check: the proof is looked at without being used up: a code is peeked, a ticket is
//     read, a sealed ticket's tag is verified. A wrong proof ends the request here. A
//     ticket read spends one of the ticket's own attempts, which is its charge, so the
//     Check step may charge too.
//  4. Work: everything that costs. Scoring, Argon2, a WebAuthn assertion, a row write,
//     and the consume of the proof, which belongs in the transaction that commits the
//     outcome so a failure after the check does not burn it. A challenge that must die
//     with its first answer (a passkey ceremony ticket) is the one thing taken at the
//     start of Work instead.
//
// internal/lint TestProofBeforeWorkRule fails the build for a heavy primitive that a
// handler of an x-ctrlz-auth none operation can reach outside the Work literal of a Spec,
// and for a Spec without a Kind, a Work or (unless it is a first-factor password) a Check.
// The flood tests of internal/api and internal/adminapi fire made-up proofs at every
// such operation and count scorings, Argon2 runs and ticket rows.
//
// A first-factor password login is the one case with no proof to look at first: the
// verify is the check, it runs once on every path (the dummy hash for a name nobody has),
// so the Spec of Kind Password has no Check and its Work holds the verify.
package proof

import (
	"context"
	"errors"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
)

// Kind says what the caller is proving. The lint reads it: a Spec must name one, and only
// Password may go without a Check.
type Kind int

// The kinds of proof.
const (
	// Password is a first factor checked by one Argon2 verify inside Work.
	Password Kind = iota + 1
	// OneTimeCode is an OTP code or a challenge id and code pair.
	OneTimeCode
	// Ticket is a stored ticket the client holds (reset, mfa, passkey reauth).
	Ticket
	// Invite is an invite token.
	Invite
	// Sealed is a ticket that carries its own state under a tag (the passkey login
	// ceremony), so it costs no row until it is used.
	Sealed
)

// ErrSpec is returned for a Spec that is malformed. It is a defect of the code that built
// it, caught by the lint first and by the first request otherwise.
var ErrSpec = errors.New("proof: malformed spec")

// Proved is handed to Work and is the evidence that the steps before it ran. It has no
// exported field and only Run makes one, so a function that wants one as a parameter
// cannot be called from a place that skipped the shape.
type Proved struct{ kind Kind }

// Kind is the kind of proof that was checked.
func (p Proved) Kind() Kind { return p.kind }

// Spec is one route. Every step but Work may be nil.
type Spec[T any] struct {
	Kind   Kind
	Shape  func(ctx context.Context) error
	Charge func(ctx context.Context) error
	Check  func(ctx context.Context) error
	// Work is where the heavy work and the commit are. It must be a function literal at
	// the Spec, so the lint can see what it holds.
	Work func(ctx context.Context, p Proved) (T, error)
	// Refund gives back what Charge took, and Run calls it only when Work answers that the
	// machine was busy (Busy): the Argon2 gate or the scoring gate refused the request, so no
	// password was looked at and nothing was learned about the caller. The charge comes first on
	// purpose (a flood must not reach Argon2), but a charge that stays after a refusal of the
	// server's own makes load into a lockout: five 503s spent the 5 tries of a phone and a
	// network, and the right password was a 429 for 15 minutes once the load had passed (round
	// 5, tenant-r5-1). Every Spec that charges has one: there was a NoRefund reason for a Spec that
	// "could not be busy", and the admin login claimed it while its verify takes an Argon2 slot like
	// any other (round 6, primitives-r6-9), so the escape is gone and a reason is not a proof. The
	// lint (TestProofBeforeWorkRule) fails for a Spec with a Charge and no Refund. It runs with the request's values but not its cancellation, since a client
	// that gave up on a 503 must still get its tries back, and it must not fail the request.
	Refund func(ctx context.Context)
}

// Run executes the steps in order and stops at the first error. Work runs only when every
// earlier step passed.
func Run[T any](ctx context.Context, s Spec[T]) (T, error) {
	var zero T
	if s.Kind == 0 || s.Work == nil || (s.Check == nil && s.Kind != Password) || (s.Charge != nil && s.Refund == nil) {
		return zero, ErrSpec
	}
	for _, step := range []func(context.Context) error{s.Shape, s.Charge, s.Check} {
		if step == nil {
			continue
		}
		if err := step(ctx); err != nil {
			return zero, err
		}
		if err := ctx.Err(); err != nil {
			return zero, err
		}
	}
	// A Spec that looked at a proof before Work (a code that was peeked, a ticket that was read, a
	// sealed ticket whose tag checked, an invite that is live) is a request with a proof: its hash and
	// its scoring are served before any stranger when the Argon2 gate is full, so unproved logins
	// cannot starve a reset or a registration whose code is right (tenant-r6-1, -7). A first-factor
	// password has nothing to look at, so it is a stranger until its caller says otherwise (a device
	// marker that holds, routes_login.go). This is the one place the lane is given to proof steps;
	// the lint lists it (TestGatePriorityIsGivenOnlyByProofs).
	workCtx := ctx
	if s.Kind != Password {
		workCtx = password.Proved(ctx)
	}
	out, err := s.Work(workCtx, Proved{kind: s.Kind})
	if err != nil && s.Refund != nil && Busy(err) {
		s.Refund(context.WithoutCancel(ctx))
	}
	return out, err
}

// Busy says the error is the server's own refusal for want of capacity, not an answer about the
// caller: the Argon2 gate (a verify or a hash) or the scoring gate stayed full for the whole wait.
func Busy(err error) bool { return errors.Is(err, password.ErrBusy) }
