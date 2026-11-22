// Package ticket issues and spends the short-lived tickets that carry a login
// across steps: the mfa ticket between password and TOTP, the reset ticket
// between OTP and the new password, and the passkey tickets that hold WebAuthn
// session data (spec 2.2, 5.7, 6.6, 7).
//
// A ticket is a random token the client holds. The database holds only its
// SHA-256, so a stolen backup has no usable ticket. Tickets sit in a global
// table that only the ctrlz_fn functions touch, because a ticket exists before
// there is a session or a known tenant.
package ticket

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Header carries the ticket on the passkey finish routes, whose body is the raw
// WebAuthn response and so has no room for it (spec 7.3).
const Header = "X-Ctrlz-Ticket"

// TTL is the life of a ticket of each kind. The database caps any ticket at ten
// minutes; these are shorter than that because each is a step in one sitting.
func TTL(_ store.TicketKind) time.Duration {
	return keyring.LifeCeremony
}

// Service issues and spends tickets.
type Service struct {
	auth store.AuthLookups
	// ring and now are set by WithSealing for the stateless tickets of ceremony.go.
	ring *keyring.Ring
	now  func() time.Time
}

// ErrSealed is a sealed ticket that cannot be made: the service was not given a ring, or the
// session data is empty or too large. It is a defect of the caller.
var ErrSealed = errors.New("ticket: cannot seal a ceremony")

// New returns a Service over the store's auth calls.
func New(a store.AuthLookups) *Service { return &Service{auth: a} }

// Issue describes a ticket to make.
type Issue struct {
	Kind        store.TicketKind
	Tenant      uuid.UUID // the nil uuid for a ticket with no subject (passkey_login)
	User        uuid.UUID
	RememberMe  bool
	FirstFactor string // password or otp
	Payload     []byte // at most 4096 bytes
	// Cred is the stamp of the first factor the ticket comes from (User.Stamp or
	// UserLogin.Cred). The mfa kind requires it; Tx.UserLockFor compares it with the row
	// when the ticket is spent (internal/credgen).
	Cred credgen.Stamp
}

// Issued is the result: the token to hand the client, and its lifetime.
type Issued struct {
	Token     secret.String
	ExpiresIn time.Duration
}

// Put stores a ticket and returns its token. The token is shown once; only its
// hash is stored.
func (s *Service) Put(ctx context.Context, in Issue) (Issued, error) {
	n, iss, err := newTicket(in)
	if err != nil {
		return Issued{}, err
	}
	_, ok, err := s.auth.TicketPut(ctx, n)
	return issued(iss, ok, err)
}

// PutTx is Put on the connection of an open transaction. A route that puts a ticket while
// it holds a row lock (the mfa ticket, put under the user's lock so that a credential
// change cannot slip in between) uses this one: Put would ask the pool for a second
// connection while the first is held, which the store refuses (store.ErrNested; rule
// one-connection-per-request).
func (s *Service) PutTx(tx store.Tx, in Issue) (Issued, error) {
	n, iss, err := newTicket(in)
	if err != nil {
		return Issued{}, err
	}
	_, ok, err := tx.TicketPut(n)
	return issued(iss, ok, err)
}

// newTicket builds the row to store and the answer to give, for both ways to put one.
func newTicket(in Issue) (store.NewTicket, Issued, error) {
	if in.Kind == store.TicketMFA && in.Cred.Zero() {
		return store.NewTicket{}, Issued{}, store.ErrConstraint // an mfa ticket without a generation could never be refused
	}
	tok, err := token.New()
	if err != nil {
		return store.NewTicket{}, Issued{}, err
	}
	ttl := TTL(in.Kind)
	return store.NewTicket{
		TokenHash: token.Hash(tok), Kind: in.Kind, Tenant: in.Tenant, User: in.User,
		RememberMe: in.RememberMe, FirstFactor: in.FirstFactor, Payload: in.Payload, TTL: ttl, Cred: in.Cred,
	}, Issued{Token: tok, ExpiresIn: ttl}, nil
}

func issued(iss Issued, ok bool, err error) (Issued, error) {
	if err != nil {
		return Issued{}, err
	}
	if !ok {
		// The function refuses only malformed input, which is a bug in the caller.
		return Issued{}, store.ErrConstraint
	}
	return iss, nil
}

// Peek reads a ticket and spends one of its five attempts. found is false for an
// unknown, wrong-kind, used, expired or exhausted ticket, without saying which.
// A value that is not shaped like a token is refused without a database call.
func (s *Service) Peek(ctx context.Context, tok string, kind store.TicketKind) (store.Ticket, bool, error) {
	if !token.Valid(tok) {
		return store.Ticket{}, false, nil
	}
	return s.auth.TicketPeek(ctx, token.HashString(tok), kind)
}

// Take spends a ticket. Of two requests with one ticket exactly one gets it.
func (s *Service) Take(ctx context.Context, tok string, kind store.TicketKind) (store.Ticket, bool, error) {
	if !token.Valid(tok) {
		return store.Ticket{}, false, nil
	}
	t, w, err := s.auth.TicketTake(ctx, token.HashString(tok), kind)
	if err != nil || !w.Yes() {
		return store.Ticket{}, false, err
	}
	return t, true, nil
}

// TakeTx is Take inside a transaction: the spend commits or rolls back with it, so a request
// that fails after the check does not burn the ticket (rule one-connection-per-request;
// tenant-r1-1). The route spends the ticket last among the checks that can fail and
// before the writes it guards, so of two requests with one ticket the second waits on the
// row and loses.
func (s *Service) TakeTx(tx store.Tx, tok string, kind store.TicketKind) (store.Ticket, bool, error) {
	if !token.Valid(tok) {
		return store.Ticket{}, false, nil
	}
	t, w, err := tx.TicketTake(token.HashString(tok), kind)
	if err != nil || !w.Yes() {
		return store.Ticket{}, false, err
	}
	return t, true, nil
}

// FromRequest reads the ticket header of a passkey finish request.
func FromRequest(r *http.Request) string { return r.Header.Get(Header) }
