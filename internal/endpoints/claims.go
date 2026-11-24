package endpoints

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The routes' half of the Plain DNS claims (docs/specs/p3-endpoints.md 4.3). The model and every rule of it are the four
// functions of PS 8, built in P0; this file takes the Endpoint's row before calling them (spec 3.7 step 5: a claim function is
// called only after its caller's Endpoint lock, which is what keeps it from deadlocking with the P4 DDNS worker and with an
// authorized delete) and maps their outcomes to the refusals of the table in 4.3. No code of P3 writes ip_claims by any other
// path.

// ClaimSources are the sources a request may name. A route sends "manual" for a typed prefix and "browser" for the address the
// panel saw; secure_dns and ddns are the hub's and the DDNS worker's.
const (
	SourceManual  = "manual"
	SourceBrowser = "browser"
)

// ClaimResult is a claim after a request or a take, and what the function answered.
type ClaimResult struct {
	Claim   store.ClaimRow
	Outcome string
}

func (e *Env) lockEndpoint(tx store.Tx, endpoint uuid.UUID) error {
	found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
	if err != nil {
		return err
	}
	if len(found) != 1 {
		return notFound()
	}
	return nil
}

// RequestClaim asks for a claim on a prefix (4.3). A claim that starts active is compiled, so the outbox is marked in the
// same transaction; a pending one is not. A request turns nobody away, so no lock password is asked.
func (e *Env) RequestClaim(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, endpoint uuid.UUID, ask ClaimAsk) (ClaimResult, error) {
	prefix, source, err := ask.resolve()
	if err != nil {
		return ClaimResult{}, err
	}
	var out ClaimResult
	err = e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		if err := e.lockEndpoint(tx, endpoint); err != nil {
			return err
		}
		r, err := tx.IPClaimRequest(endpoint, prefix, source)
		if err != nil {
			return err
		}
		switch r.Outcome {
		case "active":
			if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
				return err
			}
		case "pending_proof", "wide_requires_approval":
		case "invalid_address":
			return invalid(Field{"/cidr", CodeReservedRange})
		case "unsupported":
			return invalid(Field{"/cidr", CodeUnsupportedFamily})
		case "suspended":
			return &Error{Kind: KindIPSuspended}
		case "quota_exceeded":
			return invalid(Field{"max_ip_claims", CodeExceeded})
		case "own":
			return invalid(Field{"/cidr", CodeExists})
		case "not_found":
			return notFound()
		default:
			// invalid_source is a defect of ours, and an outcome nobody knows is one too.
			return errUnexpected()
		}
		c, ok, err := tx.ClaimGet(endpoint, r.ClaimID)
		if err != nil {
			return err
		}
		if !ok {
			return errUnexpected()
		}
		out = ClaimResult{Claim: c, Outcome: r.Outcome}
		return nil
	})
	return out, err
}

// errUnexpected is an outcome of a database function that the code does not know: the handler answers 500 internal. A function,
// not a variable: a package-level error would be state.
func errUnexpected() error {
	return errors.New("endpoints: a database function answered an outcome the code does not know")
}

// ChallengeOut is an opened challenge with what its dialog needs of the Resolver view (spec 9.3): the stored zone, which is
// empty while the admin has set no domain, and the pair's addresses, invalid where the Endpoint has no pair or no fallback.
type ChallengeOut struct {
	Challenge         store.Challenge
	Zone              string
	Primary, Fallback netip.Addr
}

// OpenChallenge opens a proof challenge for a claim of the Endpoint (4.2). The database makes the label and the expiry. When it
// opens none, the claim is told apart: suspended (409), gone (404), or at the caps of PS 8, which is 429 with the seconds until
// the oldest live challenge ends.
func (e *Env) OpenChallenge(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, endpoint, claim uuid.UUID) (ChallengeOut, error) {
	var out ChallengeOut
	err := e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		if err := e.lockEndpoint(tx, endpoint); err != nil {
			return err
		}
		c, ok, err := tx.ClaimGet(endpoint, claim)
		if err != nil {
			return err
		}
		if !ok {
			return notFound()
		}
		ch, opened, err := tx.IPClaimOpenChallenge(claim)
		if err != nil {
			return err
		}
		if opened {
			out = ChallengeOut{Challenge: ch}
			// What the dialog shows beside the label: the zone and the pair, read in the transaction that opened the challenge so a
			// challenge is never made and then not shown.
			if out.Zone, err = tx.DNSZone(); err != nil {
				return err
			}
			pairs, err := tx.EndpointPairIPs()
			if err != nil {
				return err
			}
			for _, p := range pairs {
				if p.EndpointID == endpoint {
					out.Primary, out.Fallback = p.PrimaryDNSIP, p.FallbackDNSIP
				}
			}
			return nil
		}
		if c.State == "suspended" {
			return &Error{Kind: KindIPSuspended}
		}
		// The function says nothing of why it opened none. A claim that overlaps another suspended claim of the tenant is refused
		// too, and no wait ends that (only an admin does), so it is told apart from the caps and answers 409 as the take does.
		overlap, err := tx.ClaimOverlapsSuspended(claim)
		if err != nil {
			return err
		}
		if overlap {
			return &Error{Kind: KindIPSuspended}
		}
		secs, err := tx.ClaimChallengeRetry(claim)
		if err != nil {
			return err
		}
		return &Error{Kind: KindTooManyChallenges, RetryAfter: secs}
	})
	return out, err
}

// TakeClaim proves a claim with the evidence the hub wrote (4.2): the function decides, never the caller. no_proof commits,
// because a wrong code is counted by the function and the count must stay. A take that makes the claim active is compiled.
func (e *Env) TakeClaim(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, endpoint, claim uuid.UUID, code string) (ClaimResult, error) {
	var out ClaimResult
	err := e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		if err := e.lockEndpoint(tx, endpoint); err != nil {
			return err
		}
		if _, ok, err := tx.ClaimGet(endpoint, claim); err != nil {
			return err
		} else if !ok {
			return notFound()
		}
		outcome, err := tx.IPClaimTake(claim, code)
		if err != nil {
			return err
		}
		switch outcome {
		case "active":
			// The function wrote the rows of every tenant it displaced, and the taker's own, under this transaction's batch; the mark
			// of the taker's own is idempotent with it.
			if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
				return err
			}
		case "already_active", "no_proof":
		case "unavailable":
			return &Error{Kind: KindIPUnavailable}
		case "suspended":
			return &Error{Kind: KindIPSuspended}
		case "wide_requires_approval":
			return &Error{Kind: KindNeedsAdmin}
		case "own":
			return invalid(Field{"/cidr", CodeExists})
		case "not_found":
			return notFound()
		default:
			return errUnexpected()
		}
		c, ok, err := tx.ClaimGet(endpoint, claim)
		if err != nil {
			return err
		}
		if !ok {
			return errUnexpected()
		}
		out = ClaimResult{Claim: c, Outcome: outcome}
		return nil
	})
	return out, err
}

// ReleaseClaim releases a claim of the Endpoint (4.3). A claim that was a Plain DNS identity takes its devices' filtering away,
// so the lock passwords of 3.3 are asked for the profiles those devices lose: the stack of the identity is read before and
// after, the claim being absent from the second. The mark is written for every release: the function does not return the prior
// state and a mark is idempotent.
func (e *Env) ReleaseClaim(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, endpoint, claim uuid.UUID) error {
	return e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		if err := g.Begin(tx, []uuid.UUID{endpoint}); err != nil {
			return err
		}
		if err := e.lockEndpoint(tx, endpoint); err != nil {
			return err
		}
		if _, ok, err := tx.ClaimGet(endpoint, claim); err != nil {
			return err
		} else if !ok {
			return notFound()
		}
		before, err := g.Inputs(tx, []uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		outcome, err := tx.IPClaimRelease(claim)
		if err != nil {
			return err
		}
		switch outcome {
		case "released":
		case "suspended":
			return &Error{Kind: KindIPSuspended}
		case "not_found":
			return notFound()
		default:
			return errUnexpected()
		}
		after, err := g.Inputs(tx, []uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if err := g.Check(tx, before, after); err != nil {
			return err
		}
		return store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID())
	})
}

// ClaimAsk is what a request for a claim says: a prefix typed, or the address the panel saw the request come from, which is
// claimed as a /32 with source browser (4.2). Exactly one of the two is set.
type ClaimAsk struct {
	// Cidr is the typed prefix or address; nil when Mine is used.
	Cidr *string
	// Mine is the client address of the request, set when the person asked for it; the zero Addr when not.
	Mine netip.Addr
	// UseMine says the request asked for its own address.
	UseMine bool
}

// Check refuses a request that names both or neither, or a prefix that does not parse, before anything is charged or locked.
func (a ClaimAsk) Check() *Error {
	_, _, err := a.resolve()
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		return e
	}
	return &Error{Kind: KindValidation, Fields: []Field{{"/cidr", CodeInvalid}}}
}

func (a ClaimAsk) resolve() (netip.Prefix, string, error) {
	if (a.Cidr != nil) == a.UseMine {
		return netip.Prefix{}, "", invalid(Field{"/cidr", CodeRequired})
	}
	if a.Cidr != nil {
		p, code := ParseClaimPrefix(*a.Cidr)
		if code != "" {
			return netip.Prefix{}, "", invalid(Field{"/cidr", code})
		}
		return p, SourceManual, nil
	}
	p := PrefixOfAddress(a.Mine)
	if !p.IsValid() {
		// The pipeline refuses a request with no client address, so this is a wiring defect and not the person's.
		return netip.Prefix{}, "", errors.New("endpoints: no client address to claim")
	}
	return p, SourceBrowser, nil
}

// ParseClaimPrefix reads the prefix of a claim request as typed: an address (a host prefix) or a prefix with no host bits. Width
// and family are the database function's to judge (wide_requires_approval, unsupported), since they depend on the registration
// mode and on what other tenants hold; the field code of a refusal here is `invalid`.
func ParseClaimPrefix(s string) (netip.Prefix, string) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, CodeInvalid
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, CodeInvalid
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.IsValid() || p.Addr().Is4In6() || p != p.Masked() {
		return netip.Prefix{}, CodeInvalid
	}
	return p, ""
}

// PrefixOfAddress is the host prefix of one address: the /32 a `use_my_address` request claims (4.2). An IPv4-mapped IPv6
// address is the same client as its IPv4 form.
func PrefixOfAddress(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen())
}
