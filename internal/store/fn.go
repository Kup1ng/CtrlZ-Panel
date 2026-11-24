package store

import (
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The calls below are the SECURITY DEFINER functions that act for the tenant
// of the transaction. They read the tenant from the setting WithTenant made,
// never from an argument, so a caller cannot pass someone else's id.

// EndpointPair is a tenant's two DNS addresses for one Endpoint.
type EndpointPair struct {
	EndpointID    uuid.UUID
	PrimaryDNSIP  netip.Addr
	FallbackDNSIP netip.Addr
}

const qEndpointPairIPs = `SELECT endpoint_id, primary_dns_ip, fallback_dns_ip FROM ctrlz_fn.endpoint_pair_ips()`

// EndpointPairIPs returns the primary and fallback address of every Endpoint
// of the tenant, without reading node data (R4).
func (t Tx) EndpointPairIPs() ([]EndpointPair, error) {
	rows, err := t.tx.Query(t.ctx, qEndpointPairIPs)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []EndpointPair
	for rows.Next() {
		var p EndpointPair
		if err := rows.Scan(&p.EndpointID, &p.PrimaryDNSIP, &p.FallbackDNSIP); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, p)
	}
	return out, sanitize(rows.Err())
}

const qIPClaimCheck = `SELECT outcome FROM ctrlz_fn.ip_claim_check($1)`

// IPClaimCheck says whether a prefix is available, taken by this tenant
// already ("own"), or unavailable without saying to whom.
func (t Tx) IPClaimCheck(prefix netip.Prefix) (string, error) {
	var out string
	if err := t.tx.QueryRow(t.ctx, qIPClaimCheck, prefix).Scan(&out); err != nil {
		return "", sanitize(err)
	}
	return out, nil
}

// IPClaimResult is the result of IPClaimRequest.
type IPClaimResult struct {
	ClaimID uuid.UUID // the nil uuid when nothing was created
	Outcome string
}

const qIPClaimRequest = `SELECT claim_id, outcome FROM ctrlz_fn.ip_claim_request($1, $2, $3)`

// IPClaimRequest creates a claim for an Endpoint of the tenant. Outcomes:
// active, pending_proof, wide_requires_approval (a pending row is left for an
// admin; also a /28 to /31 that overlaps another tenant's claim, which no proof
// can activate without one), own (the prefix overlaps the tenant's own active or
// grace claim: nothing is written and the claim id is the nil uuid; a route
// answers 422 cidr exists, P3 4.3), not_found, unsupported (IPv6), invalid_source,
// invalid_address (a private, loopback, multicast or reserved range),
// suspended (the tenant has a suspended claim overlapping the prefix; a
// suspension that is still uncommitted is waited for, not missed) and
// quota_exceeded (the tenant already holds as many claims that are not released
// as max_ip_claims allows; nothing is written). The new claim keeps the maximum
// first_grace_at of the tenant's overlapping claims, so releasing and requesting
// again does not earn a second grace.
//
// The function writes no policy_outbox row. A route that gets active from it
// calls MarkDirty for the endpoint_set aggregate in the same transaction: the
// claim changes what the nodes must serve, and the compiler learns of it only
// from that row. (A pending_proof or wide_requires_approval claim is not
// compiled yet, and needs none.)
func (t Tx) IPClaimRequest(endpoint uuid.UUID, prefix netip.Prefix, source string) (IPClaimResult, error) {
	var r IPClaimResult
	var id *uuid.UUID
	if err := t.tx.QueryRow(t.ctx, qIPClaimRequest, endpoint, prefix, source).Scan(&id, &r.Outcome); err != nil {
		return IPClaimResult{}, sanitize(err)
	}
	if id != nil {
		r.ClaimID = *id
	}
	return r, nil
}

const qIPClaimRelease = `SELECT outcome FROM ctrlz_fn.ip_claim_release($1)`

// IPClaimRelease releases the tenant's own claim. A suspended claim is not
// released by its tenant: the outcome is "suspended".
//
// The function writes no policy_outbox row. A route that releases a claim that
// was active or in grace calls MarkDirty for the endpoint_set aggregate in the
// same transaction, or the nodes keep serving the claim it let go of, and the
// next tenant to be given the address shares it with them.
func (t Tx) IPClaimRelease(claim uuid.UUID) (string, error) {
	var out string
	if err := t.tx.QueryRow(t.ctx, qIPClaimRelease, claim).Scan(&out); err != nil {
		return "", sanitize(err)
	}
	return out, nil
}

// Challenge is a proof challenge the tenant opened for one of its claims.
type Challenge struct {
	ID        uuid.UUID
	Label     string // the DNS label to query, under the verify zone
	ExpiresAt time.Time
}

const qIPClaimOpenChallenge = `SELECT challenge_id, label, expires_at FROM ctrlz_fn.ip_claim_open_challenge($1)`

// IPClaimOpenChallenge opens a proof challenge for the tenant's claim. The
// database makes the label and sets the expiry; the caller chooses neither.
// ok is false for a claim that is not the tenant's, or is released or
// suspended, or overlaps another suspended claim of the tenant, or already has
// ten challenges that have not expired.
func (t Tx) IPClaimOpenChallenge(claim uuid.UUID) (c Challenge, ok bool, err error) {
	err = t.tx.QueryRow(t.ctx, qIPClaimOpenChallenge, claim).Scan(&c.ID, &c.Label, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Challenge{}, false, nil
	}
	if err != nil {
		return Challenge{}, false, sanitize(err)
	}
	return c, true, nil
}

const qIPClaimTake = `SELECT outcome FROM ctrlz_fn.ip_claim_take($1, $2, $3)`

// IPClaimTake activates the tenant's claim after proof, applying the takeover
// rule to any overlapping claim of another tenant. The proof is evidence in the
// database, not the caller's word: a challenge the hub marked observed from an
// address inside the claim. A TCP-class observation (tcp, dot, doh, doh3, doq) is
// enough; a udp one also needs code, the TXT answer the node returned, because
// a UDP source address can be spoofed. code is ignored when the evidence does
// not need it; pass "" when there is none. The proof method is recorded from
// the evidence alone.
//
// The transaction's batch id goes with the call: for every tenant whose claim
// is displaced, and for the caller's own, the function writes the endpoint_set
// row of that batch, so the delete for the victim and the put for the taker are
// one config entry. The caller still marks what else it changed.
//
// Outcomes: active, already_active (active and proven), no_proof (no evidence,
// or a wrong or missing code), not_found, suspended (this claim, or another
// claim of the tenant that overlaps it), own (the tenant's own active or grace claim overlaps this one and is never
// displaced; nothing is written and a route answers 422 cidr exists, as for the request), unavailable (another
// tenant's claim, or a race at the exclusion constraint), wide_requires_approval
// (a claim wider than /32 needs an admin's approval in every mode). A wrong
// code is counted in the database and the fifth one consumes the challenge; the
// call returns normally so the count is committed.
func (t Tx) IPClaimTake(claim uuid.UUID, code string) (string, error) {
	var arg any // NULL, not the empty string, for "no code"
	if code != "" {
		arg = code
	}
	var out string
	if err := t.tx.QueryRow(t.ctx, qIPClaimTake, claim, arg, t.batch).Scan(&out); err != nil {
		return "", sanitize(err)
	}
	return out, nil
}

// Announcement is a notice for the tenant.
type Announcement struct {
	ID       uuid.UUID
	Audience string // "all" or "tenant"
	Body     string
	StartsAt time.Time
	EndsAt   *time.Time
}

const qAnnouncements = `SELECT id, audience, body, starts_at, ends_at FROM ctrlz_fn.announcements_for_tenant()`

// Announcements returns the notices that are live now and addressed to
// everybody or to this tenant. The table itself is not readable by the tenant
// role: a notice for one tenant must not be visible to another.
func (t Tx) Announcements() ([]Announcement, error) {
	rows, err := t.tx.Query(t.ctx, qAnnouncements)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []Announcement
	for rows.Next() {
		var a Announcement
		if err := rows.Scan(&a.ID, &a.Audience, &a.Body, &a.StartsAt, &a.EndsAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, a)
	}
	return out, sanitize(rows.Err())
}

// AggregateType says what a policy_outbox row asks the compiler to rebuild.
type AggregateType string

// The two aggregates of the outbox.
const (
	// AggregateProfile rebuilds one profile. aggregate_id is the profile id.
	AggregateProfile AggregateType = "profile"
	// AggregateEndpointSet rebuilds the tenant's Endpoint records and emits the
	// changed ones. aggregate_id is the tenant id.
	AggregateEndpointSet AggregateType = "endpoint_set"
)

const qMarkDirty = `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING`

// MarkDirty records, in the same transaction as the change, that an aggregate
// must be recompiled. A rule write makes one row per profile, not per rule,
// because of the unique key and ON CONFLICT DO NOTHING. Lock changes make no
// row at all: they are not compiled.
//
// A route that deletes a profile marks the profile and also the tenant's
// endpoint_set, in the same transaction. The database changes client stacks on
// its own when a profile goes (the promote_profile2 trigger moves Profile 2 up,
// and the foreign keys clear a deleted one) and writes no outbox row for it, so
// without the second mark the nodes keep a client record that names the dead
// profile.
func MarkDirty(tx Tx, agg AggregateType, aggregateID uuid.UUID) error {
	if _, err := tx.tx.Exec(tx.ctx, qMarkDirty, tx.tenant, string(agg), aggregateID, tx.batch); err != nil {
		return sanitize(err)
	}
	return nil
}

const qPhoneChangeComplete = `SELECT outcome FROM ctrlz_fn.auth_phone_change_complete($1)`

// PhoneChangeComplete finishes a phone change request (T-110). The tenant role
// cannot write the phone column, so this is the only path. The database checks
// that both OTPs were consumed after the request was made, for the right
// numbers and purposes, in the last ten minutes. Outcomes: ok, invalid (a
// missing, finished, expired or foreign request, or a code that does not count)
// and unavailable (the new number belongs to someone else).
func (t Tx) PhoneChangeComplete(request uuid.UUID) (string, error) {
	var out string
	if err := t.tx.QueryRow(t.ctx, qPhoneChangeComplete, request).Scan(&out); err != nil {
		return "", sanitize(err)
	}
	return out, nil
}

const qPhoneMarkVerified = `SELECT outcome FROM ctrlz_fn.auth_phone_mark_verified($1, $2)`

// PhoneMarkVerified sets phone_verified_at of a user an admin made, from the OTP
// that just logged them in or reset their password. The code must be a consumed login
// or reset code for the phone the locked row has NOW, verified or not (db-r6-7), so a code
// for a number the user has since left proves nothing. The outcome is ok (the phone is
// verified now, or already was), stale (the code is for this phone but too old to mark it
// verified) or invalid (not this phone's code, or no such user).
func (t Tx) PhoneMarkVerified(user, otp uuid.UUID) (string, error) {
	var out string
	if err := t.tx.QueryRow(t.ctx, qPhoneMarkVerified, user, otp).Scan(&out); err != nil {
		return "", sanitize(err)
	}
	return out, nil
}

const qTicketsRevoke = `SELECT 1 FROM ctrlz_fn.auth_tickets_revoke($1)`

// TicketsRevoke closes the user's open mfa and reset tickets. Every credential
// change calls it, so a ticket does not outlive the credential it was issued
// against. The admin's re-issue of a one-time password calls it too.
func (t Tx) TicketsRevoke(user uuid.UUID) error {
	var n int
	return sanitize(t.tx.QueryRow(t.ctx, qTicketsRevoke, user).Scan(&n))
}

const qUserFlags = `SELECT has_password FROM ctrlz_fn.auth_user_flags($1)`

// UserFlags says whether the user has a password, without loading the hash.
// found is false for a user of another tenant.
func (t Tx) UserFlags(user uuid.UUID) (hasPassword, found bool, err error) {
	err = t.tx.QueryRow(t.ctx, qUserFlags, user).Scan(&hasPassword)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, sanitize(err)
	}
	return hasPassword, true, nil
}

// TicketPut stores a login ticket on the transaction's own connection and returns its id
// (AuthLookups.TicketPut is the same statement for a caller with no transaction). The
// mfa ticket of a login is put here, while the user row is locked, so a re-issue of a
// one-time password or a password change cannot slip in between the check and the
// ticket; and so that a ticket is not left alive when the transaction rolls back (rule
// one-connection-per-request: the second connection this used to take is gone). A ticket
// of another tenant than the transaction's is refused.
func (t Tx) TicketPut(n NewTicket) (uuid.UUID, bool, error) {
	if n.Tenant != uuid.Nil && n.Tenant != t.tenant {
		return uuid.Nil, false, ErrConstraint
	}
	args, err := n.args()
	if err != nil {
		return uuid.Nil, false, err
	}
	var id uuid.UUID
	err = t.tx.QueryRow(t.ctx, qTicketPut, args...).Scan(&id)
	ok, err := notFound(err)
	return id, ok, err
}

// TicketTake spends a ticket inside the transaction. Of two requests with one ticket
// exactly one wins, as for AuthLookups.TicketTake (the row lock of the UPDATE makes the
// second wait for the first to end and then lose), and the spend commits or rolls back
// with the rest of the transaction: a request that fails after the check no longer burns
// the ticket (tenant-r1-1, tenant-r1-7). A ticket whose subject is another tenant's is
// refused, and the transaction ends with it.
func (t Tx) TicketTake(hash []byte, kind TicketKind) (Ticket, Won, error) {
	tk, err := scanTicket(t.tx.QueryRow(t.ctx, qTicketTake, hash, string(kind)))
	w, err := wonRow(err)
	if err != nil || !w.Yes() {
		return Ticket{}, w, sanitize(err)
	}
	if tk.Tenant != uuid.Nil && tk.Tenant != t.tenant {
		return Ticket{}, Won{}, ErrConstraint
	}
	return tk, w, nil
}

// The three helpers below are the only places the store hands an address to the database driver as a statement
// parameter or a scan target (the network-cut lint, rule 6, lists this file and no other store file for that). The
// driver takes `any`, which is where an address would be rendered as a string and cut by hand, so every other store
// file passes the result of one of these, an opaque value, and never the address itself (tenant-r16-17).

// addrArg binds an address as inet, and an invalid one as NULL. An IPv4-mapped IPv6 address is the same client as
// its IPv4 form.
func addrArg(ip netip.Addr) any {
	if !ip.IsValid() {
		return nil
	}
	return ip.Unmap()
}

// scanAddr is the scan target of a nullable inet column held in a *netip.Addr.
func scanAddr(dst **netip.Addr) any { return dst }

// scanPrefixes is the scan target of an inet[] column.
func scanPrefixes(dst *[]netip.Prefix) any { return dst }
