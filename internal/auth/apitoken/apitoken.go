// Package apitoken is the lookup half of the API token path (docs/specs/p3-endpoints.md 6.3): it turns the text of an
// Authorization header into a token's tenant and user, and applies the gates that belong to the token and not to the operation.
//
// It knows nothing of HTTP statuses and nothing of the rate classes. The pipeline (internal/httpx) asks Screen first, which
// costs one MAC and no I/O, charges the budgets of the token it names, and only then asks Lookup, which is one SECURITY DEFINER
// call (ctrlz_fn.auth_token_by_hash). The two are separate so that a value that was never issued here, or that has expired, is
// refused for the price of the MAC and charges nothing.
package apitoken

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Prefix is what an API token starts with when it is shown (6.2): a string a secret scanner can find. The value itself is
// bearer.Len characters after it.
const Prefix = "ctz_"

// Shown is the text of a token as its owner copies it.
func Shown(value string) string { return Prefix + value }

// Value strips the prefix. ok is false for text that does not start with it, which is no token of ours.
func Value(credential string) (string, bool) {
	v, ok := strings.CutPrefix(credential, Prefix)
	return v, ok
}

// The refusals of Lookup. Each is what the request is answered with, and none carries the value or a row.
var (
	// ErrInvalid is the token that does not exist, was revoked, or whose tenant is in a state that ends every session (401).
	ErrInvalid = errors.New("apitoken: not a live token")
	// ErrSuspended is a live token of a suspended tenant (403 account_suspended).
	ErrSuspended = errors.New("apitoken: the tenant is suspended")
	// ErrIPNotAllowed is a live token used from an address outside its list (403 token_ip_not_allowed).
	ErrIPNotAllowed = errors.New("apitoken: the address is outside the token's allowed list")
	// ErrReadOnly is a read token on an operation that writes (403 token_read_only).
	ErrReadOnly = errors.New("apitoken: a read token cannot write")
)

// Lookups is the one read the path needs: the row of a token by the hash of its value. store.AuthLookups is the production one; a
// test passes its own.
type Lookups interface {
	TokenByHash(ctx context.Context, hash []byte) (store.TokenInfo, bool, error)
}

// Resolver screens and looks up tokens.
type Resolver struct {
	Signer *bearer.Signer
	Auth   Lookups
}

// Screen checks the shape, the tag and the expiry of the credential (the text after "Bearer ") with no I/O, and returns the id
// of the row it was issued with. ok is false for anything this service did not issue as an API token, and for one past its expiry.
func (r Resolver) Screen(credential string) (uuid.UUID, bool) {
	v, ok := Value(credential)
	if !ok {
		return uuid.Nil, false
	}
	b, ok := r.Signer.Screen(bearer.APIToken, v)
	if !ok {
		return uuid.Nil, false
	}
	return b.ID, true
}

// Info is a token that passed every gate.
type Info struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	TokenID  uuid.UUID
	// Kind is "read" or "write".
	Kind string
}

// Outcome is what Lookup learned besides the gates.
type Outcome struct {
	// Live says the row exists and was not revoked, whatever a later gate decided: the pipeline gives back the miss charge of a
	// live token (6.3 step 4).
	Live bool
	// Dead says the value is gone for good (no row, or revoked): the pipeline remembers it and refuses it with no lookup.
	Dead bool
}

// Lookup finds the token of a credential that Screen passed and applies the gates of 6.3 step 4 in order: the tenant's status,
// the client address against allowed_ips, and a read token against an operation that writes. client is the address the request
// came from (the pipeline's, never a header of the request).
func (r Resolver) Lookup(ctx context.Context, credential string, client netip.Addr, writes bool) (Info, Outcome, error) {
	v, ok := Value(credential)
	if !ok {
		return Info{}, Outcome{Dead: true}, ErrInvalid
	}
	row, found, err := r.Auth.TokenByHash(ctx, bearer.Hash(v))
	if err != nil {
		return Info{}, Outcome{}, err
	}
	if !found || row.RevokedAt != nil {
		return Info{}, Outcome{Dead: true}, ErrInvalid
	}
	out := Outcome{Live: true}
	switch row.TenantStatus {
	case "active":
	case "suspended":
		return Info{}, out, ErrSuspended
	default:
		// "deleting" and any status this switch does not know: an allow list that fails closed, as the session gate is.
		return Info{}, out, ErrInvalid
	}
	if len(row.AllowedIPs) > 0 && !within(row.AllowedIPs, client) {
		return Info{}, out, ErrIPNotAllowed
	}
	if writes && row.Kind != "write" {
		return Info{}, out, ErrReadOnly
	}
	return Info{TenantID: row.TenantID, UserID: row.UserID, TokenID: row.TokenID, Kind: row.Kind}, out, nil
}

// within says the address is inside one of the prefixes. An IPv4-mapped address is compared as the IPv4 address it is.
func within(list []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// MaxAllowed is how many addresses or subnets one token may be limited to (D31, spec 3.8).
const MaxAllowed = 32

// ParseAllowed reads one entry of a token's allowed list: an address, or a subnet with no host bits. An IPv4-mapped IPv6 address and
// an address with a zone are refused, so the list means one thing to every reader.
func ParseAllowed(s string) (netip.Prefix, bool) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || a.Is4In6() {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() || p != p.Masked() {
		return netip.Prefix{}, false
	}
	return p, true
}
