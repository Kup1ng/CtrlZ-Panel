package endpoints

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The access list of an Endpoint: Authorized IPs and DDNS hosts (docs/specs/p3-endpoints.md 5, 4.5). Every writer takes the
// lock order of 3.7: the quota lock where a tenant-wide count is decided, the profiles, then the Endpoint's row, then the
// rows. A delete that can take a locked profile away from the identities of the Endpoint goes through the lock passwords of
// 3.3.

// The bounds of spec 3.5 and 3.8.
const (
	// MaxPrefixesPerAdd is how many prefixes one add carries (D31).
	MaxPrefixesPerAdd = 100
	// widestV4 and widestV6 are the shortest masks an authorized prefix may have (D31; spec 3.8): a prefix wider than that
	// would make rule 1 of spec 5 leave a row undeletable from a whole family.
	widestV4 = 16
	widestV6 = 32
	// MaxHostnameBytes is the longest DDNS hostname (DNS allows 253).
	MaxHostnameBytes = 253
)

// ParseAuthorized reads one authorized prefix as typed: an address (a host prefix) or a prefix with no host bits, IPv4 /16 or
// narrower, IPv6 /32 or narrower (spec 3.8). The second result is the field code of a refusal, empty when it is accepted. An
// IPv4-mapped IPv6 address is not an address of either family here: a client reaches us as one or the other.
func ParseAuthorized(s string) (netip.Prefix, string) {
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
	if (p.Addr().Is4() && p.Bits() < widestV4) || (p.Addr().Is6() && p.Bits() < widestV6) {
		return netip.Prefix{}, CodeOutOfRange
	}
	return p, ""
}

// AddAuthorized adds manual prefixes to an Endpoint (spec 5). The request is judged whole: any refused prefix refuses all,
// each field named by its index. The tenant-wide cap of manual rows is decided by the statement that adds them, under the
// quota lock; the Endpoint's row orders the rows' writers. current is the caller's address: the answer marks the row that holds
// it (is_current), as the list does, so a client does not offer to delete the row it is on. Adding a row turns nobody away, so no lock password is asked.
func (e *Env) AddAuthorized(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, endpoint uuid.UUID, cidrs []string, current netip.Addr) ([]store.AuthorizedRow, error) {
	if len(cidrs) == 0 {
		return nil, invalid(Field{"/cidrs", CodeRequired})
	}
	if len(cidrs) > MaxPrefixesPerAdd {
		return nil, invalid(Field{"/cidrs", CodeExceeded})
	}
	var fs []Field
	ps := make([]netip.Prefix, len(cidrs))
	seen := map[netip.Prefix]bool{}
	for i, c := range cidrs {
		p, code := ParseAuthorized(c)
		if code != "" {
			fs = append(fs, Field{fmt.Sprintf("/cidrs/%d", i), code})
			continue
		}
		if seen[p] {
			fs = append(fs, Field{fmt.Sprintf("/cidrs/%d", i), CodeDuplicate})
		}
		seen[p] = true
		ps[i] = p
	}
	if fs != nil {
		return nil, invalid(fs...)
	}
	var out []store.AuthorizedRow
	err := e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		if err := tx.QuotaLock(); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		have, err := tx.AuthorizedExisting(endpoint, ps)
		if err != nil {
			return err
		}
		if len(have) > 0 {
			for _, i := range have {
				fs = append(fs, Field{fmt.Sprintf("/cidrs/%d", i), CodeExists})
			}
			return invalid(fs...)
		}
		ids, won, err := tx.AuthorizedInsert(endpoint, ps)
		switch {
		case isConflict(err):
			return &Error{Kind: KindConflict}
		case err != nil:
			return err
		case !won.Yes():
			return invalid(Field{"max_authorized_ips", CodeExceeded})
		}
		if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
			return err
		}
		out, err = tx.AuthorizedByIDs(endpoint, ids, current)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// deleteRows is the body of every delete of authorized rows of one Endpoint, for the owner's routes and a DDNS host delete:
// rule 1 (a row that holds the caller's address stays), rule 2 (the last row under Require stays, decided by the store
// method) and the lock passwords of 3.3 when Require is on, since the devices that lose the access list then lose their
// filtering. It runs inside Run, after Begin and the Endpoint's lock. field names an id of the request, or none.
func deleteRows(tx store.Tx, g *Guard, endpoint uuid.UUID, ids []uuid.UUID, current netip.Addr, field func(i int) string, extra func() error) error {
	rows, err := tx.AuthorizedLock(endpoint, ids, current)
	if err != nil {
		return err
	}
	if len(rows) != len(ids) {
		return notFound()
	}
	var fs []Field
	for _, r := range rows {
		if r.IsCurrent {
			fs = append(fs, Field{field(slices.Index(ids, r.ID)), CodeCurrentAddress})
		}
	}
	if fs != nil {
		return invalid(fs...)
	}
	before, err := g.Inputs(tx, []uuid.UUID{endpoint})
	if err != nil {
		return err
	}
	won, err := tx.AuthorizedDelete(endpoint, ids)
	if err != nil {
		return err
	}
	if !won.Yes() {
		for i := range ids {
			fs = append(fs, Field{field(i), CodeLastAuthorized})
		}
		return invalid(fs...)
	}
	if extra != nil {
		if err := extra(); err != nil {
			return err
		}
	}
	ep, ok, err := tx.EndpointGet(endpoint)
	if err != nil {
		return err
	}
	if !ok {
		return notFound()
	}
	after, err := g.Inputs(tx, []uuid.UUID{endpoint})
	if err != nil {
		return err
	}
	if ep.RequireAuthorizedIPs && len(ids) > 0 {
		after[endpoint].Away = AwayAll
	}
	if err := g.Check(tx, before, after); err != nil {
		return err
	}
	if len(ids) > 0 {
		return store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID())
	}
	return nil
}

// DeleteAuthorized deletes authorized rows of an Endpoint by id (T-263). The request is all or nothing.
func (e *Env) DeleteAuthorized(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, endpoint uuid.UUID, ids []uuid.UUID, current netip.Addr) error {
	if len(ids) == 0 {
		return invalid(Field{"/ids", CodeRequired})
	}
	if err := checkIDs(ids); err != nil {
		return err
	}
	return e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		if err := g.Begin(tx, []uuid.UUID{endpoint}); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		return deleteRows(tx, g, endpoint, ids, current, func(i int) string { return fmt.Sprintf("/ids/%d", i) }, nil)
	})
}

// SetCleanupOptIn sets cleanup_opt_in of one authorized row (T-265). Turning it on while the Endpoint requires authorized
// IPs hands the row to the P5 cleanup, which deletes it with no password, so it needs the lock passwords like a delete.
// Turning it off, or any change while Require is off, needs none. Nothing of it is compiled, so nothing is marked.
func (e *Env) SetCleanupOptIn(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, endpoint, id uuid.UUID, on bool, current netip.Addr) (store.AuthorizedRow, error) {
	var out store.AuthorizedRow
	err := e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		if err := g.Begin(tx, []uuid.UUID{endpoint}); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		rows, err := tx.AuthorizedByIDs(endpoint, []uuid.UUID{id}, current)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return notFound()
		}
		ep, ok, err := tx.EndpointGet(endpoint)
		if err != nil {
			return err
		}
		if !ok {
			return notFound()
		}
		before, err := g.Inputs(tx, []uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if rows[0].CleanupOptIn != on {
			if err := tx.AuthorizedSetOptIn(endpoint, id, on); err != nil {
				return err
			}
		}
		after, err := g.Inputs(tx, []uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if on && !rows[0].CleanupOptIn && ep.RequireAuthorizedIPs {
			after[endpoint].Away = AwayAll
		}
		if err := g.Check(tx, before, after); err != nil {
			return err
		}
		got, err := tx.AuthorizedByIDs(endpoint, []uuid.UUID{id}, current)
		if err != nil {
			return err
		}
		if len(got) != 1 {
			return notFound()
		}
		out = got[0]
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------
// DDNS hosts.

// CheckDDNSHostname reads a hostname as typed (names.ParseUser, SC 2.2) and returns its canonical text. zone is our own
// resolver zone, which no host may be at or under: a name of ours would let a tenant point its access list at a host we
// serve. The second result is the field code of a refusal.
func CheckDDNSHostname(s, zone string) (string, string) {
	n, err := names.ParseUser(s)
	if err != nil {
		return "", CodeInvalid
	}
	h := n.String()
	if len(h) > MaxHostnameBytes {
		return "", CodeExceeded
	}
	if !strings.Contains(h, ".") {
		return "", CodeInvalid
	}
	if zone != "" {
		z := strings.TrimSuffix(strings.ToLower(zone), ".")
		if h == z || strings.HasSuffix(h, "."+z) {
			return "", CodeInvalid
		}
	}
	return h, ""
}

// CreateDDNSHost adds a DDNS host to an Endpoint (T-225). At most MaxDDNSHostsPerEndpoint, decided by the statement that adds
// it under the Endpoint's row. The worker that resolves the host is P4's; nothing here turns anybody away, so no password.
func (e *Env) CreateDDNSHost(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, endpoint uuid.UUID, hostname string) (store.DDNSHostRow, error) {
	var out store.DDNSHostRow
	err := e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		zone, err := tx.DNSZone()
		if err != nil {
			return err
		}
		h, code := CheckDDNSHostname(hostname, zone)
		if code != "" {
			return invalid(Field{"/hostname", code})
		}
		id, won, err := tx.DDNSHostInsert(endpoint, h)
		switch {
		case isConflict(err):
			return invalid(Field{"/hostname", CodeExists})
		case err != nil:
			return err
		case !won.Yes():
			return invalid(Field{"max_ddns_hosts", CodeExceeded})
		}
		out, _, err = tx.DDNSHostGet(endpoint, id)
		return err
	})
	return out, err
}

// DeleteDDNSHost deletes a host and the rows it learned, under the same Endpoint lock (spec 5): the rows go through the one
// method that deletes authorized rows, so rule 1, rule 2 and the lock passwords bind a host delete like any other deleter,
// and then the host goes. Nothing cascades into authorized_ips from a host.
func (e *Env) DeleteDDNSHost(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, endpoint, host uuid.UUID, current netip.Addr) error {
	return e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		if err := g.Begin(tx, []uuid.UUID{endpoint}); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		if _, ok, err := tx.DDNSHostGet(endpoint, host); err != nil {
			return err
		} else if !ok {
			return notFound()
		}
		ids, err := tx.AuthorizedOfHost(endpoint, host)
		if err != nil {
			return err
		}
		removeHost := func() error {
			ok, err := tx.DDNSHostDelete(endpoint, host)
			if err != nil {
				return err
			}
			if !ok {
				return notFound()
			}
			return nil
		}
		// A host with no learned rows goes through the same path with no ids: nothing is turned away, nothing is marked, and the
		// probe still reaches the check.
		return deleteRows(tx, g, endpoint, ids, current, func(int) string { return "/id" }, removeHost)
	})
}
