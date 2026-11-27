package periodic

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

// The DDNS pass (T-091, docs/specs/p4-nodes.md 8, P3 4.5). For each host of an Endpoint with authorize_ddns it resolves A and
// AAAA, keeps the public answers, and makes the host's authorized rows equal to them.
//
// What it will not do. A failed or empty lookup changes nothing (an outage of the resolver must not delete a tenant's
// addresses). A host with more than ddnsMaxAddrs public answers changes nothing and alerts (a name that rotates through a
// pool is not an address of one person's router). An address of the injected block-page range is counted and alerts, and
// like any other non-public answer it is never written. It does not touch an Endpoint whose authorize_ddns went off after the
// pass read it: the flag is read again under the Endpoint's row.

// ddnsMaxAddrs is the most public addresses one host may resolve to (D31).
const ddnsMaxAddrs = 20

// ddnsStale is how long a host may go without a usable answer before an alert (D31).
const ddnsStale = 24 * time.Hour

// lookupParallel bounds the lookups of one tenant that run at once.
const lookupParallel = 4

// ddnsTenantBudget is how long one tenant's lookups may take in all. A tenant whose names never answer (each costs the full
// lookup timeout) would otherwise hold the pass for minutes and starve every tenant after it. A host the budget did not reach
// was not asked, so it is neither answered nor failed: the next pass starts its lookups where this one stopped, so a long list is worked
// through over several passes and its tail is not the part that is always cut (J12-r2-5).
const ddnsTenantBudget = 30 * time.Second

type unit string

const unitLookup unit = "ddns_lookup"

func (u unit) Valid() bool { return u == unitLookup }

// answer is the outcome of one host's lookup.
type answer struct {
	addrs []netip.Addr
	err   error
	// skipped is a host the tenant's budget ended before it was answered. It changes nothing and records nothing: it was not
	// asked, which is not a failure of the name.
	skipped bool
}

// lookupAll resolves the hosts of the tenant, a few at a time, starting at index start and wrapping round. A lookup that panics
// is a failed one. When ctx ends first, the hosts not yet asked, and those it cut short, are skipped; next is where the following
// pass should start (0 when every host was answered), so the hosts the budget keeps reaching late are first next time.
func (r *Runner) lookupAll(ctx context.Context, work []store.DDNSWork, start int) (out []answer, next int) {
	n := len(work)
	out = make([]answer, n)
	for i := range out {
		out[i] = answer{err: errLookup, skipped: true}
	}
	if n == 0 {
		return out, 0
	}
	start = ((start % n) + n) % n
	sem := make(chan struct{}, lookupParallel)
	var wg sync.WaitGroup
	for k := 0; k < n; k++ {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		i := (start + k) % n
		wg.Add(1)
		safego.Go(r.log, unitLookup, func() {
			defer func() { <-sem; wg.Done() }()
			out[i] = answer{err: errLookup} // what stays if the lookup panics
			a, err := r.resolver.Lookup(ctx, work[i].Hostname)
			if err != nil && ctx.Err() != nil {
				out[i] = answer{err: errLookup, skipped: true} // cut short by the budget: not the name's failure
				return
			}
			out[i] = answer{addrs: a, err: err}
		})
	}
	wg.Wait()
	// A lookup that panicked stays a failure of the name; the first skipped host is where the next pass begins.
	for k := 0; k < n; k++ {
		if i := (start + k) % n; out[i].skipped && ctx.Err() != nil {
			return out, i
		}
	}
	return out, 0
}

// classify keeps the public addresses of an answer, once each and in order, and counts the injected ones. The block page that
// some networks inject for a filtered name sits in the private range 10.10.34.0/24; it says the name is filtered where the
// worker runs, not where the tenant's router is, so it is never written.
func classify(addrs []netip.Addr) (public []netip.Addr, injected int) {
	for _, a := range addrs {
		a = a.Unmap()
		switch netclass.ClassOf(a) {
		case netclass.Public:
			public = append(public, a)
		case netclass.Injected:
			injected++
		}
	}
	slices.SortFunc(public, netip.Addr.Compare)
	return slices.Compact(public), injected
}

// DDNS runs one pass over the tenants. A pass that runs out of its time resumes after its last tenant next time, so a large
// install is worked through over several passes and no tenant is always the one left out.
func (r *Runner) DDNS(ctx context.Context) error {
	if r.resolver == nil {
		return nil
	}
	r.mu.Lock()
	after := r.ddnsAfter
	r.mu.Unlock()
	last, complete, err := r.walkTenants(ctx, after, r.ddnsTenant)
	r.mu.Lock()
	if complete {
		r.ddnsAfter = uuid.Nil
	} else {
		r.ddnsAfter = last
	}
	r.mu.Unlock()
	return err
}

// hostAlertSpec is an alert a tenant's pass wants raised once its transactions are done.
type hostAlertSpec struct {
	reason   Reason
	endpoint uuid.UUID
	host     uuid.UUID
}

// ddnsWriteMargin is the time a tenant's writes are given after its lookups: a tenant is begun only when the pass has its whole
// lookup budget and this left, so a pass that ends does so between tenants and not inside one (J12-r3-5).
const ddnsWriteMargin = 10 * time.Second

// errOutOfTime says a pass has too little time left to begin another tenant. It is not a failure of the job.
var errOutOfTime = errors.New("periodic: the pass is out of time")

// hasRoom says whether ctx has time for one more tenant.
func hasRoom(ctx context.Context, need time.Duration) bool {
	dl, ok := ctx.Deadline()
	return !ok || time.Until(dl) >= need
}

func (r *Runner) ddnsTenant(ctx context.Context, tenant uuid.UUID) error {
	if !hasRoom(ctx, r.tenantBudget+ddnsWriteMargin) {
		return errOutOfTime
	}
	var work []store.DDNSWork
	if err := r.db.WithTenant(ctx, tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
		work, err = tx.DDNSWork()
		return err
	}); err != nil {
		return err
	}
	if len(work) == 0 {
		return nil
	}
	r.mu.Lock()
	start := r.ddnsStart[tenant]
	r.mu.Unlock()
	lctx, cancel := context.WithTimeout(ctx, r.tenantBudget)
	answers, next := r.lookupAll(lctx, work, start)
	cancel()
	var alerts []hostAlertSpec
	var errs []error
	// The work is in Endpoint order: one transaction per Endpoint, under its row.
	for lo := 0; lo < len(work); {
		hi := lo
		for hi < len(work) && work[hi].Endpoint == work[lo].Endpoint {
			hi++
		}
		a, err := r.ddnsEndpoint(ctx, tenant, work[lo:hi], answers[lo:hi])
		alerts = append(alerts, a...)
		if err != nil {
			errs = append(errs, err)
		}
		lo = hi
	}
	// Where the next pass starts its lookups is kept only once this pass's answers are written: a pass cut short before its
	// writes has used nothing of them, and the hosts it asked would otherwise not be asked again for a round (J12-r3-5).
	if ctx.Err() == nil {
		r.mu.Lock()
		if next == 0 {
			delete(r.ddnsStart, tenant)
		} else {
			r.ddnsStart[tenant] = next
		}
		r.mu.Unlock()
	}
	// One open alert of a reason per tenant: the Endpoint and host in its params are the first that raised it. A tenant makes
	// hosts at will and a name it controls decides these answers, so a key per host would let it fill the admin list.
	raised := map[Reason]bool{}
	for _, a := range alerts {
		if raised[a.reason] {
			continue
		}
		raised[a.reason] = true
		params, err := closed.NewParams(hostAlert{Reason: a.reason, Tenant: tenant, Endpoint: a.endpoint, Host: a.host})
		if err != nil {
			continue
		}
		r.raise(ctx, "warning", closed.NewKey(a.reason, closed.ID(tenant)), params)
	}
	return errors.Join(errs...)
}

// ddnsEndpoint applies the answers of one Endpoint's hosts in one transaction. The Endpoint's row is taken first, which is
// what keeps the pass from deadlocking with a claim route and an authorized delete on the same Endpoint (P3 3.7 step 5).
func (r *Runner) ddnsEndpoint(ctx context.Context, tenant uuid.UUID, hosts []store.DDNSWork, answers []answer) ([]hostAlertSpec, error) {
	var alerts []hostAlertSpec
	ep := hosts[0].Endpoint
	err := r.db.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		alerts = alerts[:0] // a retried transaction starts over
		found, err := tx.EndpointsLock([]uuid.UUID{ep})
		if err != nil || len(found) != 1 {
			return err
		}
		flags, ok, err := tx.DDNSFlags(ep)
		if err != nil || !ok || !flags.Authorize {
			return err
		}
		// The hosts the Endpoint has now: one the tenant deleted since the work was read is skipped (J12-r1-5).
		current, err := tx.DDNSHostIDs(ep)
		if err != nil {
			return err
		}
		changed, waiting := false, false
		for i, h := range hosts {
			if answers[i].skipped || !slices.Contains(current, h.Host) {
				continue
			}
			c, d, a, err := r.ddnsHost(tx, tenant, flags, h, answers[i])
			if err != nil {
				return err
			}
			changed = changed || c
			waiting = waiting || d
			alerts = append(alerts, a...)
		}
		// The claims of an address no host answers with any more go, once every host's answer is in last_ips. Not while an
		// address waits for claim budget: the host keeps its last claim until the new one is in (P3 4.5), and the pass that
		// gets it in releases the old one. The rows of the host's old address are deleted above, so this is what makes the
		// claim follow the row (J12-r3-4).
		if !waiting {
			n, err := tx.DDNSClaimsRelease(ep)
			if err != nil {
				return err
			}
			changed = changed || n > 0
		}
		if changed {
			// The authorized prefixes and the claims of the Endpoint are in its record.
			return store.MarkDirty(tx, store.AggregateEndpointSet, tenant)
		}
		return nil
	})
	return alerts, err
}

// ddnsHost makes one host's rows equal to its public answers. It says whether it changed what the nodes serve.
func (r *Runner) ddnsHost(tx store.Tx, tenant uuid.UUID, flags store.DDNSFlags, h store.DDNSWork, a answer) (changed, deferred bool, alerts []hostAlertSpec, err error) {
	// deferred is set below when an address waits for claim budget: its host then keeps the claims it has.
	ep := h.Endpoint
	spec := func(reason Reason) hostAlertSpec { return hostAlertSpec{reason: reason, endpoint: ep, host: h.Host} }
	fail := func(why store.DDNSFailure) (bool, bool, []hostAlertSpec, error) {
		if err := tx.DDNSRecordFailed(ep, h.Host, why); err != nil {
			return false, false, nil, err
		}
		since := h.CreatedAt
		if h.LastResolvedAt != nil {
			since = *h.LastResolvedAt
		}
		if why == store.DDNSTooMany {
			return false, false, []hostAlertSpec{spec(ReasonDDNSMany)}, nil
		}
		if appclock.Now().Sub(since) > ddnsStale {
			return false, false, []hostAlertSpec{spec(ReasonDDNSStale)}, nil
		}
		return false, false, nil, nil
	}

	if a.err != nil {
		return fail(store.DDNSLookup)
	}
	if len(a.addrs) == 0 {
		return fail(store.DDNSEmpty)
	}
	public, injected := classify(a.addrs)
	if injected > 0 {
		alerts = append(alerts, spec(ReasonDDNSInject))
	}
	if len(public) == 0 {
		c, d, more, err := fail(noPublicFailure(r.resolver))
		return c, d, append(alerts, more...), err
	}
	if len(public) > ddnsMaxAddrs {
		c, d, more, err := fail(store.DDNSTooMany)
		return c, d, append(alerts, more...), err
	}

	texts := make([]string, len(public))
	for i, p := range public {
		texts[i] = p.String()
	}
	quota := false // a new address went without its claim only because the tenant is at its quota
	// last_ips is what the claim rule reads as "the host kept answering with this address", so an address enters it only once
	// its claim question is settled: asked for, covered, or not wanted. One that waits for budget or went unasked at the quota
	// stays out, or its old released row (the worker's own release when the address left) would read as the tenant's release
	// and the claim would never be asked for again (J12-r4-1).
	kept := make([]string, 0, len(public))
	for _, p := range public {
		prefix := endpoints.PrefixOfAddress(p)
		needClaim, unasked := false, false
		if flags.LegacyDNS && p.Is4() {
			// A Plain DNS claim is asked for when none was asked for before and the request could succeed, whether or not
			// the row is new: an address learned from a secure DNS query is authorized and has no claim (J12-r1-15). A
			// claim the tenant released or the database refuses (suspended, quota, own) is not asked for again and costs no
			// budget, so a refusal never holds back another address (J12-r2-3, r2-4). A new claim is charged to the tenant's
			// ip-claim budget; when it has no room the address waits for the next pass, and the rows of its family that it
			// would have replaced stay (the host keeps its last claim).
			var atQuota bool
			needClaim, atQuota, err = tx.DDNSClaimWanted(ep, p.String())
			if err != nil {
				return false, false, nil, err
			}
			quota = quota || atQuota
			unasked = atQuota
			if needClaim && !r.allowClaim(tx.Context(), tenant) {
				deferred = true
				continue
			}
		}
		wrote, err := tx.DDNSInsert(ep, h.Host, p.String())
		if err != nil {
			return false, false, nil, err
		}
		changed = changed || wrote
		if needClaim {
			// The outcome is the claim's own business: a pending proof waits for the tenant, and a refusal (suspended,
			// quota) leaves the address an authorized one with no Plain DNS claim. An active claim is in the Endpoint's
			// record, which the caller marks.
			res, err := tx.IPClaimRequest(ep, prefix, "ddns")
			if err != nil {
				return false, false, nil, err
			}
			changed = changed || res.Outcome == "active"
			unasked = res.Outcome == "quota_exceeded" // the quota filled between the read ahead and the request
		}
		if !unasked {
			kept = append(kept, p.String())
		}
	}
	stale, err := tx.DDNSStale(ep, h.Host, texts)
	if err != nil {
		return false, false, nil, err
	}
	// While a claim waits for budget the host keeps the IPv4 rows it has (it holds its last claim), but never more than the
	// cap in all, so a name that rotates through addresses cannot grow the table: the newest rows stay (J12-r1-9).
	room := ddnsMaxAddrs - len(public)
	var drop []uuid.UUID
	for i := len(stale) - 1; i >= 0; i-- {
		if deferred && stale[i].IsIPv4 && room > 0 {
			room--
			continue
		}
		drop = append(drop, stale[i].ID)
	}
	if len(drop) > 0 {
		// The one delete method: it refuses the last row of an Endpoint that requires authorized addresses. The new rows
		// went in first, so it refuses only when the host's answer was entirely rows the Endpoint already held from another
		// source.
		w, err := tx.AuthorizedDelete(ep, drop)
		if err != nil {
			return false, false, nil, err
		}
		if w.Yes() {
			changed = true
		}
	}
	// A tenant at its quota gets its addresses and no claim for the new one; the code says why, and clears when a pass finds
	// nothing in the way (J12-r3-4).
	var note store.DDNSFailure
	if quota {
		note = store.DDNSClaimQuota
	}
	if err := tx.DDNSRecordOK(ep, h.Host, kept, note); err != nil {
		return false, false, nil, err
	}
	return changed, deferred, alerts, nil
}

// noPublicFailure is what a host is recorded as when its answer held no public address. A resolver that reads the machine's own
// sources (HostLocal) may have answered with the address of a panel service, so it says no_address like a name that does not
// exist; a tenant must not tell the two apart by reading last_error (J12-r1-18).
func noPublicFailure(res Resolver) store.DDNSFailure {
	if hl, ok := res.(interface{ HostLocal() bool }); ok && hl.HostLocal() {
		return store.DDNSEmpty
	}
	return store.DDNSNoPublic
}

// allowClaim charges the tenant's ip-claim class. A budget that cannot answer refuses: the claim waits for the next pass.
func (r *Runner) allowClaim(ctx context.Context, tenant uuid.UUID) bool {
	if r.claims == nil {
		return true
	}
	ok, err := r.claims.Allow(ctx, tenant)
	if err != nil {
		r.log.Warn("ddns claim budget failed", logattr.Enum("error_class", errClass(err)))
		return false
	}
	return ok
}
