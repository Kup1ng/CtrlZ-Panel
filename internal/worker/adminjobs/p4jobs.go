package adminjobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The three jobs of P4 (docs/specs/p4-nodes.md 8): pair_change, domain_change and node_revoked.
//
// Each is a function of state and not of the change that queued it. A newer change ends an unfinished job of its kind
// (migration 0028) and queues its own, and the new job walks every tenant again from the first, so what the old one did
// before it was ended is either what the new one would do too (a bump that is repeated only makes the records be written
// again) or is keyed by the state it announced (a notice that carries a hash of the addresses, the zones or the nodes, held
// once by a unique index, migration 0101). That is why none of them keeps a cursor, and why a worker that dies in the middle
// leaves nothing to repair.

// Job kinds of P4 (the CHECK of admin_jobs.kind after migration 0100).
const (
	KindPairChange   = "pair_change"
	KindDomainChange = "domain_change"
	KindNodeRevoked  = "node_revoked"
)

// Notification kinds the three jobs write to a tenant. The texts are in packages/i18n (bell.kinds).
const (
	notifyPairChanged      = "pair_changed"
	notifyDomainChanged    = "domain_changed"
	notifyAuthorizedReview = "authorized_review"
)

// noticeKey is the dedupe key of a notice: the hash of the state it announces, never the state itself. The parts are
// joined with a byte that no part can hold, so two different states cannot make the same text.
func noticeKey(kind string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(kind))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// pair_change (T-023, SC 8a.11 L7)

// PairProgress is the progress of a pair change.
type PairProgress struct {
	Tenants  int `json:"tenants"`
	Bumped   int `json:"endpoints_bumped"`
	Notified int `json:"tenants_notified"`
	// Pair is the hash of the two addresses the job began with and Epoch the job that first announced that pair; the next job
	// reads them (store.PairEpochBefore).
	Pair  string `json:"pair,omitempty"`
	Epoch string `json:"epoch,omitempty"`
}

func pairHash(a store.PairAddresses) string {
	return noticeKey("pair", a.Primary.String(), a.Fallback.String())
}

// epochOf is the epoch of the pair a tenant's transaction read. A pair that moved while the job walked is not the one the job
// began with: it has no epoch to inherit, and the job that its change queues will walk the tenants again.
func epochOf(a store.PairAddresses, prog PairProgress) string {
	if pairHash(a) == prog.Pair {
		return prog.Epoch
	}
	return "moved"
}

// pairChange raises pair_version of every Endpoint, marks the tenant's Endpoint records dirty, and tells each tenant that
// holds a Plain DNS claim which two addresses the global pair has now. The addresses are read inside each tenant's own
// transaction, so a change that lands while the job walks is seen by the tenants after it, and the job that change queues
// walks the tenants before it.
//
// Why a repeat notifies nobody twice, and a move back does tell: the notice is keyed by the two addresses and by the epoch of
// that pair. The epoch is the job that first announced the pair: a later job that finds the same pair announced by the job
// before it (a run again, or a job that supersedes a half-done one) keeps that epoch, and the unique index holds one notice per
// tenant and key; a job that finds a different pair than the one before it starts a new epoch, so a return to an earlier pair
// (A to B and then A again), which a tenant must act on, is told again. The pair and its epoch are in the job's progress, which
// is written before the first tenant is read. A repeat bump is not a harm; it only makes the compiler write the records again
// (spec 8).
func (r *Runner) pairChange(ctx context.Context, j store.AdminJob, report Report) (any, error) {
	var prog PairProgress
	// What the pair is now and whose epoch it is, recorded before the first notice goes out.
	var start store.PairAddresses
	var haveStart bool
	if err := r.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
		if start, haveStart, err = g.GlobalPairAddresses(); err != nil || !haveStart {
			return err
		}
		prev, epoch, ok, err := g.PairEpochBefore(j.ID, j.CreatedAt)
		if err != nil {
			return err
		}
		prog.Pair = pairHash(start)
		prog.Epoch = j.ID.String()
		if ok && prev == prog.Pair {
			prog.Epoch = epoch
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if haveStart {
		report(prog)
	}
	_, _, err := r.forEachTenantWith(ctx, store.TxOpts{}, walk{SkipRetry: true}, func(tx store.Tx) error {
		held, err := tx.AdminJobHold(j.ID)
		if err != nil {
			return err
		}
		if !held {
			return errSuperseded
		}
		// The notice goes first: notifications rank below endpoints, and a statement may not take a lock under one the
		// transaction holds (internal/lockrank).
		notified := false
		if addrs, ok, err := tx.GlobalPairAddresses(); err != nil {
			return err
		} else if ok {
			claim, err := tx.HasServingClaim()
			if err != nil {
				return err
			}
			if claim {
				notified, err = tx.NoticeOnce(notifyPairChanged, "warning",
					noticeKey(notifyPairChanged, addrs.Primary.String(), addrs.Fallback.String(), epochOf(addrs, prog)),
					mustJSON(map[string]string{"primary": addrs.Primary.String(), "fallback": addrs.Fallback.String()}))
				if err != nil {
					return err
				}
			}
		}
		n, err := tx.EndpointsBumpPairVersion()
		if err != nil {
			return err
		}
		if n > 0 {
			// The Endpoint records carry pair_version, so the compiler must write them again (the mark is the tenant's).
			if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
				return err
			}
		}
		// A transaction that fails here is run again whole, so the counts are added at the very end.
		prog.Bumped += n
		if notified {
			prog.Notified++
		}
		return nil
	}, func(done int) {
		prog.Tenants = done
		report(prog)
	})
	if err != nil {
		return nil, err
	}
	return prog, nil
}

// ---------------------------------------------------------------------------
// domain_change (T-345)

// DomainProgress is the progress of a domain change.
type DomainProgress struct {
	Tenants  int `json:"tenants"`
	Notified int `json:"tenants_notified"`
	// Passes is how many times the walk began: more than one means the state moved while it ran.
	Passes int `json:"passes"`
}

// maxDomainPasses bounds the restarts of one run. The state moves only when an admin changes the domain or the hub issues
// a new zone CA, each rare and each far apart; a run that is still chasing it after this many gives up and the runner tries
// it again after its backoff.
const maxDomainPasses = 5

var errDomainUnsettled = errors.New("adminjobs: the zone state kept moving")

// uploadCovers says whether any one uploaded certificate covers the zone. The rule is certcheck.CoversZone, the one the
// upload check and the hub's choice of a wildcard (4.3) use; a notice that is wrong by a name is harmless, but there is no
// reason for a second reading of it.
func uploadCovers(certs [][]string, zone string) bool {
	for _, sans := range certs {
		if certcheck.CoversZone(sans, zone) {
			return true
		}
	}
	return false
}

// zoneKey is what the notice of one domain state is keyed by: the live zones and the start of the active zone CA row (4.3).
func zoneKey(z store.ZoneState) string {
	nb := ""
	if !z.CANotBefore.IsZero() {
		nb = z.CANotBefore.UTC().Format(time.RFC3339Nano)
	}
	return noticeKey(notifyDomainChanged, z.Zone, z.Prev, nb)
}

// domainChange tells each tenant the domain changed. A tenant reads the state inside its own transaction and the notice is
// keyed by that state; when the state at the end of a pass is not the one the pass began with (a zone CA was issued while
// it ran, whose job met this one in the table and queued nothing, 4.3), the walk starts again from the first tenant, and the
// tenants it already told for the earlier state are told once more only for the new one.
func (r *Runner) domainChange(ctx context.Context, j store.AdminJob, report Report) (any, error) {
	var prog DomainProgress
	for prog.Passes < maxDomainPasses {
		prog.Passes++
		begin, err := r.zoneState(ctx)
		if err != nil {
			return nil, err
		}
		prog.Tenants, prog.Notified = 0, 0
		_, _, err = r.forEachTenantWith(ctx, store.TxOpts{}, walk{SkipRetry: true}, func(tx store.Tx) error {
			held, err := tx.AdminJobHold(j.ID)
			if err != nil {
				return err
			}
			if !held {
				return errSuperseded
			}
			z, err := tx.ZoneState()
			if err != nil {
				return err
			}
			if z.Zone == "" {
				return nil // no domain is set: there is nothing to tell
			}
			// The line is for a private-CA user, who has the zone CA installed: no uploaded certificate covers the new zone.
			reinstall := "yes"
			if uploadCovers(z.Wildcards, z.Zone) {
				reinstall = "no"
			}
			wrote, err := tx.NoticeOnce(notifyDomainChanged, "warning", zoneKey(z),
				mustJSON(map[string]string{"zone": z.Zone, "reinstall": reinstall}))
			if err != nil {
				return err
			}
			if wrote {
				prog.Notified++
			}
			return nil
		}, func(done int) {
			prog.Tenants = done
			report(prog)
		})
		if err != nil {
			return nil, err
		}
		end, err := r.zoneState(ctx)
		if err != nil {
			return nil, err
		}
		if zoneKey(begin) == zoneKey(end) {
			return prog, nil
		}
	}
	return nil, errDomainUnsettled
}

func (r *Runner) zoneState(ctx context.Context) (z store.ZoneState, err error) {
	err = r.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
		z, err = g.ZoneState()
		return err
	})
	return z, err
}

// ---------------------------------------------------------------------------
// node_revoked (4.5)

// KeptRow is an address a revoked node learned that the job could not delete, because it is the last authorized address of
// an Endpoint that requires them. The admin reads these from GET /nodes/{id}/reports.
type KeptRow struct {
	Tenant   uuid.UUID `json:"tenant_id"`
	Endpoint uuid.UUID `json:"endpoint_id"`
	Address  uuid.UUID `json:"address_id"`
	Node     uuid.UUID `json:"node_id"`
}

// maxKeptListed bounds the list in the job's progress. One Endpoint keeps at most one such row (the rule refuses only the
// last), so the list is as long as the Endpoints that depend on a learned address; the count is always exact.
const maxKeptListed = 500

// RevokedProgress is the progress of a node_revoked job.
type RevokedProgress struct {
	Tenants   int       `json:"tenants"`
	Addresses int       `json:"addresses_deleted"`
	Clients   int       `json:"clients_deleted"`
	KeptTotal int       `json:"kept_total"`
	Kept      []KeptRow `json:"kept,omitempty"`
}

type revokedParams struct {
	NodeIDs []uuid.UUID `json:"node_ids"`
}

// revokedPage is how many rows one transaction of an Endpoint deletes. A learned address is bounded per Endpoint by the hub
// and a client row by client_cap, so an Endpoint seldom needs a second page; the bound keeps one transaction short.
const revokedPage = 200

// nodeRevoked deletes what a revoked node reported (4.5): per tenant, per Endpoint, in a transaction of its own under the
// Endpoint's lock (P3 3.7), the secure_dns addresses it learned, one row at a time through the one delete method of
// authorized_ips (P3 5 rule 2), and the auto client rows it created that nobody has touched since. A row the rule refuses
// stays: it is recorded in the progress, raises an alert and a notice to the tenant, who reviews the addresses of that
// Endpoint.
//
// Why a repeat or a superseding job loses and doubles nothing: the rows it deletes are chosen by the node ids and the state
// of the row, so the second walk finds only what is left. A kept row is found again and recorded again (the progress of the
// new run replaces the old), the alert is open once per Endpoint (alerts_open_key_uq) and the notice once per set of nodes
// (notifications_kind_key_uq).
func (r *Runner) nodeRevoked(ctx context.Context, j store.AdminJob, report Report) (any, error) {
	var p revokedParams
	if err := json.Unmarshal(j.Params, &p); err != nil || len(p.NodeIDs) == 0 {
		return nil, errBadParams
	}
	nodes := slices.Clone(p.NodeIDs)
	slices.SortFunc(nodes, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	nodes = slices.Compact(nodes)
	// The revoke route queues the job in its own transaction, so the job's creation is the revoke. A job that replaced an
	// earlier one carries that one's nodes too, and a client row seen between the two revokes is then kept for nobody: the
	// later cut only deletes more, and a real device that was seen comes back on its next query (4.5).
	since := j.CreatedAt

	var prog RevokedProgress
	err := r.forEachTenantCtx(ctx, func(ctx context.Context, tenant uuid.UUID) error {
		return r.revokeTenant(ctx, j.ID, tenant, nodes, since, &prog)
	}, func(done int) {
		prog.Tenants = done
		report(prog)
	})
	if err != nil {
		return nil, err
	}
	return prog, nil
}

// revokeTenant is one tenant: its Endpoints that hold a row of the nodes, each cleaned in its own transaction, then the notice
// and the alerts for what stayed.
func (r *Runner) revokeTenant(ctx context.Context, job, tenant uuid.UUID, nodes []uuid.UUID, since time.Time, prog *RevokedProgress) error {
	var endpoints []uuid.UUID
	if err := r.db.WithTenant(ctx, tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
		endpoints, err = tx.RevokedNodeEndpoints(nodes)
		return err
	}); err != nil {
		return err
	}
	var kept []KeptRow
	for _, ep := range endpoints {
		res, err := r.revokeEndpoint(ctx, job, tenant, ep, nodes, since)
		if err != nil {
			return err
		}
		prog.Addresses += res.addresses
		prog.Clients += res.clients
		kept = append(kept, res.kept...)
	}
	if len(kept) == 0 {
		return nil
	}
	prog.KeptTotal += len(kept)
	for _, k := range kept {
		if len(prog.Kept) < maxKeptListed {
			prog.Kept = append(prog.Kept, k)
		}
	}
	// The notice is keyed by the nodes whose rows stayed, so a repeat of this job, or the job that replaces it with the same
	// nodes behind it, tells the tenant once.
	var learned []string
	for _, k := range kept {
		learned = append(learned, k.Node.String())
	}
	slices.Sort(learned)
	learned = slices.Compact(learned)
	if err := r.db.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		held, err := tx.AdminJobHold(job)
		if err != nil {
			return err
		}
		if !held {
			return errSuperseded
		}
		_, err = tx.NoticeOnce(notifyAuthorizedReview, "warning", noticeKey(notifyAuthorizedReview, learned...), mustJSON(map[string]int{"endpoints": len(kept)}))
		return err
	}); err != nil {
		return err
	}
	return r.alertKept(ctx, tenant, kept)
}

// endpointResult is what one Endpoint's cleaning did.
type endpointResult struct {
	addresses, clients int
	kept               []KeptRow
}

// revokeEndpoint cleans one Endpoint in pages, one transaction each. The order inside is the lock order of P3 3.7: the
// job's row, the clients (rank of clients), then the Endpoint's row, then its authorized rows, and the mark last.
func (r *Runner) revokeEndpoint(ctx context.Context, job, tenant, ep uuid.UUID, nodes []uuid.UUID, since time.Time) (endpointResult, error) {
	var out endpointResult
	after := uuid.Nil
	for {
		var more bool
		var page endpointResult
		var next uuid.UUID
		err := r.db.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
			// A retried transaction starts these over.
			page, more, next = endpointResult{}, false, after
			held, err := tx.AdminJobHold(job)
			if err != nil {
				return err
			}
			if !held {
				return errSuperseded
			}
			clients, err := tx.RevokedClientsDelete(ep, nodes, since, revokedPage)
			if err != nil {
				return err
			}
			page.clients = clients
			found, err := tx.EndpointsLock([]uuid.UUID{ep})
			if err != nil {
				return err
			}
			if len(found) != 1 {
				return nil // the Endpoint is gone, and its rows with it
			}
			learned, err := tx.RevokedLearnedLock(ep, nodes, after, revokedPage)
			if err != nil {
				return err
			}
			for _, a := range learned {
				w, err := tx.AuthorizedDelete(ep, []uuid.UUID{a.ID})
				if err != nil {
					return err
				}
				if w.Yes() {
					page.addresses++
				} else {
					page.kept = append(page.kept, KeptRow{Tenant: tenant, Endpoint: ep, Address: a.ID, Node: a.Node})
				}
				next = a.ID
			}
			more = clients > 0 || len(learned) == revokedPage
			if page.clients+page.addresses > 0 {
				return store.MarkDirty(tx, store.AggregateEndpointSet, tenant)
			}
			return nil
		})
		if err != nil {
			return out, err
		}
		out.addresses += page.addresses
		out.clients += page.clients
		out.kept = append(out.kept, page.kept...)
		after = next
		if !more {
			return out, nil
		}
	}
}

// keptReason is the one reason of the alerts this job raises: a closed set, as every alert's params are (internal/closed).
type keptReason string

const reasonAuthorizedKept keptReason = "authorized_kept"

func (r keptReason) Valid() bool    { return r == reasonAuthorizedKept }
func (r keptReason) String() string { return string(r) }

// keptAlert is the params of the alert: which tenant and Endpoint hold an address of a revoked node that stayed.
type keptAlert struct {
	Reason   keptReason `json:"reason"`
	Tenant   uuid.UUID  `json:"tenant_id"`
	Endpoint uuid.UUID  `json:"endpoint_id"`
}

// alertKept raises one alert per Endpoint that kept an address, open once until an admin acknowledges it.
func (r *Runner) alertKept(ctx context.Context, tenant uuid.UUID, kept []KeptRow) error {
	seen := map[uuid.UUID]bool{}
	return r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		for _, k := range kept {
			if seen[k.Endpoint] {
				continue
			}
			seen[k.Endpoint] = true
			params, err := closed.NewParams(keptAlert{Reason: reasonAuthorizedKept, Tenant: tenant, Endpoint: k.Endpoint})
			if err != nil {
				return err
			}
			if _, err := g.AlertOnce("warning", KindNodeRevoked, closed.NewKey(reasonAuthorizedKept, closed.ID(tenant), closed.ID(k.Endpoint)), params); err != nil {
				return err
			}
		}
		return nil
	})
}

// forEachTenantCtx pages through the tenants like forEachTenant, but hands fn the tenant and no transaction: node_revoked
// opens one per Endpoint (a WithTenant may not be opened inside another), and its reads of one tenant stay short.
func (r *Runner) forEachTenantCtx(ctx context.Context, fn func(context.Context, uuid.UUID) error, after func(done int)) error {
	var cursor uuid.UUID
	done := 0
	var retried error
	for {
		var ids []uuid.UUID
		if err := r.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			ids, err = g.TenantIDs(cursor, r.page)
			return err
		}); err != nil {
			return err
		}
		if len(ids) == 0 {
			return retried
		}
		for _, id := range ids {
			if err := fn(ctx, id); err != nil {
				// A lost lock race or a deadlock of one tenant must not hold back the tenants after it: the revoke is what
				// every tenant is waiting for. The tenant is passed over and the run ends with its error, so the runner
				// walks again after its backoff.
				if !errors.Is(err, store.ErrRetry) || ctx.Err() != nil {
					return err
				}
				if retried == nil {
					retried = err
				}
			}
			done++
		}
		after(done)
		if r.afterPage != nil {
			r.afterPage(done)
		}
		cursor = ids[len(ids)-1]
	}
}

// ---------------------------------------------------------------------------
// A P4 job that does not finish.

// failReason is the one reason of the alerts of a job that did not finish: a closed set, as every alert's params are.
type failReason string

const (
	reasonJobFailed failReason = "job_failed" // the job ended as failed after its runs
	reasonJobStuck  failReason = "job_stuck"  // the job keeps losing lock races and is still being run
)

func (r failReason) Valid() bool    { return r == reasonJobFailed || r == reasonJobStuck }
func (r failReason) String() string { return string(r) }

type jobAlert struct {
	Reason failReason `json:"reason"`
	Job    uuid.UUID  `json:"job_id"`
}

// p4Kind says whether a job is one of the three whose work nobody queues again: a revoked node cannot be revoked twice, and a
// pair or a domain that changed back is a different change. Their failure is an alert, not a log line.
func p4Kind(kind string) bool {
	return kind == KindPairChange || kind == KindDomainChange || kind == KindNodeRevoked
}

// alertJob raises the alert of a P4 job that ended as failed or keeps failing, open once per job until an admin acknowledges it.
func (r *Runner) alertJob(ctx context.Context, j store.AdminJob, reason failReason) {
	params, err := closed.NewParams(jobAlert{Reason: reason, Job: j.ID})
	if err != nil {
		return
	}
	if err := r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := g.AlertOnce("critical", j.Kind, closed.NewKey(reason, closed.ID(j.ID)), params)
		return err
	}); err != nil {
		r.log.Warn("admin job alert failed", logattr.Enum("error_class", errClass(err)))
	}
}
