package store

// The registration sweep of P3 spec 4.4 and AUTH 11.5: what a change of the registration mode does to the claims that were
// never proven. Each statement is one bounded batch of one tenant, picked and locked in key order, and repeats its
// predicate on the outer statement so a row another transaction moved after the pick is left alone. The worker reads the
// mode and the grace from the settings and passes them in; the statements never read a clock but the database's own, which
// is the one grace_until is compared with (the column is not an application-clock column, clocks.yaml).

// SweepBatch is how many claims one statement of one tenant moves in one run. A tenant holds at most max_ip_claims claims,
// so the bound is only ever met by a plan with a very large limit; the next run takes the rest.
const SweepBatch = 1000

// ClaimSweep says what the sweep did to one tenant.
type ClaimSweep struct {
	Graced    int
	Suspended int
	Restored  int
}

const qClaimsGrace = `UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now(), grace_until = now() + make_interval(days => $2::int)
WHERE tenant_id = $1 AND state = 'active' AND proven_at IS NULL AND first_grace_at IS NULL
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state = 'active' AND proven_at IS NULL AND first_grace_at IS NULL` +
	keyOrder + ` LIMIT $3::int` + lockNoKeyUpdate + `))
RETURNING id`

const qClaimsSuspendReopened = `UPDATE ctrlz.ip_claims SET state = 'suspended'
WHERE tenant_id = $1 AND state = 'active' AND proven_at IS NULL AND first_grace_at IS NOT NULL
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state = 'active' AND proven_at IS NULL AND first_grace_at IS NOT NULL` +
	keyOrder + ` LIMIT $2::int` + lockNoKeyUpdate + `))
RETURNING id`

const qClaimsSuspendEnded = `UPDATE ctrlz.ip_claims SET state = 'suspended', grace_until = NULL
WHERE tenant_id = $1 AND state = 'grace' AND grace_until <= now()
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state = 'grace' AND grace_until <= now()` +
	keyOrder + ` LIMIT $2::int` + lockNoKeyUpdate + `))
RETURNING id`

const qClaimsRestore = `UPDATE ctrlz.ip_claims SET state = 'active', grace_until = NULL
WHERE tenant_id = $1 AND state = 'grace'
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state = 'grace'` +
	keyOrder + ` LIMIT $2::int` + lockNoKeyUpdate + `))
RETURNING id`

// ClaimsSweepOpen applies the sweep of the mode `open` to the tenant: an unproven active claim that has not had its grace
// gets it (graceDays from now), one that already had it is suspended at once, and a claim whose grace ended is suspended.
// It never lowers first_grace_at, so each claim keeps its one grace (T-529).
func (t Tx) ClaimsSweepOpen(graceDays int) (ClaimSweep, error) {
	var r ClaimSweep
	g, err := idRows(t.tx.Query(t.ctx, qClaimsGrace, t.tenant, int32(graceDays), int32(SweepBatch)))
	if err != nil {
		return r, err
	}
	s1, err := idRows(t.tx.Query(t.ctx, qClaimsSuspendReopened, t.tenant, int32(SweepBatch)))
	if err != nil {
		return r, err
	}
	s2, err := idRows(t.tx.Query(t.ctx, qClaimsSuspendEnded, t.tenant, int32(SweepBatch)))
	if err != nil {
		return r, err
	}
	r.Graced, r.Suspended = len(g), len(s1)+len(s2)
	return r, nil
}

// ClaimsSweepClosed applies the sweep of a mode that is not `open`: a claim in grace is active again.
func (t Tx) ClaimsSweepClosed() (ClaimSweep, error) {
	var r ClaimSweep
	ids, err := idRows(t.tx.Query(t.ctx, qClaimsRestore, t.tenant, int32(SweepBatch)))
	if err != nil {
		return r, err
	}
	r.Restored = len(ids)
	return r, nil
}

// ---------------------------------------------------------------------------
// The lease of the 10-minute sweep.

const qLeaseTake = `INSERT INTO ctrlz.leases AS l (name, holder, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3::int))
ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at
WHERE l.holder = EXCLUDED.holder OR l.expires_at <= now()
RETURNING name`

// LeaseTake takes or renews the named lease for the holder, for secs seconds. It succeeds when nobody holds it, when the holder
// is the caller, or when the holder's time ran out, so two workers sweeping at once do not both run (the sweep is safe to
// run twice, the lease only saves the work).
func (g GlobalTx) LeaseTake(name, holder string, secs int) (bool, error) {
	var got string
	return notFound(g.tx.QueryRow(g.ctx, qLeaseTake, name, holder, int32(secs)).Scan(&got))
}

const qRegistrationForSweep = `SELECT registration_mode, open_grace_days FROM ctrlz.system_settings`

// RegistrationForSweep reads the registration mode and the grace in force, inside the tenant's transaction, so a sweep that
// began under one mode and finds another when it reaches a tenant applies the one in force (the job is a function of the
// state and not of the change that queued it, AUTH 11.4). The read takes no lock: a change in the next instant is the next
// run's.
func (t Tx) RegistrationForSweep() (mode string, graceDays int, err error) {
	var d int32
	if err = t.tx.QueryRow(t.ctx, qRegistrationForSweep).Scan(&mode, &d); err != nil {
		return "", 0, sanitize(err)
	}
	return mode, int(d), nil
}
