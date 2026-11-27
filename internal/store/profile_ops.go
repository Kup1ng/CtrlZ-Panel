package store

import (
	"time"

	"github.com/google/uuid"
)

// Idempotency, jobs and the location reads of the profile write path (spec 3.5, 4).

// ---------------------------------------------------------------------------
// Idempotency keys.

// Replay is what a key that already exists says.
type Replay struct {
	// Same is false when the key was used for another request (409 idempotency_key_reused).
	Same     bool
	Status   int
	Response []byte
}

// An expired row is replaced by the new claim in the same statement (spec 3.5: a key lives 24 hours): nothing
// sweeps keys in the write path, so a lookup that ignored expires_at would replay or refuse for as long as the
// row stays. The WHERE is the application clock, like every other stamp.
const qIdempotencyBegin = `INSERT INTO ctrlz.idempotency_keys (tenant_id, key, route, request_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6::timestamptz)
ON CONFLICT (tenant_id, key) DO UPDATE SET route = EXCLUDED.route, request_hash = EXCLUDED.request_hash, expires_at = EXCLUDED.expires_at,
  created_at = EXCLUDED.created_at, status_code = NULL, response = NULL
WHERE ctrlz.idempotency_keys.expires_at <= $6::timestamptz RETURNING key`

const qIdempotencyFind = `SELECT request_hash, status_code, response FROM ctrlz.idempotency_keys WHERE tenant_id = $1 AND key = $2`

// IdempotencyBegin (now is the application clock) is the first statement of a request that carries an Idempotency-Key: it claims the
// key. Of N twins exactly one wins; a concurrent twin waits on the unique index until the first commits
// (the lock wait of the transaction bounds it) and then finds the row. A win means "do the work and call
// IdempotencyFinish". A loss returns what the key stored: the same request replays its answer, another
// one is 409. A row with no answer yet cannot be seen here (it is uncommitted until it has one), so a
// replay always has a status.
func (t Tx) IdempotencyBegin(key, route string, hash []byte, now, expires time.Time) (Won, Replay, error) {
	var got string
	w, err := wonRow(t.tx.QueryRow(t.ctx, qIdempotencyBegin, t.tenant, key, route, hash, expires, now).Scan(&got))
	if err != nil || w.Yes() {
		return w, Replay{}, err
	}
	var stored []byte
	var status *int32
	var resp []byte
	if err := t.tx.QueryRow(t.ctx, qIdempotencyFind, t.tenant, key).Scan(&stored, &status, &resp); err != nil {
		return Won{}, Replay{}, sanitize(err)
	}
	r := Replay{Same: string(stored) == string(hash), Response: resp}
	if status != nil {
		r.Status = int(*status)
	}
	return Won{}, r, nil
}

const qIdempotencyFinish = `UPDATE ctrlz.idempotency_keys SET status_code = $3, response = $4::jsonb WHERE tenant_id = $1 AND key = $2`

// IdempotencyFinish stores the answer of the request that claimed the key, in the same transaction
// as its effect, so a replay sees both or neither.
func (t Tx) IdempotencyFinish(key string, status int, response []byte) error {
	_, err := t.tx.Exec(t.ctx, qIdempotencyFinish, t.tenant, key, int32(status), response)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// Jobs.

// JobRow is a batch job.
type JobRow struct {
	ID        uuid.UUID
	Kind      string
	ProfileID uuid.UUID // Nil until an Import or Duplicate has made its profile
	State     string
	Progress  int
	Total     int
	Result    []byte
	Error     []byte
}

const jobColumns = `id, kind, profile_id, state, progress, total, result, error`

func scanJob(r interface{ Scan(...any) error }) (JobRow, error) {
	var j JobRow
	var p *uuid.UUID
	err := r.Scan(&j.ID, &j.Kind, &p, &j.State, &j.Progress, &j.Total, &j.Result, &j.Error)
	if p != nil {
		j.ProfileID = *p
	}
	return j, err
}

const qJobQueue = `INSERT INTO ctrlz.batch_jobs (tenant_id, kind, profile_id, total, input) VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id`

const qJobOutbox = `INSERT INTO ctrlz.job_outbox (tenant_id, kind, args) VALUES ($1, 'batch_job', jsonb_build_object('job_id', $2::text))`

// JobQueue records a job and the outbox row that makes the worker pick it up, in one transaction. One
// job per tenant may be queued or running: a second is ErrConflict (the unique index of 0070), which the
// caller answers as 409 job_running. input is the validated items of the request.
func (t Tx) JobQueue(kind string, profile uuid.UUID, total int, input []byte) (uuid.UUID, error) {
	var id uuid.UUID
	if err := t.tx.QueryRow(t.ctx, qJobQueue, t.tenant, kind, nullUUID(profile), int32(total), input).Scan(&id); err != nil {
		return uuid.Nil, sanitize(err)
	}
	if _, err := t.tx.Exec(t.ctx, qJobOutbox, t.tenant, id.String()); err != nil {
		return uuid.Nil, sanitize(err)
	}
	return id, nil
}

const qJobGet = `SELECT ` + jobColumns + ` FROM ctrlz.batch_jobs WHERE tenant_id = $1 AND id = $2`

// Job reads a job of the tenant; another tenant's id is not found.
func (t Tx) Job(id uuid.UUID) (JobRow, bool, error) {
	j, err := scanJob(t.tx.QueryRow(t.ctx, qJobGet, t.tenant, id))
	ok, err := notFound(err)
	return j, ok, err
}

// qJobResultSize is the size of a job's stored result as text, which is about the size of its answer: the database detoasts and
// renders it and sends back a number, so the api can reserve the room of the answer before it reads one byte of it (p2-B3-r13-3).
const qJobResultSize = `SELECT COALESCE(octet_length(result::text), 0)::bigint FROM ctrlz.batch_jobs WHERE tenant_id = $1 AND id = $2`

// JobResultSize reads how many bytes the result of the tenant's job takes as JSON, 0 for a job with none; another tenant's id
// is not found.
func (t Tx) JobResultSize(id uuid.UUID) (int64, bool, error) {
	var n int64
	err := t.tx.QueryRow(t.ctx, qJobResultSize, t.tenant, id).Scan(&n)
	ok, err := notFound(err)
	return n, ok, err
}

const qJobActive = `SELECT ` + jobColumns + ` FROM ctrlz.batch_jobs WHERE tenant_id = $1 AND state IN ('queued', 'running')`

// JobActive is the tenant's queued or running job, so a client that lost the 202 can resume polling.
func (t Tx) JobActive() (JobRow, bool, error) {
	j, err := scanJob(t.tx.QueryRow(t.ctx, qJobActive, t.tenant))
	ok, err := notFound(err)
	return j, ok, err
}

// JobWork is what a claimed job carries.
type JobWork struct {
	Kind      string
	ProfileID uuid.UUID
	Input     []byte
}

const qJobClaim = `UPDATE ctrlz.batch_jobs SET state = 'running' WHERE tenant_id = $1 AND id = $2 AND state IN ('queued', 'running')
RETURNING kind, profile_id, input`

// JobClaim marks a queued job running. A job that is done or failed is a loss (a delivery that River
// repeats applies once); a job that is already running is claimed again, since that is a retry or a
// rescue. Run the work only on a win. Only the worker role may update this table.
func (t Tx) JobClaim(id uuid.UUID) (JobWork, Won, error) {
	var w JobWork
	var p *uuid.UUID
	won, err := wonRow(t.tx.QueryRow(t.ctx, qJobClaim, t.tenant, id).Scan(&w.Kind, &p, &w.Input))
	if err != nil || !won.Yes() {
		return JobWork{}, Won{}, err
	}
	if p != nil {
		w.ProfileID = *p
	}
	return w, won, nil
}

const qJobRunning = `SELECT state = 'running' FROM ctrlz.batch_jobs WHERE tenant_id = $1 AND id = $2`

// JobRunning reads, with no lock, whether the job is still running. The work of a job calls it after
// its first lock and does nothing unless it is: a mark-failed that came between ended it already.
func (t Tx) JobRunning(id uuid.UUID) (bool, error) {
	var running bool
	err := t.tx.QueryRow(t.ctx, qJobRunning, t.tenant, id).Scan(&running)
	ok, err := notFound(err)
	return ok && running, err
}

const qJobFinish = `UPDATE ctrlz.batch_jobs SET state = 'done', progress = total, result = $3::jsonb, profile_id = COALESCE($4::uuid, profile_id), input = NULL
WHERE tenant_id = $1 AND id = $2 AND state = 'running' RETURNING id`

// JobFinish is the last statement of the work of a job: done, with its result and the profile an Import
// or a Duplicate made. It applies where the job is still running, so one delivery ends it.
func (t Tx) JobFinish(id uuid.UUID, result []byte, profile uuid.UUID) (Won, error) {
	var got uuid.UUID
	return wonRow(t.tx.QueryRow(t.ctx, qJobFinish, t.tenant, id, result, nullUUID(profile)).Scan(&got))
}

const qJobFail = `UPDATE ctrlz.batch_jobs SET state = 'failed', error = $3::jsonb, input = NULL
WHERE tenant_id = $1 AND id = $2 AND state IN ('queued', 'running') RETURNING id`

// JobFail is mark-failed: the refusal of a job, in a transaction of its own after the work rolled back.
func (t Tx) JobFail(id uuid.UUID, errJSON []byte) (Won, error) {
	var got uuid.UUID
	return wonRow(t.tx.QueryRow(t.ctx, qJobFail, t.tenant, id, errJSON).Scan(&got))
}

// ---------------------------------------------------------------------------
// Locations (spec 4.1, 4.2).

// LocationRow is a row of ctrlz.locations.
type LocationRow struct {
	ID      uuid.UUID
	WireID  int
	Country string
	City    string
	Label   string
}

const qLocationRows = `SELECT id, wire_id, COALESCE(country_code, ''), COALESCE(city, ''), COALESCE(label, '') FROM ctrlz.locations ORDER BY wire_id`

// LocationRows reads every location. The tenant role reads this table (PS 6.2).
func (t Tx) LocationRows() ([]LocationRow, error) {
	rows, err := t.tx.Query(t.ctx, qLocationRows)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []LocationRow
	for rows.Next() {
		var l LocationRow
		if err := rows.Scan(&l.ID, &l.WireID, &l.Country, &l.City, &l.Label); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, l)
	}
	return out, sanitize(rows.Err())
}

// Availability says a node has a location with an enabled config.
type Availability struct{ Node, Location uuid.UUID }

const qLocationAvailability = `SELECT node_id, location_id FROM ctrlz.location_availability ORDER BY node_id, location_id`

// LocationAvailability reads which node has which location.
func (t Tx) LocationAvailability() ([]Availability, error) {
	rows, err := t.tx.Query(t.ctx, qLocationAvailability)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []Availability
	for rows.Next() {
		var a Availability
		if err := rows.Scan(&a.Node, &a.Location); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, a)
	}
	return out, sanitize(rows.Err())
}

// Pair is two nodes.
type Pair struct{ A, B uuid.UUID }

const qGlobalPair = `SELECT p.primary_node_id, p.fallback_node_id FROM ctrlz.public_settings s JOIN ctrlz.node_pairs p ON p.id = s.global_pair_id`

// GlobalPair reads the global pair; found is false when none is set (a stack with no nodes yet).
func (t Tx) GlobalPair() (Pair, bool, error) {
	var p Pair
	err := t.tx.QueryRow(t.ctx, qGlobalPair).Scan(&p.A, &p.B)
	ok, err := notFound(err)
	return p, ok, err
}

// qProfilePairs lists the node pair of every Endpoint that uses the profile in any role: enforced,
// Profile 2, a schedule window, or a client. The override columns are NULL in v1 (D30), and a NULL pair
// means the global pair; the query is written so that a pair override needs no change (T-022).
//
// It starts from the profile and not from the endpoints: the four index lookups (clients_profile_idx and
// clients_profile2_idx, schedule_windows_profile_idx and schedule_windows_profile2_idx, migration 0091) are the rows that
// name it, joined once to the endpoint ids. The form it replaced asked, for each of 50 endpoints, whether any of 1,000
// clients named the profile, and so read all 50,000 of them for a profile no client uses (p2-B3-r13-4).
const qProfilePairs = `SELECT DISTINCT e.pair_override_node_a, e.pair_override_node_b FROM ctrlz.endpoints e
WHERE e.tenant_id = $1 AND (e.profile_id = $2 OR e.profile2_id = $2 OR e.id IN (
  SELECT w.endpoint_id FROM ctrlz.schedule_windows w WHERE w.tenant_id = $1 AND w.profile_id = $2
  UNION SELECT w.endpoint_id FROM ctrlz.schedule_windows w WHERE w.tenant_id = $1 AND w.profile2_id = $2
  UNION SELECT c.endpoint_id FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.profile_id = $2
  UNION SELECT c.endpoint_id FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.profile2_id = $2))`

// ProfilePairs returns the pairs of the Endpoints that use the profile. A zero Pair stands for the
// global pair.
func (t Tx) ProfilePairs(profile uuid.UUID) ([]Pair, error) {
	rows, err := t.tx.Query(t.ctx, qProfilePairs, t.tenant, profile)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []Pair
	for rows.Next() {
		var a, b *uuid.UUID
		if err := rows.Scan(&a, &b); err != nil {
			return nil, sanitize(err)
		}
		var p Pair
		if a != nil && b != nil {
			p = Pair{A: *a, B: *b}
		}
		out = append(out, p)
	}
	return out, sanitize(rows.Err())
}
