package batchjobs_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/batchjobs"
)

// The fault cases of spec 10.5 for the job runner: the server stops during a job, a worker is killed and River rescues its
// job, a job kills its worker on every attempt, a mark-failed that itself fails, and a job River discards on its args. In
// each one the row of batch_jobs is the truth: a job is never lost, never applies twice, and never holds the tenant's one slot
// for ever.

// plant puts a River job for a batch job straight into River's table, as a worker that died leaves it (state running, claimed
// an hour ago, by a client that no longer exists) or as a delivery that has not run yet (state available). attempt is the
// number of deliveries it already had, and args is the JSON of its arguments.
func (f *fx) plant(t *testing.T, tenant, job uuid.UUID, state string, attempt, maxAttempts int, args string) {
	t.Helper()
	if state == "running" {
		f.exec(t, `INSERT INTO river.river_job (state, attempt, max_attempts, attempted_at, attempted_by, kind, args, metadata, queue)
VALUES ('running', $1, $2, now() - interval '1 hour', ARRAY['dead-worker'], 'batch_job', $3::jsonb, jsonb_build_object('tenant_id', $4::text), 'default')`,
			attempt, maxAttempts, args, tenant.String())
		f.exec(t, `UPDATE ctrlz.batch_jobs SET state = 'running' WHERE id = $1`, job)
		return
	}
	f.exec(t, `INSERT INTO river.river_job (state, attempt, max_attempts, kind, args, metadata, queue)
VALUES ('available', $1, $2, 'batch_job', $3::jsonb, jsonb_build_object('tenant_id', $4::text), 'default')`,
		attempt, maxAttempts, args, tenant.String())
}

// jobArgs is the arguments of the River job of a batch job.
func jobArgs(id uuid.UUID) string { return `{"job_id": "` + id.String() + `"}` }

func (f *fx) profilesNamed(t *testing.T, tenant uuid.UUID, name string) int {
	t.Helper()
	var n int
	f.scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1 AND name = $2`, []any{tenant, name}, &n)
	return n
}

// TestARescueNeverComesBeforeTheTimeout: a live job slowed to just under its timeout is never rescued, because River's stuck
// bound is above the bound that stops the run (spec 3.5, 10.5): it completes with one attempt and no second run.
func TestARescueNeverComesBeforeTheTimeout(t *testing.T) {
	// The bounds River really gets, read from the configuration the runner builds, and not the constants beside it: a literal in
	// that configuration would pass a comparison of the constants and still let a live job be rescued and run twice.
	timeout, rescue := batchjobs.RiverBounds(batchjobs.Config{})
	if timeout != batchjobs.JobTimeout || rescue != batchjobs.RescueAfter || rescue <= timeout {
		t.Fatalf("River stops a run after %v and rescues a job after %v, want %v and %v with the rescue the later", timeout, rescue, batchjobs.JobTimeout, batchjobs.RescueAfter)
	}
	if batchjobs.RescueAfter <= batchjobs.JobTimeout {
		t.Fatalf("River rescues a job after %v and stops a run after %v: a live job could be run twice at once", batchjobs.RescueAfter, batchjobs.JobTimeout)
	}
	if batchjobs.StaleAfter < batchjobs.RescueAfter {
		t.Fatalf("the sweep ends a row after %v, before River may rescue it (%v)", batchjobs.StaleAfter, batchjobs.RescueAfter)
	}
}

// TestAWorkerKilledMidJobIsRescuedAndTheJobAppliesOnce: a worker that died left its River job running. River rescues it after
// the stuck bound, the next worker runs it, and the import is applied once: the dead worker's transaction never committed
// (spec 3.5, 10.5).
func TestAWorkerKilledMidJobIsRescuedAndTheJobAppliesOnce(t *testing.T) {
	f := newFx(t)
	id := f.queueImport(t, f.A.Tenant, "Rescued", 3)
	f.exec(t, `DELETE FROM ctrlz.job_outbox`) // the dead worker had drained it
	f.plant(t, f.A.Tenant, id, "running", 1, 4, jobArgs(id))
	f.start(t)
	testwait.Until(t, 4*time.Minute, "River to rescue and run the job", func() bool { s, _ := f.state(t, id); return s == "done" || s == "failed" })
	if s, e := f.state(t, id); s != "done" {
		t.Fatalf("state %s, error %s", s, e)
	}
	if n := f.profilesNamed(t, f.A.Tenant, "Rescued"); n != 1 {
		t.Fatalf("the rescued job made %d profiles, want 1", n)
	}
	var attempt int
	f.scan(t, `SELECT attempt FROM river.river_job WHERE args->>'job_id' = $1`, []any{id.String()}, &attempt)
	if attempt != 2 {
		t.Fatalf("the job ran %d times in all, want the dead one and one more", attempt)
	}
}

// TestAJobThatKillsItsWorkerOnEveryAttemptEndsFailed: three deliveries each ended by a dead worker leave a fourth, which only
// marks the job failed with job_attempts_exhausted. Nothing of the job was applied, and the tenant can queue again (spec 3.5,
// 10.5).
func TestAJobThatKillsItsWorkerOnEveryAttemptEndsFailed(t *testing.T) {
	f := newFx(t)
	id := f.queueImport(t, f.A.Tenant, "Deadly", 3)
	f.exec(t, `DELETE FROM ctrlz.job_outbox`)
	f.plant(t, f.A.Tenant, id, "running", profiles.JobAttempts, profiles.JobAttempts+1, jobArgs(id))
	f.start(t)
	// River waits its backoff for the third attempt (about 81 seconds) before the fourth runs.
	testwait.Until(t, 5*time.Minute, "the fourth delivery to mark the job failed", func() bool { s, _ := f.state(t, id); return s == "done" || s == "failed" })
	s, e := f.state(t, id)
	if s != "failed" || e != `{"code": "job_attempts_exhausted"}` {
		t.Fatalf("state %s, error %s", s, e)
	}
	if n := f.profilesNamed(t, f.A.Tenant, "Deadly"); n != 0 {
		t.Fatalf("a job that never finished made %d profiles", n)
	}
	f.queueImport(t, f.A.Tenant, "Again", 2) // the slot is free
}

// TestAJobRiverDiscardedOnItsArgsIsEndedBySweep: a River job whose arguments do not decode is discarded by River and never
// reaches the handler; its row would stay queued for ever, and the sweep ends it failed with job_attempts_exhausted so the
// tenant can queue again (spec 3.5, 10.5).
func TestAJobRiverDiscardedOnItsArgsIsEndedBySweep(t *testing.T) {
	f := newFx(t)
	id := f.queueImport(t, f.A.Tenant, "Undecodable", 3)
	f.exec(t, `DELETE FROM ctrlz.job_outbox`)
	f.plant(t, f.A.Tenant, id, "available", 0, 1, `{"job_id": 7}`)
	f.age(t, id, time.Hour)
	f.start(t)
	testwait.Until(t, 90*time.Second, "River to discard the job", func() bool {
		var n int
		f.scan(t, `SELECT count(*) FROM river.river_job WHERE state IN ('discarded', 'cancelled')`, nil, &n)
		return n == 1
	})
	// The River job names no job id that decodes, so the sweep finds no live River job for the row: the runner's own pass may have
	// ended it already, and the explicit one then finds it done.
	if err := f.runner.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	if s, e := f.state(t, id); s != "failed" || e != `{"code": "job_attempts_exhausted"}` {
		t.Fatalf("state %s, error %s", s, e)
	}
	f.queueImport(t, f.A.Tenant, "Again", 2)
}

// TestAMarkFailedThatItselfFailsIsEndedBySweep: the fourth delivery cannot write its mark (batch_jobs is locked past the
// worker's lock wait), so River discards the job after its last attempt, and the sweep ends the row (spec 3.5, 10.5).
func TestAMarkFailedThatItselfFailsIsEndedBySweep(t *testing.T) {
	f := newFx(t)
	id := f.queueImport(t, f.A.Tenant, "Unmarked", 3)
	f.exec(t, `DELETE FROM ctrlz.job_outbox`)
	f.plant(t, f.A.Tenant, id, "available", profiles.JobAttempts, profiles.JobAttempts+1, jobArgs(id))
	f.age(t, id, time.Hour)
	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	// The table is locked from here until River has given up, so the mark of the fourth delivery fails on its lock wait.
	if _, err := super.Exec(f.ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `LOCK TABLE ctrlz.batch_jobs IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_, _ = super.Exec(context.Background(), `COMMIT`)
		}
	}
	defer release()
	f.start(t)
	testwait.Until(t, 3*time.Minute, "River to give the job up", func() bool {
		var n int
		// A read of River's own table, which the lock does not touch.
		f.scan(t, `SELECT count(*) FROM river.river_job WHERE state IN ('discarded', 'cancelled')`, nil, &n)
		return n == 1
	})
	release()
	// River gave the job up while the table was locked, so the fourth delivery could not write its mark; the row is ended by
	// the sweep, and the periodic one of the runner may get there first, which is the same end.
	if err := f.runner.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	if s, e := f.state(t, id); s != "failed" || e != `{"code": "job_attempts_exhausted"}` {
		t.Fatalf("state %s, error %s", s, e)
	}
	f.queueImport(t, f.A.Tenant, "Again", 2)
}

// TestAJobIsNotLostWhenPostgresStopsDuringIt: the server stops while the job's transaction waits on a lock, so the run ends
// with the connection and nothing of it is applied; the job is a row, so when the server is back River runs it again and the
// import is applied once (spec 10.5).
func TestAJobIsNotLostWhenPostgresStopsDuringIt(t *testing.T) {
	f := newFx(t)
	c := testpg.Need(t, cluster)
	id := f.queueImport(t, f.A.Tenant, "Interrupted", 50)
	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	// The job takes its tenant's lock, creates the profile and then waits at the rules: it cannot finish before the stop.
	if _, err := super.Exec(f.ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `LOCK TABLE ctrlz.rules IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	count := func(ctx context.Context, sql string) (int, error) {
		var n int
		err := f.db.Scan(ctx, sql, nil, &n)
		return n, err
	}
	waitCtx, cancel := context.WithTimeout(f.ctx, time.Minute)
	defer cancel()
	if err := testpg.AwaitLockWaiters(waitCtx, count, 1); err != nil {
		t.Fatal(err)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer stopCancel()
	if err := c.StopPostgres(stopCtx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	t.Cleanup(func() {
		if !restarted { // never leave the cluster down for the tests that follow
			_ = c.StartPostgres(context.Background())
		}
	})
	// The worker and River meet a server that is not there: wait until a connection really is refused, so the stop is a fact
	// and not a delay.
	for i := 0; i < 100; i++ {
		var n int
		if f.db.Scan(f.ctx, `SELECT 1`, nil, &n) != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := c.StartPostgres(stopCtx); err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	restarted = true
	testwait.Until(t, 4*time.Minute, "the job to end after the server came back", func() bool {
		var s string
		if err := f.db.Scan(f.ctx, `SELECT state FROM ctrlz.batch_jobs WHERE id = $1`, []any{id}, &s); err != nil {
			return false // the pool of the test is still finding its way back
		}
		return s == "done" || s == "failed"
	})
	if s, e := f.state(t, id); s != "done" {
		t.Fatalf("state %s, error %s", s, e)
	}
	if n := f.profilesNamed(t, f.A.Tenant, "Interrupted"); n != 1 {
		t.Fatalf("the interrupted job made %d profiles, want 1", n)
	}
}

// TestALockSecretReachesNoJobRowAndNoRiverRow: the lock hash of a profile that a Duplicate job reads, and the text of a job that
// fails on that very source, are in no column of batch_jobs, job_outbox, idempotency_keys or River's table, and not in the log of
// the runner (spec 10.5, lock secrets). The new profile is not locked and holds no hash.
func TestALockSecretReachesNoJobRowAndNoRiverRow(t *testing.T) {
	const canary = "Canary-Job-Lock-Hash-98765-Cedar"
	f := newFx(t)
	src := f.seedProfile(t, f.A.Tenant, "Locked source", "a1.example", "a2.example", "a3.example")
	f.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = convert_to($2, 'UTF8') WHERE id = $1`, src, canary)
	dup := f.queue(t, f.A.Tenant, profiles.JobDuplicate, uuid.Nil, 3, profiles.DuplicateInput{Source: src, Name: "Copy of locked"})
	// A job that fails: its error is stored and must carry no text of the file.
	bad := importDoc(1)
	bad.Rules[0].Pattern = "bad..name"
	failing := f.queue(t, f.B.Tenant, profiles.JobImport, uuid.Nil, 1, profiles.ImportInput{Name: "Fails", Doc: bad})
	f.start(t)
	testwait.Until(t, 90*time.Second, "both jobs to end", func() bool {
		a, _ := f.state(t, dup)
		b, _ := f.state(t, failing)
		return (a == "done" || a == "failed") && (b == "done" || b == "failed")
	})
	if s, e := f.state(t, dup); s != "done" {
		t.Fatalf("the duplicate is %s (%s)", s, e)
	}
	if s, _ := f.state(t, failing); s != "failed" {
		t.Fatalf("the failing import is %s", s)
	}
	// A Duplicate of the same locked source that fails: the source now holds a grandfathered Iranian Redirect, which a Duplicate
	// refuses (spec 3.7), so the job that read the locked row is the one that ends failed.
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_host) VALUES ($1, $2, 'later.ir', 'domain', 'redirect', 'host', 'proxy.example.net')`, f.A.Tenant, src)
	refused := f.queue(t, f.A.Tenant, profiles.JobDuplicate, uuid.Nil, 4, profiles.DuplicateInput{Source: src, Name: "Refused copy"})
	s, e := f.untilEnded(t, refused)
	if s != "failed" || !strings.Contains(e, "iranian_name") {
		t.Fatalf("the duplicate of a source with a grandfathered Iranian Redirect is %s (%s), want failed with iranian_name", s, e)
	}
	for _, table := range []string{"batch_jobs", "job_outbox", "idempotency_keys"} {
		var n int
		f.scan(t, `SELECT count(*) FROM ctrlz.`+table+` t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, encode(convert_to($1, 'UTF8'), 'hex')) > 0`, []any{canary}, &n)
		if n != 0 {
			t.Errorf("the lock hash is in %s", table)
		}
	}
	var n int
	f.scan(t, `SELECT count(*) FROM river.river_job t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, encode(convert_to($1, 'UTF8'), 'hex')) > 0`, []any{canary}, &n)
	if n != 0 {
		t.Error("the lock hash is in river.river_job")
	}
	if strings.Contains(f.logs.String(), canary) {
		t.Error("the lock hash is in the log of the runner")
	}
	f.scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1 AND name = 'Copy of locked' AND lock_state = 'unlocked' AND lock_password_hash IS NULL`, []any{f.A.Tenant}, &n)
	if n != 1 {
		t.Errorf("the copy of a locked profile is not one unlocked profile with no hash (%d)", n)
	}
}

// TestTheReindexerNeverRunsAndNeverSpins: River's reindexer arms a timer with time.Until(Next(now)) and asks Next again after
// each run. The schedule this runner gave it once returned the zero time, so the timer fired at once and the reindexer looped
// without a pause (about 58,700 "Found reindex artifact" warnings in a few hours on the test install). The schedule must name
// a time far in the future, later than the one it was asked from, and the reindexer must have no index to work on.
func TestTheReindexerNeverRunsAndNeverSpins(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	next, indexes, set := batchjobs.ReindexerPlan(batchjobs.Config{}, now)
	if got := next.Sub(now); got < 50*365*24*time.Hour {
		t.Fatalf("the reindexer would next run %v after now, want decades (a zero or near time makes its timer fire at once, again and again)", got)
	}
	if !set || len(indexes) != 0 {
		t.Fatalf("the reindexer is given indexes %v (set %v), want an empty list that is not nil (nil means River's default list)", indexes, set)
	}
}
