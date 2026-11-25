package batchjobs_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/batchjobs"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

type fx struct {
	ctx    context.Context
	db     *testpg.DB
	A, B   catalogtest.SeedIDs
	tenant *store.Store
	worker *store.Store
	env    *profiles.Env
	now    time.Time
	runner *batchjobs.Runner
}

func newFx(t *testing.T) *fx {
	t.Helper()
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	db := c.NewDB(ctx, t)
	super, err := db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	f := &fx{ctx: ctx, db: db, A: catalogtest.NewSeedIDs(1), B: catalogtest.NewSeedIDs(2), now: time.Now().UTC().Truncate(time.Second)}
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatal(err)
	}
	for _, ids := range []catalogtest.SeedIDs{f.A, f.B} {
		if err := catalogtest.SeedTenant(ctx, super, ids); err != nil {
			t.Fatal(err)
		}
	}
	// Each seeded tenant holds one queued job, which would be its one active job.
	if err := db.Exec(ctx, `DELETE FROM ctrlz.batch_jobs`); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(ctx, `DELETE FROM ctrlz.job_outbox`); err != nil {
		t.Fatal(err)
	}
	f.tenant = db.Store(ctx, t, store.RoleTenant)
	f.worker = db.Store(ctx, t, store.RoleWorker)
	f.env = &profiles.Env{Catalog: locations.Store{}, Clock: appclock.Func(func() time.Time { return f.now })}
	r, err := batchjobs.New(batchjobs.Config{Store: f.worker, Env: f.env, Log: slog.New(slog.DiscardHandler), Poll: 100 * time.Millisecond, Now: appclock.Func(func() time.Time { return f.now })})
	if err != nil {
		t.Fatal(err)
	}
	f.runner = r
	return f
}

func (f *fx) scan(t *testing.T, sql string, args []any, dst ...any) {
	t.Helper()
	if err := f.db.Scan(f.ctx, sql, args, dst...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fx) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.db.Exec(f.ctx, sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// start runs the runner (River, the drain and the sweep) until the test ends.
func (f *fx) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { done <- f.runner.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func (f *fx) state(t *testing.T, id uuid.UUID) (state string, errJSON string) {
	t.Helper()
	var e *string
	f.scan(t, `SELECT state, error::text FROM ctrlz.batch_jobs WHERE id = $1`, []any{id}, &state, &e)
	if e != nil {
		errJSON = *e
	}
	return state, errJSON
}

// age makes a job look as old as d: the touch trigger sets updated_at on every update, so it is off for the statement.
func (f *fx) age(t *testing.T, id uuid.UUID, d time.Duration) {
	t.Helper()
	f.exec(t, `ALTER TABLE ctrlz.batch_jobs DISABLE TRIGGER touch_updated_at`)
	f.exec(t, `UPDATE ctrlz.batch_jobs SET updated_at = $2 WHERE id = $1`, id, f.now.Add(-d))
	f.exec(t, `ALTER TABLE ctrlz.batch_jobs ENABLE TRIGGER touch_updated_at`)
}

// importDoc is a document of n rules.
func importDoc(n int) profiles.Document {
	d := profiles.Document{Format: profiles.DocFormat, Version: profiles.DocVersion, Kind: "custom"}
	for i := 0; i < n; i++ {
		d.Rules = append(d.Rules, profiles.DocRule{Pattern: "h" + uuid.NewString()[:8] + ".example.com", Action: "block"})
	}
	return d
}

func (f *fx) queueImport(t *testing.T, tenant uuid.UUID, name string, rules int) uuid.UUID {
	t.Helper()
	in, err := profiles.JobInputJSON(profiles.ImportInput{Name: name, Doc: importDoc(rules)})
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	err = f.tenant.WithTenant(f.ctx, tenant, store.TxOpts{}, func(tx store.Tx) (e error) {
		id, e = f.env.QueueJob(tx, profiles.JobRequest{Kind: profiles.JobImport, Total: rules, Input: in})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestAJobRunsEndToEnd: the outbox row of the api becomes a River job, the handler runs the import as the tenant, and
// the job ends done with its profile; another tenant has nothing of it (spec 3.5, 10.1).
func TestAJobRunsEndToEnd(t *testing.T) {
	f := newFx(t)
	var before int
	f.scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1`, []any{f.B.Tenant}, &before)
	id := f.queueImport(t, f.A.Tenant, "Imported", 1100)
	// The job row and its outbox row exist, in the same transaction.
	var outbox int
	f.scan(t, `SELECT count(*) FROM ctrlz.job_outbox WHERE tenant_id = $1`, []any{f.A.Tenant}, &outbox)
	if outbox != 1 {
		t.Fatalf("job_outbox rows = %d, want 1", outbox)
	}
	f.start(t)
	testwait.Until(t, 90*time.Second, "the job to end", func() bool { s, _ := f.state(t, id); return s == "done" || s == "failed" })
	if s, e := f.state(t, id); s != "done" {
		t.Fatalf("state %s, error %s", s, e)
	}
	var rules int
	var profile uuid.UUID
	f.scan(t, `SELECT p.id, (SELECT count(*) FROM ctrlz.rules r WHERE r.profile_id = p.id) FROM ctrlz.profiles p
WHERE p.tenant_id = $1 AND p.name = 'Imported'`, []any{f.A.Tenant}, &profile, &rules)
	if rules != 1100 {
		t.Fatalf("imported %d rules, want 1100", rules)
	}
	var jobProfile uuid.UUID
	var input *string
	f.scan(t, `SELECT profile_id, input::text FROM ctrlz.batch_jobs WHERE id = $1`, []any{id}, &jobProfile, &input)
	if jobProfile != profile || input != nil {
		t.Fatalf("the job reports profile %s and input %v", jobProfile, input)
	}
	var after int
	f.scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1`, []any{f.B.Tenant}, &after)
	if after != before {
		t.Fatalf("tenant B has %d profiles after A's job, had %d", after, before)
	}
	var outboxLeft int
	f.scan(t, `SELECT count(*) FROM ctrlz.job_outbox`, nil, &outboxLeft)
	if outboxLeft != 0 {
		t.Fatalf("the drain left %d outbox rows", outboxLeft)
	}
}

// TestARefusedJobFailsOnceWithItsError: a refusal is the end of the job (no retry), with the closed code and the fields.
func TestARefusedJobFailsOnceWithItsError(t *testing.T) {
	f := newFx(t)
	// An import whose document has a rule the parser refuses.
	d := importDoc(1)
	d.Rules[0].Pattern = "bad..name"
	in, _ := profiles.JobInputJSON(profiles.ImportInput{Name: "x", Doc: d})
	var id uuid.UUID
	if err := f.tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) (e error) {
		id, e = f.env.QueueJob(tx, profiles.JobRequest{Kind: profiles.JobImport, Total: 1, Input: in})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	testwait.Until(t, 90*time.Second, "the job to end", func() bool { s, _ := f.state(t, id); return s == "failed" || s == "done" })
	s, e := f.state(t, id)
	if s != "failed" {
		t.Fatalf("state %s", s)
	}
	var got struct {
		Code   string `json:"code"`
		Fields []struct{ Name, Code string }
	}
	if err := json.Unmarshal([]byte(e), &got); err != nil || got.Code != "validation_failed" || len(got.Fields) != 1 || got.Fields[0].Name != "/rules/0/pattern" {
		t.Fatalf("error %s (%v)", e, err)
	}
	var attempts int
	f.scan(t, `SELECT coalesce(max(attempt), 0) FROM river.river_job`, nil, &attempts)
	if attempts != 1 {
		t.Fatalf("a refusal took %d attempts, want 1", attempts)
	}
	_ = base64.StdEncoding
}

// TestAnOutboxRowNamingAnotherTenantsJobTouchesNothing: the tenant of a River job is the outbox column, so a row of B that
// names A's job id finds nothing under RLS and A's job is untouched (spec 10.1).
func TestAnOutboxRowNamingAnotherTenantsJobTouchesNothing(t *testing.T) {
	f := newFx(t)
	aJob := f.queueImport(t, f.A.Tenant, "A's import", 3)
	// Take A's outbox row away and plant one of B that names A's job.
	f.exec(t, `DELETE FROM ctrlz.job_outbox`)
	f.exec(t, `INSERT INTO ctrlz.job_outbox (tenant_id, kind, args) VALUES ($1, 'batch_job', jsonb_build_object('job_id', $2::text))`, f.B.Tenant, aJob.String())
	f.start(t)
	testwait.Until(t, 60*time.Second, "the outbox to drain", func() bool {
		var n int
		f.scan(t, `SELECT count(*) FROM ctrlz.job_outbox`, nil, &n)
		return n == 0
	})
	testwait.Until(t, 60*time.Second, "River to run it", func() bool {
		var n int
		f.scan(t, `SELECT count(*) FROM river.river_job WHERE state = 'completed'`, nil, &n)
		return n == 1
	})
	if s, _ := f.state(t, aJob); s != "queued" {
		t.Fatalf("A's job is %s after B's row named it", s)
	}
	var n int
	f.scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE name = 'A''s import'`, nil, &n)
	if n != 0 {
		t.Fatalf("B's row made %d profiles of A's import", n)
	}
}

// TestTheSweepEndsAJobRiverCannotEnd: a row older than 15 minutes with no outbox row and no River job is failed with
// job_attempts_exhausted, and the tenant can queue again (spec 3.5).
func TestTheSweepEndsAJobRiverCannotEnd(t *testing.T) {
	f := newFx(t)
	id := f.queueImport(t, f.A.Tenant, "Lost", 2)
	f.exec(t, `DELETE FROM ctrlz.job_outbox`)
	f.age(t, id, time.Hour)
	if err := f.runner.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	s, e := f.state(t, id)
	if s != "failed" || e != `{"code": "job_attempts_exhausted"}` {
		t.Fatalf("state %s error %s", s, e)
	}
	// A finished job a day old is deleted.
	f.age(t, id, 48*time.Hour)
	if err := f.runner.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	f.scan(t, `SELECT count(*) FROM ctrlz.batch_jobs WHERE id = $1`, []any{id}, &n)
	if n != 0 {
		t.Fatal("a finished job a day old was kept")
	}
	// The slot is free: a new job can be queued.
	f.queueImport(t, f.A.Tenant, "Again", 2)
}
