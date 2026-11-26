package adminjobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/adminjobs"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

type rig struct {
	t      *testing.T
	env    *authtest.Env
	admin  *store.Store
	runner *adminjobs.Runner
}

func newRig(t *testing.T, cfg adminjobs.Config) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	env.Exec(t, `DELETE FROM ctrlz.admin_jobs`) // the seed queues one
	cfg.Store = env.Worker(t)
	cfg.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg.Page = 1 // one tenant per read: the paging is exercised
	runner, err := adminjobs.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, env: env, admin: env.Admin(t), runner: runner}
}

func (r *rig) queue(kind string, params any) uuid.UUID {
	r.t.Helper()
	b, _ := json.Marshal(params)
	var id uuid.UUID
	err := r.admin.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		id, err = g.AdminJobInsert(kind, b, uuid.MustParse("00000000-0000-7000-8000-0000000000e1"))
		return err
	})
	if err != nil {
		r.t.Fatal(err)
	}
	// The admin API sets the configuration and queues the job together, and the
	// database functions of the job act for the RP ID in force only (migration
	// 0017), so the rig does the same.
	if p, ok := params.(map[string]string); ok && kind == adminjobs.KindWebauthnRPChange {
		r.env.Exec(r.t, `UPDATE ctrlz.webauthn_config SET rp_id = $1`, p["rp_id"])
	}
	return id
}

func (r *rig) job(id uuid.UUID) (state string, progress map[string]any) {
	r.t.Helper()
	var raw []byte
	if err := r.env.DB.Scan(r.env.Ctx, `SELECT state, progress FROM ctrlz.admin_jobs WHERE id = $1`, []any{id}, &state, &raw); err != nil {
		r.t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &progress)
	return state, progress
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.env.DB.Scan(r.env.Ctx, sql, args, &n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *rig) runOnce() int {
	r.t.Helper()
	n, err := r.runner.RunOnce(r.env.Ctx)
	if err != nil {
		r.t.Fatalf("RunOnce: %v", err)
	}
	return n
}

// addPasskey plants a credential for a user under an RP ID.
func (r *rig) addPasskey(tenant, user uuid.UUID, id, rp string) {
	r.env.Exec(r.t, `INSERT INTO ctrlz.webauthn_credentials (tenant_id, user_id, credential_id, public_key, rp_id) VALUES ($1, $2, convert_to($3, 'UTF8'), '\x01', $4)`,
		tenant, user, id, rp)
}

func TestRPChangeMarksStaleNotifiesAndLiftsEnforceOnlyWhereNothingIsLive(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	a, b := r.env.A, r.env.B
	// The seed gave each user one credential on example.test. A also holds one on
	// the new RP ID, so A's Enforce stays in force. B has none, so B's lifts.
	r.addPasskey(a.Tenant, a.User, "a-new", "new.test")
	r.env.Exec(t, `UPDATE ctrlz.users SET enforce_passkey = true WHERE id = ANY ($1)`, []uuid.UUID{a.User, b.User})

	id := r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "new.test"})
	if n := r.runOnce(); n != 1 {
		t.Fatalf("ran %d jobs", n)
	}
	state, progress := r.job(id)
	if state != "done" {
		t.Fatalf("state %s, progress %v", state, progress)
	}
	if progress["tenants"] != float64(2) || progress["users_notified"] != float64(2) || progress["enforce_cleared"] != float64(1) {
		t.Errorf("progress %v", progress)
	}

	// Stale: the example.test credentials of both tenants, and not A's new one.
	if r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE rp_id = 'example.test' AND stale_at IS NOT NULL`) != 2 ||
		r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE rp_id = 'new.test' AND stale_at IS NULL`) != 1 {
		t.Error("the wrong credentials were marked stale")
	}
	// Enforce: A keeps it (a live credential remains), B does not.
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND enforce_passkey`, a.User) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND NOT enforce_passkey`, b.User) != 1 {
		t.Error("Enforce Passkey after the change")
	}
	// One notification per affected user, in the user's own tenant.
	for _, x := range []struct{ tenant, user uuid.UUID }{{a.Tenant, a.User}, {b.Tenant, b.User}} {
		if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'passkey_stale' AND params ->> 'user_id' = $2`,
			x.tenant, x.user.String()) != 1 {
			t.Errorf("notification of %v", x.user)
		}
	}
	if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'passkey_stale'`) != 2 {
		t.Error("a notification for the wrong tenant")
	}

	// A retry changes nothing and notifies nobody twice (7.4 step 4).
	id2 := r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "new.test"})
	r.runOnce()
	if state, p := r.job(id2); state != "done" || p["users_notified"] != float64(0) || p["enforce_cleared"] != float64(0) {
		t.Errorf("second run: %s %v", state, p)
	}
	if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'passkey_stale'`) != 2 {
		t.Error("the retry notified again")
	}
	// A credential that is already stale is not touched again: its stale_at is the
	// first one.
	if r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE stale_at > now() - interval '1 second'`) > 2 {
		t.Error("stale_at moved")
	}
}

func TestRPChangeBackToTheOldIDDoesNotReviveCredentials(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "new.test"})
	r.runOnce()
	r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "example.test"})
	r.runOnce()
	// The first change marked the example.test credentials stale; the second marks
	// nothing back to live.
	if r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE rp_id = 'example.test' AND stale_at IS NULL`) != 0 {
		t.Error("setting the RP ID back revived a stale credential (7.4 step 5)")
	}
}

func TestRegistrationTransitionCountsAndFinishes(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{"from": "closed", "to": "open", "grace_days": 7})
	r.runOnce()
	state, p := r.job(id)
	// The seed gives each tenant one active claim with no proof.
	if state != "done" || p["tenants"] != float64(2) || p["claims"] != float64(2) {
		t.Errorf("%s %v", state, p)
	}
	// P1 changes no claim.
	if r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE state <> 'active'`) != 0 {
		t.Error("a claim was changed")
	}
	// With none, it is {claims: 0} as 11.2 says.
	r.env.Exec(t, `UPDATE ctrlz.ip_claims SET proven_at = now()`)
	id2 := r.queue(adminjobs.KindRegistrationTransition, map[string]any{})
	r.runOnce()
	if state, p := r.job(id2); state != "done" || p["claims"] != float64(0) {
		t.Errorf("%s %v", state, p)
	}
}

func TestBadParamsFailAtOnce(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	id := r.queue(adminjobs.KindWebauthnRPChange, map[string]string{})
	// The run reports the parameter error, and the job is finished as failed.
	if n, err := r.runner.RunOnce(r.env.Ctx); n != 1 || err == nil {
		t.Errorf("RunOnce: %d %v", n, err)
	}
	state, p := r.job(id)
	if state != "failed" || p["error"] != "bad_params" {
		t.Errorf("%s %v", state, p)
	}
	if r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE stale_at IS NOT NULL`) != 0 {
		t.Error("a job with no RP ID changed credentials")
	}
}

func TestAFailingJobIsRetriedThenGivenUp(t *testing.T) {
	boom := errors.New("tenant 3 timed out")
	calls := 0
	now := time.Now()
	r := newRig(t, adminjobs.Config{MaxFailures: 3, Backoff: []time.Duration{time.Second}, Now: func() time.Time { return now }, Handlers: map[string]adminjobs.Handler{
		adminjobs.KindRegistrationTransition: func(context.Context, store.AdminJob, adminjobs.Report) (any, error) {
			calls++
			return nil, boom
		},
	}})
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{})
	for i := 1; i <= 2; i++ {
		if _, err := r.runner.RunOnce(r.env.Ctx); !errors.Is(err, boom) {
			t.Fatalf("run %d: %v", i, err)
		}
		if state, _ := r.job(id); state != "running" {
			t.Fatalf("after failure %d the job is %s: a transient failure must leave it to be retried", i, state)
		}
		now = now.Add(2 * time.Second) // past the backoff
	}
	_, _ = r.runner.RunOnce(r.env.Ctx)
	state, p := r.job(id)
	if state != "failed" || p["error"] != "error" || calls != 3 {
		t.Errorf("%s %v calls %d", state, p, calls)
	}
	// The error text is not stored.
	raw, _ := json.Marshal(p)
	if string(raw) != `{"error":"error"}` {
		t.Errorf("progress holds more than a class: %s", raw)
	}
	// A failed job no longer runs.
	if n := r.runOnce(); n != 0 {
		t.Errorf("a failed job ran again: %d", n)
	}
}

func TestARunningJobOfADeadWorkerIsPickedUp(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{})
	r.env.Exec(t, `UPDATE ctrlz.admin_jobs SET state = 'running', started_at = now() - interval '1 hour' WHERE id = $1`, id)
	r.runOnce()
	if state, _ := r.job(id); state != "done" {
		t.Errorf("state %s", state)
	}
	if r.count(`SELECT count(*) FROM ctrlz.admin_jobs WHERE id = $1 AND started_at < now() - interval '30 minutes'`, id) != 1 {
		t.Error("the original start time was lost")
	}
}

func TestShutdownLeavesTheJobRunning(t *testing.T) {
	var r *rig
	started := make(chan struct{})
	r = newRig(t, adminjobs.Config{Handlers: map[string]adminjobs.Handler{
		adminjobs.KindRegistrationTransition: func(ctx context.Context, _ store.AdminJob, _ adminjobs.Report) (any, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}})
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{})
	ctx, cancel := context.WithCancel(r.env.Ctx)
	done := make(chan struct{})
	go func() { _, _ = r.runner.RunOnce(ctx); close(done) }()
	<-started
	cancel()
	<-done
	if state, _ := r.job(id); state != "running" {
		t.Errorf("a cancelled job is %s: it must stay running so the next worker resumes it", state)
	}
}

func TestProgressIsReportedWhileRunning(t *testing.T) {
	var r *rig
	seen := make(chan string, 1)
	r = newRig(t, adminjobs.Config{Handlers: map[string]adminjobs.Handler{
		adminjobs.KindRegistrationTransition: func(_ context.Context, j store.AdminJob, report adminjobs.Report) (any, error) {
			report(map[string]int{"tenants": 1})
			state, p := r.job(j.ID)
			b, _ := json.Marshal(p)
			seen <- state + " " + string(b)
			return map[string]int{"tenants": 2}, nil
		},
	}})
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{})
	r.runOnce()
	if got := <-seen; got != `running {"tenants":1}` {
		t.Errorf("mid-run: %s", got)
	}
	if state, p := r.job(id); state != "done" || p["tenants"] != float64(2) {
		t.Errorf("end: %s %v", state, p)
	}
}

func TestRunPollsAndStops(t *testing.T) {
	r := newRig(t, adminjobs.Config{Poll: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(r.env.Ctx)
	done := make(chan error, 1)
	go func() { done <- r.runner.Run(ctx) }()
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if state, _ := r.job(id); state == "done" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if state, _ := r.job(id); state != "done" {
		t.Errorf("the poll did not run the job: %s", state)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestNewNeedsStoreAndLog(t *testing.T) {
	if _, err := adminjobs.New(adminjobs.Config{}); err == nil {
		t.Error("built without a store")
	}
}

// A short database blip must not end a job that walks every tenant for good
// (review sms-r1-11). Before the fix five polls of 5 s were the whole budget;
// now each failure waits longer than the one before, and a retry inside the
// pause does not run at all.
func TestAFailureBacksOffBeforeTheNextTry(t *testing.T) {
	calls := 0
	const failFor = 4
	now := time.Now()
	r := newRig(t, adminjobs.Config{Now: func() time.Time { return now }, Handlers: map[string]adminjobs.Handler{
		adminjobs.KindRegistrationTransition: func(context.Context, store.AdminJob, adminjobs.Report) (any, error) {
			calls++
			if calls <= failFor {
				return nil, errors.New("connection refused")
			}
			return map[string]int{"tenants": 3}, nil
		},
	}})
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{})

	// The default pauses are 5 s, 30 s, 2 min, 10 min.
	for i, pause := range []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute} {
		if n, err := r.runner.RunOnce(r.env.Ctx); err == nil || n != 1 {
			t.Fatalf("failure %d: ran %d, err %v", i+1, n, err)
		}
		before := calls
		now = now.Add(pause - time.Second)
		if n, _ := r.runner.RunOnce(r.env.Ctx); n != 0 || calls != before {
			t.Fatalf("failure %d: the job ran again inside its %v pause", i+1, pause)
		}
		now = now.Add(2 * time.Second)
		if state, _ := r.job(id); state != "running" {
			t.Fatalf("after failure %d the job is %s", i+1, state)
		}
	}
	// Four blips in a row (about 12 minutes) and the fifth poll succeeds: the job
	// finishes and was never marked failed.
	if _, err := r.runner.RunOnce(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if state, _ := r.job(id); state != "done" {
		t.Errorf("after the blip the job is %s", state)
	}
}
