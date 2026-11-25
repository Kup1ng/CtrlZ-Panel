package adminjobs_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/adminjobs"
)

// finish plays the part of another worker that completed the job.
func (r *rig) finishByOther(id uuid.UUID) {
	r.t.Helper()
	r.env.Exec(r.t, `UPDATE ctrlz.admin_jobs SET state = 'done', finished_at = now() WHERE id = $1`, id)
}

// Review sms-r2-12 (and sms-r2-3): a job that another worker has finished must
// not be run again from a job list that was read earlier. A second RP ID change
// may be queued by then, and the old handler, with the old RP ID, would mark the
// credentials of the new one stale for good (7.4 step 5: never revived).
func TestAJobFinishedByAnotherWorkerIsNotRunFromAStaleList(t *testing.T) {
	var r *rig
	var second uuid.UUID
	r = newRig(t, adminjobs.Config{BeforeStart: func(j store.AdminJob) {
		if second != uuid.Nil {
			return
		}
		// Between the list and the start: the other worker finishes the job, the
		// admin changes the RP ID again, and a user enrols under the new one.
		r.finishByOther(j.ID)
		second = r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "c.test"})
		r.addPasskey(r.env.A.Tenant, r.env.A.User, "a-c", "c.test")
		r.addPasskey(r.env.B.Tenant, r.env.B.User, "b-c", "c.test")
	}})
	first := r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "b.test"})

	r.runOnce()
	if state, _ := r.job(first); state != "done" {
		t.Errorf("the first job is %s", state)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE stale_at IS NOT NULL`); n != 0 {
		t.Errorf("%d credentials were marked stale by a job that was already finished", n)
	}
	if state, _ := r.job(second); state != "queued" {
		t.Errorf("the second job is %s, want queued", state)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'passkey_stale'`); n != 0 {
		t.Errorf("%d users were told their passkey went stale", n)
	}

	// The second job then does its own work: the credentials of the old RP ID go
	// stale and the new ones stay live.
	r.runOnce()
	if state, _ := r.job(second); state != "done" {
		t.Fatalf("the second job is %s", state)
	}
	if r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE rp_id = 'c.test' AND stale_at IS NULL`) != 2 ||
		r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE rp_id = 'example.test' AND stale_at IS NOT NULL`) != 2 {
		t.Error("the second job did not mark exactly the old credentials stale")
	}
}

// The same, one step later: the job is still running here when another worker
// finishes it and the next one is queued. The tenants not yet visited must be
// left alone, because the job's RP ID is no longer the one in force. Two tenants,
// so the isolation is visible: the one already walked keeps what the job did, the
// one not yet walked is untouched.
func TestAJobFinishedMidWalkLeavesTheTenantsNotYetVisited(t *testing.T) {
	var r *rig
	var second uuid.UUID
	var firstTenant, secondTenant, secondUser uuid.UUID
	r = newRig(t, adminjobs.Config{AfterPage: func(done int) {
		if done != 1 {
			return
		}
		var first uuid.UUID
		r.env.Scan(r.t, `SELECT id FROM ctrlz.admin_jobs WHERE state = 'running'`, nil, &first)
		r.finishByOther(first)
		second = r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "c.test"})
		r.addPasskey(secondTenant, secondUser, "later-c", "c.test")
	}})
	// The runner walks tenants in id order.
	a, b := r.env.A, r.env.B
	firstTenant, secondTenant, secondUser = a.Tenant, b.Tenant, b.User
	if b.Tenant.String() < a.Tenant.String() {
		firstTenant, secondTenant, secondUser = b.Tenant, a.Tenant, a.User
	}
	r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "b.test"})

	r.runOnce()
	if second == uuid.Nil {
		t.Fatal("the hook never ran")
	}
	stale := func(tenant uuid.UUID, rp string) int {
		return r.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE tenant_id = $1 AND rp_id = $2 AND stale_at IS NOT NULL`, tenant, rp)
	}
	if stale(firstTenant, "example.test") != 1 {
		t.Error("the tenant walked before the job was finished lost its stale mark")
	}
	if stale(secondTenant, "c.test") != 0 {
		t.Error("a credential of the new RP ID was marked stale by the old job")
	}
	if stale(secondTenant, "example.test") != 0 {
		t.Error("the old job went on to a tenant after it was finished")
	}
	if state, _ := r.job(second); state != "queued" {
		t.Errorf("the second job is %s, want queued", state)
	}
}
