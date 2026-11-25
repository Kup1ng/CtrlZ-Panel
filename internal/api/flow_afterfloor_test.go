package api

import (
	"context"
	"sync"
	"testing"
)

// refusingWork is a Runner whose queue is always full.
type refusingWork struct {
	mu sync.Mutex
	n  int
}

func (r *refusingWork) Go(context.Context, func(context.Context)) bool {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	return false
}

// TestFailedLoginTrailIsWrittenAfterTheAnswerForTheRightTenant (tenant-r13-2): the failed-login row
// is work owed after the floor. A wrong password for the phone of tenant A leaves exactly one row, on
// tenant A, and none on tenant B; an unknown phone owes nothing; and when the queue is full the row
// is dropped and the answer is the same 401 an unknown phone gets (a dropped row is never an answer).
func TestFailedLoginTrailIsWrittenAfterTheAnswerForTheRightTenant(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	rows := func(tenant any) int {
		return f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'login.failed' AND tenant_id = $1`, tenant)
	}

	f.client().loginPassword(A.Phone, "not the password at all 1", false).want(401, "invalid_credentials")
	f.client().loginPassword("09129999999", "not the password at all 1", false).want(401, "invalid_credentials")
	f.after.Wait()
	if a, b := rows(A.Tenant), rows(B.Tenant); a != 1 || b != 0 {
		t.Fatalf("login.failed rows: tenant A %d (want 1), tenant B %d (want 0)", a, b)
	}

	// A full queue: the row is dropped, the answer does not change.
	full := &refusingWork{}
	f.deps.After = full
	f.setLimiter(f.deps.Limiter)
	f.clearThrottle()
	f.client().loginPassword(B.Phone, "not the password at all 1", false).want(401, "invalid_credentials")
	if full.n != 1 {
		t.Fatalf("the handler offered %d tasks, want 1", full.n)
	}
	f.after.Wait()
	if b := rows(B.Tenant); b != 0 {
		t.Fatalf("a dropped task left %d rows on tenant B", b)
	}
}
