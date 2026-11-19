package adminapi

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTwoAdminsChangingTheLimitsEachNameTheirOwnChange is admin-r11-1. PUT /sms/limits read the old
// values with no lock and built the audit row from them, so an admin whose read came before another's
// commit named the wrong fields: B read cap 100, A committed 200, B wrote 100 and its row listed no
// cost cap although the real change was 200 to 100. The seam holds the first request after its read
// until the second has read too (or a time passes). With the read under the settings row lock the
// second cannot read until the first has committed, so the wait times out and each row is judged
// against what that request really replaced.
func TestTwoAdminsChangingTheLimitsEachNameTheirOwnChange(t *testing.T) {
	r := newRig(t)
	r.env.ResetSMS(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = 100`)
	r.env.Exec(t, `DELETE FROM ctrlz.audit_log WHERE action = 'sms.limits_change'`)

	var lim map[string]any
	b.get("/sms/limits").want(200, "").json(&lim)
	bodyA, bodyB := map[string]any{}, map[string]any{}
	for k, v := range lim {
		bodyA[k], bodyB[k] = v, v
	}
	bodyA["sms_cost_cap_daily"] = "200"
	bodyB["sms_cost_cap_daily"] = "100"

	var calls atomic.Int32
	aRead, bRead := make(chan struct{}), make(chan struct{})
	h := r.handler(t, func(d *Deps) {
		d.limitsRead = func() {
			if calls.Add(1) == 1 {
				close(aRead)
				select {
				case <-bRead:
				case <-time.After(1500 * time.Millisecond):
				}
				return
			}
			close(bRead)
		}
	})
	clone := func() *browser {
		c := &browser{r: b.r, ip: b.ip, jar: map[string]*http.Cookie{}}
		for k, v := range b.jar {
			c.jar[k] = v
		}
		return c
	}
	ba, bb := clone(), clone()
	var wg sync.WaitGroup
	var codeA, codeB int
	wg.Add(1)
	go func() {
		defer wg.Done()
		codeA = ba.callOn(h, adminHost, "PUT", "/sms/limits", bodyA).Code
	}()
	<-aRead
	wg.Add(1)
	go func() {
		defer wg.Done()
		codeB = bb.callOn(h, adminHost, "PUT", "/sms/limits", bodyB).Code
	}()
	wg.Wait()
	if codeA != 200 || codeB != 200 {
		t.Fatalf("statuses %d and %d", codeA, codeB)
	}

	// Whatever the order, each request replaced the other's value or the starting 100, and a row
	// that names no cost cap is a request that left the cap as it found it.
	var capNow string
	r.env.Scan(t, `SELECT sms_cost_cap_daily::text FROM ctrlz.system_settings`, nil, &capNow)
	if n := r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'sms.limits_change'`); n != 2 {
		t.Fatalf("%d audit rows", n)
	}
	for i := 0; i < 2; i++ {
		var f string
		r.env.Scan(t, `SELECT params->'fields'::text FROM ctrlz.audit_log WHERE action = 'sms.limits_change' ORDER BY id OFFSET $1 LIMIT 1`, []any{i}, &f)
		if !strings.Contains(f, "sms_cost_cap_daily") {
			t.Errorf("row %d omits the cost cap that this request really changed (cap now %s): %s", i, capNow, f)
		}
	}
}
