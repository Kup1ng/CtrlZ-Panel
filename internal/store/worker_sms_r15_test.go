package store_test

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Review round 15, SMS area (sms-r15-1, sms-r15-4, migration 0048). The worker's judgement that no
// sender can be built for a gateway is a column of the row, keyed on the ciphertext it was made
// for, and blocked_now (what auth_public_config reads) is true while it still names the credentials
// the row has. It ends with new credentials and moves with a rekey, as the hold does (rule
// sms-failure-classification, round 13: a state keyed on a digest is carried when its key is
// rewritten).
func TestTheWorkersJudgementOfAGatewayIsKeyedOnItsCredentials(t *testing.T) {
	f := newFixture(t)
	super := f.superConn(t)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	if _, err := super.Exec(f.ctx, `DELETE FROM ctrlz.sms_gateways`); err != nil {
		t.Fatal(err)
	}
	var pri, fb uuid.UUID
	for _, g := range []struct {
		id         *uuid.UUID
		provider   string
		role       string
		credential string
	}{{&pri, "sms_ir", "primary", "sealed-pri"}, {&fb, "melipayamak", "fallback", "sealed-fb"}} {
		if err := super.QueryRow(f.ctx, `INSERT INTO ctrlz.sms_gateways (provider, role, credentials_ct) VALUES ($1, $2, $3) RETURNING id`,
			g.provider, g.role, []byte(g.credential)).Scan(g.id); err != nil {
			t.Fatal(err)
		}
	}
	sum := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
	available := func() bool {
		t.Helper()
		cfg, err := tenant.Auth().PublicConfig(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.SMSAvailable
	}
	judge := func(id uuid.UUID, ct string) store.Won {
		t.Helper()
		var w store.Won
		f.global(t, worker, func(g store.GlobalTx) {
			var err error
			if w, err = g.GatewayUnusable(id, sum(ct)); err != nil {
				t.Fatal(err)
			}
		})
		return w
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET breaker_open_until = now() - interval '1 second', consecutive_failures = 3`); err != nil {
		t.Fatal(err)
	}
	if !available() {
		t.Fatal("two gateways with credentials and lapsed pauses read as unavailable before any judgement")
	}
	// A judgement for credentials the row does not have is dropped.
	if judge(pri, "other").Yes() {
		t.Fatal("a judgement about other credentials was recorded")
	}
	if !judge(pri, "sealed-pri").Yes() || judge(pri, "sealed-pri").Yes() {
		t.Fatal("the judgement must win once and lose when it is already there")
	}
	if !available() {
		t.Fatal("one unusable gateway made the other unavailable")
	}
	if !judge(fb, "sealed-fb").Yes() {
		t.Fatal("judgement of the fallback")
	}
	if available() {
		t.Fatal("both routed gateways are judged unusable and sms_available is true with every pause lapsed")
	}
	// New credentials end the judgement of that gateway with no write of the column.
	f.global(t, admin, func(g store.GlobalTx) {
		if ok, _ := g.SMSGatewaySetCredentials(pri, []byte("sealed-pri-2"), "1234"); !ok {
			t.Fatal("credentials")
		}
	})
	if !available() {
		t.Fatal("new credentials did not end the judgement")
	}
	// A rekey re-seals the same credentials: the judgement moves with them.
	f.global(t, admin, func(g store.GlobalTx) {
		if ok, err := g.SMSCredentialsReplace(fb, []byte("sealed-fb"), []byte("resealed-fb")); err != nil || !ok {
			t.Fatalf("replace: %v %v", ok, err)
		}
	})
	var blocked bool
	if err := super.QueryRow(f.ctx, `SELECT blocked_now FROM ctrlz.sms_gateways WHERE id = $1`, fb).Scan(&blocked); err != nil || !blocked {
		t.Fatalf("a rekey of an unusable gateway made it usable (%v %v)", blocked, err)
	}
	// A judgement that names credentials the row no longer has (a stale write) counts for nothing.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET unusable_ct_sum = $2 WHERE id = $1`, pri, sum("sealed-pri")); err != nil {
		t.Fatal(err)
	}
	if !available() {
		t.Fatal("a judgement for old credentials counted")
	}
	// Taking it back.
	f.global(t, worker, func(g store.GlobalTx) {
		if w, err := g.GatewayUsable(fb, sum("sealed-fb")); err != nil || w.Yes() {
			t.Fatalf("a stale build took back the judgement of the credentials the row holds now: %v %v", w, err)
		}
		if w, err := g.GatewayUsable(fb, sum("resealed-fb")); err != nil || !w.Yes() {
			t.Fatalf("usable: %v %v", w, err)
		}
		if w, err := g.GatewayUsable(fb, sum("resealed-fb")); err != nil || w.Yes() {
			t.Fatalf("usable twice: %v %v", w, err)
		}
	})
	if !available() {
		t.Fatal("a build that works did not take the judgement back")
	}
	// No credentials at all is known by the database alone, for every provider but noop, and the
	// worker's judgement of such a row names the digest of the empty string.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET credentials_ct = NULL, unusable_ct_sum = NULL`); err != nil {
		t.Fatal(err)
	}
	if available() {
		t.Fatal("routed gateways with no credentials read as available")
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET provider = 'noop', role = 'primary' WHERE id = $1`, pri); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET role = 'disabled' WHERE id = $1`, fb); err != nil {
		t.Fatal(err)
	}
	if !available() {
		t.Fatal("a noop row takes no credentials; only the worker can know it is in production")
	}
	if !judge(pri, "").Yes() {
		t.Fatal("the judgement of a row with no credentials must name the digest of the empty string")
	}
	if available() {
		t.Fatal("a noop row judged unusable (production) reads as available")
	}
}
