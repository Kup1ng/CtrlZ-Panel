package store_test

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Review round 14, SMS area (sms-r14-2). sms_available is what the login page reads to offer the
// one-time code. A gateway whose login the provider refused is held (0043): no call to it can
// succeed. Before 0046 only the breaker timestamp reached auth_public_config, so every time a pause
// lapsed the flag read true again for a gateway known to be held, and one user per pause was told
// 202 for a code that could not arrive. blocked_now (which held_now became in 0048) is what the function reads now: the hold still
// names the credentials the row has.
func TestAHeldRoutedGatewayDoesNotMakeSMSAvailable(t *testing.T) {
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
	code := sms.StatusOf(sms.StatusCode("10"))
	available := func() bool {
		t.Helper()
		cfg, err := tenant.Auth().PublicConfig(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.SMSAvailable
	}
	hold := func(id uuid.UUID, ct string) {
		t.Helper()
		f.global(t, worker, func(g store.GlobalTx) {
			if w, err := g.GatewayHold(id, sum(ct), code); err != nil || !w.Yes() {
				t.Fatalf("hold: %v %v", w, err)
			}
		})
	}
	// Every pause is over, as it is each time the flag is read after a lapse: only the hold can
	// make the answer false.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0`); err != nil {
		t.Fatal(err)
	}
	if !available() {
		t.Fatal("two working routed gateways read as unavailable")
	}
	// One held gateway leaves the other able to send.
	hold(pri, "sealed-pri")
	if !available() {
		t.Fatal("a held primary made the fallback unavailable")
	}
	// Both held: nothing can send, with every breaker closed.
	hold(fb, "sealed-fb")
	if available() {
		t.Fatal("both routed gateways are held and sms_available is true; a code would be promised that cannot arrive")
	}
	// A pause that lapses does not change that.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET breaker_open_until = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if available() {
		t.Fatal("a lapsed pause made held gateways available again")
	}
	// Saving other credentials ends the hold of that gateway with no write to the hold columns.
	f.global(t, admin, func(g store.GlobalTx) {
		if ok, _ := g.SMSGatewaySetCredentials(pri, []byte("sealed-pri-2"), "1234"); !ok {
			t.Fatal("credentials")
		}
	})
	if !available() {
		t.Fatal("new credentials did not end the hold")
	}
	// A hold that names credentials the row no longer has (the PUT ran after the call began, then
	// the columns were written by a stale worker) does not count, even if the columns say held.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET held_ct_sum = $2, held_code = '10' WHERE id = $1`, pri, sum("sealed-pri")); err != nil {
		t.Fatal(err)
	}
	if !available() {
		t.Fatal("a hold made for other credentials counted")
	}
	// The same gateway held for its current credentials, and an accepted test send lifting it.
	hold(pri, "sealed-pri-2")
	if available() {
		t.Fatal("both held again and available")
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if w, err := g.GatewayRelease(pri, sum("sealed-pri-2")); err != nil || !w.Yes() {
			t.Fatalf("release: %v %v", w, err)
		}
	})
	if !available() {
		t.Fatal("an accepted test send did not make the gateway available again")
	}
	// A gateway with no role does not count whatever it holds, and a held one with a role closed
	// by its breaker still reads closed: the new term only removes, it adds nothing.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET role = 'disabled' WHERE id = $1`, pri); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET breaker_open_until = now() + interval '1 minute' WHERE id = $1`, fb); err != nil {
		t.Fatal(err)
	}
	if available() {
		t.Fatal("a closed breaker on the only routed gateway read as available")
	}
}
