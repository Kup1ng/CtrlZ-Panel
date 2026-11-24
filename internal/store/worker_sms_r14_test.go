package store_test

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Review round 18, SMS area (sms-r18-2, D64 sms-available-oracle, migration 0057). The public flag
// sms_available is what the login page reads to offer the one-time code, and anyone can read it. In
// rounds 14 and 15 it followed what the SENDS did (a refused login holds a gateway, three failures open
// a breaker), and only a real OTP row, which exists only for a phone with an account, ever reaches a
// gateway: a stranger who asked for a code for a phone and watched the flag fall learned that the phone
// has an account. It is computed from configuration alone now: a routed gateway (primary or fallback)
// whose credentials exist and that the worker has not judged unusable for them. The breaker, the hold and
// blocked_now stay the router's own view and no public output reads them.
func TestNoSendOutcomeMovesThePublicSMSFlag(t *testing.T) {
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
	blocked := func(id uuid.UUID) (b bool) {
		t.Helper()
		if err := super.QueryRow(f.ctx, `SELECT blocked_now FROM ctrlz.sms_gateways WHERE id = $1`, id).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	if !available() {
		t.Fatal("two working routed gateways read as unavailable")
	}

	// A hold of a refused login on every routed gateway: the router's view moves, the public flag does not.
	for id, ct := range map[uuid.UUID]string{pri: "sealed-pri", fb: "sealed-fb"} {
		f.global(t, worker, func(g store.GlobalTx) {
			if w, err := g.GatewayHold(id, sum(ct), code); err != nil || !w.Yes() {
				t.Fatalf("hold: %v %v", w, err)
			}
		})
	}
	if !blocked(pri) || !blocked(fb) {
		t.Fatal("a held gateway is not blocked for the router; the internal view must keep following the hold")
	}
	if !available() {
		t.Fatal("a hold of a refused login moved the public flag: a stranger could read from it whether a request left a real row")
	}

	// Breakers open on every routed gateway, and a pause that lapses: the same.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET consecutive_failures = 3, breaker_open_until = now() + interval '10 minutes'`); err != nil {
		t.Fatal(err)
	}
	if !available() {
		t.Fatal("open breakers moved the public flag")
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET breaker_open_until = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if !available() {
		t.Fatal("lapsed breakers moved the public flag")
	}

	// What does move it is configuration. The worker's judgement of unreadable credentials (written
	// whatever any user asked), no credentials, and a role that is not routed.
	for _, id := range []uuid.UUID{pri, fb} {
		ct := map[uuid.UUID]string{pri: "sealed-pri", fb: "sealed-fb"}[id]
		f.global(t, worker, func(g store.GlobalTx) {
			if w, err := g.GatewayUnusable(id, sum(ct)); err != nil || !w.Yes() {
				t.Fatalf("judgement: %v %v", w, err)
			}
		})
	}
	if available() {
		t.Fatal("both routed gateways are judged unusable for their credentials and the flag still offers a code")
	}
	// Saving other credentials ends the judgement of that gateway with no write of its column.
	f.global(t, admin, func(g store.GlobalTx) {
		if ok, _ := activate(g, pri, "sms_ir", []byte("sealed-pri-2"), "1234"); !ok {
			t.Fatal("credentials")
		}
	})
	if !available() {
		t.Fatal("new credentials did not end the judgement")
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET role = 'disabled'`); err != nil {
		t.Fatal(err)
	}
	if available() {
		t.Fatal("no routed gateway at all reads as available")
	}
}

// The role that runs the function can read nothing of the sends: a column that says whether sends failed
// is the channel itself, so the definer role holds only what the configuration answer needs (0057).
func TestThePublicConfigRoleCannotReadTheBreakerOrTheHold(t *testing.T) {
	f := newFixture(t)
	super := f.superConn(t)
	for _, c := range []struct {
		col  string
		want bool
	}{{"provider", true}, {"role", true}, {"unusable_now", true}, {"breaker_open_until", false}, {"blocked_now", false}, {"consecutive_failures", false}, {"held_code", false}, {"credentials_ct", false}} {
		var got bool
		if err := super.QueryRow(f.ctx, `SELECT has_column_privilege('ctrlz_auth', 'ctrlz.sms_gateways', $1, 'SELECT')`, c.col).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("ctrlz_auth SELECT on sms_gateways.%s = %v, want %v", c.col, got, c.want)
		}
	}
}
