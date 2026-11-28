package adminapi

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestNeighbourSpendingTheLoginClassCannotKeepTheFirstLoginOut is admin-r7-1, through the real
// pipeline. The class admin-login (five a minute on the /24) was charged before the body was read and
// answered 429 itself, so the exception for the right console one-time password, which only the handler
// can see, never got to run: the test of round 5 spent the Postgres scopes by hand and never touched the
// class. A neighbour who sends logins at the class's rate used to be enough. The class is deferred now,
// and its refusal reaches the handler as a value.
func TestNeighbourSpendingTheLoginClassCannotKeepTheFirstLoginOut(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	otp := r.makeOneTime(t)

	owner, neighbour := r.browser(), r.browser()
	ip := netip.MustParseAddr(owner.ip).As4()
	ip[3] ^= 0x55
	neighbour.ip = netip.AddrFrom4(ip).String()

	// Garbage and wrong passwords alike spend the class; the first five are answered by the handler,
	// the rest by the class's refusal.
	refused := 0
	for i := 0; i < 12; i++ {
		if res := neighbour.login("wrong-wrong-wrong-1", ""); res.Code == 429 {
			refused++
		}
	}
	if refused < 5 {
		t.Fatalf("the neighbour was refused %d times of 12: the class never ran, and the test proves nothing", refused)
	}
	neighbour.login("wrong-wrong-wrong-1", "").want(429, "rate_limited")

	// The owner, from the same /24 with the console password and no marker, gets in.
	owner.login(otp, "").want(200, "")
	owner.get("/me").want(200, "")

	// A password the owner chose is not the exception: the same class turns it away while it is spent.
	owner.post("/me/password", map[string]any{"current_password": otp, "new_password": adminNewPW}).want(204, "")
	again := r.browser()
	again.ip = neighbour.ip
	again.login(adminNewPW, "").want(429, "rate_limited")

	// Another network is untouched.
	r.browser().login(adminNewPW, "").want(200, "")
}

// TestTwoAdminsMakingTheSameSettingsChangeDoNotEndTheOthersJob is admin-r7-2. A settings route
// decides from a read that holds no lock whether the change ends the unfinished job of its kind. If
// another admin commits the same change in the gap, the ending job is the one that admin just queued,
// the lock then shows the target already in place, and the request used to return 200 as a no-op:
// the mode was changed and the transition that goes with it never ran. The seam stands for the other
// admin and commits between the read and the next statement; the second request must answer 409 and
// leave the first admin's job queued.
func TestTwoAdminsMakingTheSameSettingsChangeDoNotEndTheOthersJob(t *testing.T) {
	t.Run("registration mode", func(t *testing.T) {
		r := newRig(t)
		b, _ := r.admin(t)
		r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)
		b.put("/settings/registration", map[string]any{"mode": "closed"}).want(200, "")
		r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)

		fired := 0
		h := r.handler(t, func(d *Deps) {
			d.between = func() {
				fired++
				r.env.Exec(t, `UPDATE ctrlz.system_settings SET registration_mode = 'open'`)
				r.env.Exec(t, `INSERT INTO ctrlz.admin_jobs (kind, params) VALUES ('registration_transition', '{"from":"closed","to":"open","grace_days":14}')`)
			}
		})
		b.callOn(h, adminHost, "PUT", "/settings/registration", map[string]any{"mode": "open"}).want(409, "")
		if fired != 1 {
			t.Fatalf("the seam ran %d times", fired)
		}
		if n := r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'registration_transition' AND state = 'queued'`); n != 1 {
			t.Fatalf("%d queued transition jobs: the other admin's job was ended and nothing replaced it", n)
		}
		if n := r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE progress ? 'superseded'`); n != 0 {
			t.Fatalf("%d jobs marked superseded by a request that changed nothing", n)
		}
	})

	t.Run("passkey RP ID", func(t *testing.T) {
		r := newRig(t)
		b, _ := r.admin(t)
		r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)
		b.put("/settings/webauthn", map[string]any{"rp_id": "example.test", "enabled": false}).want(200, "")
		r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)

		h := r.handler(t, func(d *Deps) {
			d.between = func() {
				r.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'panel.example.test'`)
				r.env.Exec(t, `INSERT INTO ctrlz.admin_jobs (kind, params) VALUES ('webauthn_rp_change', '{"rp_id":"panel.example.test"}')`)
			}
		})
		b.callOn(h, adminHost, "PUT", "/settings/webauthn", map[string]any{"rp_id": "panel.example.test", "enabled": false}).want(409, "")
		if n := r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'webauthn_rp_change' AND state = 'queued'`); n != 1 {
			t.Fatalf("%d queued RP jobs: the other admin's job was lost", n)
		}
	})
}

// TestABusyPasswordChangeStaysA503WhenItsTryCannotBeGivenBack is admin-r7-4 and -8. The route gives
// the admin_reauth try back when the Argon2 gate is full, and a failure of that refund (a dropped
// connection, a statement timeout) used to panic: the client got a plain-text 500 and the log a
// stack trace where every other busy answer is the JSON 503 with Retry-After. The refund is best
// effort like the tenant reauth's and proof.Spec's. The fault is a refund the database refuses.
func TestABusyPasswordChangeStaysA503WhenItsTryCannotBeGivenBack(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	b := r.browser()
	b.login(adminPW, "").want(200, "")
	r.env.Exec(t, `DO $$ DECLARE f regprocedure; BEGIN
		FOR f IN SELECT oid::regprocedure FROM pg_proc WHERE proname = 'admin_throttle_refund' LOOP
			EXECUTE 'REVOKE EXECUTE ON FUNCTION ' || f || ' FROM ctrlz_admin';
		END LOOP; END $$`)

	gate := password.NewGate(1, 50*time.Millisecond)
	release, err := gate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	busy, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	h := r.handler(t, func(d *Deps) { d.Hasher = busy })
	res := b.callOn(h, adminHost, "POST", "/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW})
	res.want(503, "server_busy")
	if res.H.Get("Retry-After") == "" || res.H.Get("Content-Type") != "application/json" {
		t.Errorf("the busy answer lost its shape: %v", res.H)
	}
	if log := r.logs.String(); strings.Contains(log, "handler panicked") || !strings.Contains(log, "could not give its try back") {
		t.Errorf("the log of a failed refund: %q", log)
	}
}

// TestAnAdminTotpChargeIsNotAProofForAnotherAdminOrSession is primitives-r7-8. checkAdminTOTP used
// to build the expectation of throttle.Counted from the charge's own fields, so it held for every
// non-zero charge and a route that charged one admin and checked the code of another passed every
// test; the guess at the second admin's code would have been counted on the first one's scope.
// The expectation now comes from the call's own arguments.
func TestAnAdminTotpChargeIsNotAProofForAnotherAdminOrSession(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, true)
	s := &Server{
		d: r.deps, hasher: r.hasher, strength: pwstrength.New(),
		throttle: throttle.NewAdmin(r.deps.Store.Admin(), r.deps.Keys),
		markers:  marker.New(r.deps.Keys, r.deps.Sessions.Now),
	}
	other := uuid.New()
	seal := func(id uuid.UUID) []byte {
		seed, err := totp.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		ct, err := r.keys.Seal(keyring.DomainAdminTOTP, totp.AdminAAD(id), seed.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		return ct
	}
	ctx := context.Background()
	sess, sess2 := uuid.New(), uuid.New()
	loginCharge, err := s.totpHit(ctx, seedAdmin)
	if err != nil {
		t.Fatal(err)
	}
	sessCharge, err := s.chargeTOTP(ctx, throttle.AdminTOTPSession, throttle.Who{Session: sess})
	if err != nil {
		t.Fatal(err)
	}
	check := func(c totpCharge, admin, session uuid.UUID) error {
		return s.global(ctx, func(g store.GlobalTx) error {
			if session == uuid.Nil {
				return s.checkAdminTOTP(g, c, admin, seal(admin), "000000", nil)
			}
			return s.checkSessionTOTP(g, c, admin, session, seal(admin), "000000", nil)
		})
	}
	// Each of these is a wrong code behind a right charge (the check runs and says invalid) ...
	if err := check(loginCharge, seedAdmin, uuid.Nil); errors.Is(err, throttle.ErrNotCharged) || err == nil {
		t.Errorf("the charge of its own admin: %v, want the check to run", err)
	}
	if err := check(sessCharge, seedAdmin, sess); errors.Is(err, throttle.ErrNotCharged) || err == nil {
		t.Errorf("the charge of its own session: %v, want the check to run", err)
	}
	// ... and each of these is refused before the code is looked at.
	for name, err := range map[string]error{
		"another admin":   check(loginCharge, other, uuid.Nil),
		"another session": check(sessCharge, seedAdmin, sess2),
		"a login charge used for a session check": check(loginCharge, seedAdmin, sess),
		"a session charge used for a login check": check(sessCharge, seedAdmin, uuid.Nil),
		"a zero charge": check(totpCharge{}, seedAdmin, uuid.Nil),
	} {
		if !errors.Is(err, throttle.ErrNotCharged) {
			t.Errorf("%s: %v, want throttle.ErrNotCharged", name, err)
		}
	}
}

// TestAnAdminPasswordWithACompatibilityCharacterIsScoredOnWhatWasTyped is primitives-r7-5 on the
// admin route: 'Password12345' plus U+FDFB is 14 typed code points and was accepted with score 4
// when the scorer saw the NFKC form only.
func TestAnAdminPasswordWithACompatibilityCharacterIsScoredOnWhatWasTyped(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": "Password12345ﷻ"}).want(422, "password_weak")
}
