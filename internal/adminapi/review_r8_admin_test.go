package adminapi

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// oneTimeShaped is a password with the shape of a console one-time password (24 base32 characters,
// enough different ones). Tests plant its hash by hand, as the console does with the output of
// NewOneTime.
const oneTimeShaped = "ONETIMEPASSWORDXYZ234567"

// makeOneTime gives the seed admin a live console one-time password, hashed the way the console
// hashes it (the cheap hash that only a generated password may reach), and returns it. The older
// fixtures hashed a chosen password in full and called it one-time, which stopped working as a model
// of the first login once the handler refuses a spent class's request that cannot be one (admin-r8-1).
func (r *rig) makeOneTime(t *testing.T) string {
	t.Helper()
	hash, err := r.hasher.HashOneTime(secretOf(oneTimeShaped))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2, must_change_password = true,
	  password_expires_at = now() + interval '24 hours' WHERE id = $1`, seedAdmin, hash.Reveal())
	return oneTimeShaped
}

// deadStore is an admin store whose pool is closed: every read or write through it fails. A request
// that must make no database call is shown by getting its ordinary answer through it, and the control
// (a request that does call) is shown by the failure.
func (r *rig) deadStore(t *testing.T) *store.Store {
	t.Helper()
	dead, err := store.Open(r.env.Ctx, r.env.DB.StoreConfig(store.RoleAdmin))
	if err != nil {
		t.Fatal(err)
	}
	dead.Close()
	return dead
}

// TestARefusedLoginOfTheSpentClassMakesNoDatabaseCall is admin-r8-1 and admin-r8-4. Since round 7 the
// class admin-login (five a minute on the network) hands its refusal to the handler, which read the
// account and waited out the 500 ms floor before it refused: one source with no device marker could
// queue the owner's own requests behind junk logins on the small admin pool. The handler now answers
// the refusal before the floor and before any read unless the password can be a console one-time
// password, and reads in one of two slots for the passwords that can. The store behind the handler is
// closed, so any call it makes is a 5xx and not the 429 the test asks for.
func TestARefusedLoginOfTheSpentClassMakesNoDatabaseCall(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	otp := r.makeOneTime(t)
	dead := r.deadStore(t)
	h := r.handler(t, func(d *Deps) { d.Store = dead })

	junk := r.browser()
	// The first five are answered by the handler, which reaches the throttle through the closed store:
	// they fail with a server error, which is what shows that a call WOULD have been seen.
	for i := 0; i < 5; i++ {
		if res := junk.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": "wrong-wrong-wrong-1"}); res.Code < 500 {
			t.Fatalf("attempt %d through a closed store answered %d: the store is not what the test thinks it is", i+1, res.Code)
		}
	}
	// The class is spent. Every junk login is refused at once with the class's own answer and no read:
	// with a closed store, a read would be a 5xx.
	for i, pw := range []string{"wrong-wrong-wrong-1", "", "x", "short", "ONETIMEPASSWORDXYZ23456", "onetimepasswordxyz234567", "AAAAAAAAAAAAAAAAAAAAAAAA", "ONETIMEPASSWORDXYZ2345678"} {
		start := time.Now()
		res := junk.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": pw})
		res.want(429, "rate_limited")
		if res.H.Get("Retry-After") == "" {
			t.Errorf("junk %d: the refusal has no Retry-After", i)
		}
		if el := time.Since(start); el > floorLogin/4 {
			t.Errorf("junk %d was refused after %v: it waited for the floor or for a read", i, el)
		}
	}

	// The control: a password that can be the console's is let through to the read, which fails on
	// the closed store. Without it the test would pass for a handler that refuses everything.
	if res := junk.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": otp}); res.Code < 500 {
		t.Fatalf("a console-shaped password answered %d through a closed store: the read never ran", res.Code)
	}
	// The slot of a read that failed is given back: five more reach the read and none is refused.
	for i := 0; i < 5; i++ {
		if res := junk.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": "nobody-here", "password": otp}); res.Code < 500 {
			t.Fatalf("console-shaped attempt %d answered %d: a slot leaked", i+1, res.Code)
		}
	}
}

// TestShapedLoginsBeyondTheLookupSlotsAreRefusedAtOnce is the other half: a flood of passwords that
// DO have the console shape cannot queue reads either. With both slots held the next such login is
// answered with the class's refusal at once, through a closed store, and the declared price is that
// the owner's own first login is refused the same way while the flood holds the slots (spec 10.2).
func TestShapedLoginsBeyondTheLookupSlotsAreRefusedAtOnce(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	otp := r.makeOneTime(t)
	full := newLookupSlots(deferredLookupSlots)
	for i := 0; i < deferredLookupSlots; i++ {
		if _, ok := full.try(); !ok {
			t.Fatal("could not fill the slots")
		}
	}
	spent := r.browser()
	free := r.handler(t, func(d *Deps) {})
	// Spend the class from this network on a healthy handler.
	for i := 0; i < 6; i++ {
		spent.callOn(free, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": "wrong-wrong-wrong-1"})
	}
	spent.callOn(free, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": "wrong-wrong-wrong-1"}).want(429, "rate_limited")

	busy := r.handler(t, func(d *Deps) { d.Store = r.deadStore(t); d.lookupSlots = full })
	start := time.Now()
	spent.callOn(busy, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": otp}).want(429, "rate_limited")
	if d := time.Since(start); d > floorLogin/4 {
		t.Errorf("a shaped login with no free slot was refused after %v", d)
	}

	// With a free slot the same request reaches the account and signs the owner in.
	spent.callOn(free, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": otp}).want(200, "")
}
