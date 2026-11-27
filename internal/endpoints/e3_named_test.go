package endpoints_test

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// E3 (docs/specs/p3-endpoints.md 11.2) at the database: the named cases of the lock rule of 3.3, each against rows made by the
// request that is judged, and the concurrent pair that must never remove a locked profile with no password. The comparison of
// Needed with the 15-minute reference over generated states is TestNeededMatchesTheReference (needed_test.go), which has no
// database; here the answers come from Postgres rows, so a route that forgets to take part in the rule shows.

const rightPassword = "right-password"

// needsPassword runs one request as the test's tenant. When want is true the request carries no password and must be refused
// 423 with nothing verified, and then carries the right one and must pass; when it is false it passes with none and verifies
// nothing. A request that is refused must leave its rows as they were, which the caller checks through undone.
func (f *fx) needsPassword(t *testing.T, name string, locked uuid.UUID, want bool, run func(a endpoints.Auth) error, undone func() bool) {
	t.Helper()
	v := &fakeVerifier{right: rightPassword}
	err := run(f.auth(f.A.Tenant, v))
	if !want {
		if err != nil {
			t.Errorf("%s: needs no password, got %v", name, err)
		}
		if len(v.calls) != 0 {
			t.Errorf("%s: a password was verified for a request that needs none", name)
		}
		return
	}
	if err == nil {
		t.Errorf("%s: a locked profile left with no password", name)
		return
	}
	var e *endpoints.Error
	if !errors.As(err, &e) || e.Kind != endpoints.KindLocked || !hasField(e, "/lock_passwords", endpoints.CodeRequired) {
		t.Errorf("%s: want 423 profile_locked, got %v", name, err)
		return
	}
	if len(v.calls) != 0 {
		t.Errorf("%s: the refusal verified or charged a password", name)
	}
	if undone != nil && !undone() {
		t.Errorf("%s: a refused request wrote", name)
	}
	if err := run(f.auth(f.A.Tenant, v, pw(locked, rightPassword))); err != nil {
		t.Errorf("%s: the right password was refused: %v", name, err)
	}
}

func (f *fx) createWith(t *testing.T, in endpoints.CreateIn) store.EndpointRow {
	t.Helper()
	in.Type = f.typ
	if in.Names == nil {
		in.Names = []string{"e3-" + uuid.NewString()[:8]}
	}
	rows, err := f.env.Create(f.ctx, f.st, f.A.Tenant, opts, in)
	if err != nil {
		t.Fatal(err)
	}
	return rows[0]
}

func (f *fx) profileOf(t *testing.T, ep uuid.UUID) (p, p2 string) {
	t.Helper()
	var q *string
	f.scan(t, `SELECT profile_id::text, profile2_id::text FROM ctrlz.endpoints WHERE id = $1`, []any{ep}, &p, &q)
	if q != nil {
		p2 = *q
	}
	return p, p2
}

func (f *fx) stateOf(t *testing.T, ep uuid.UUID) string {
	t.Helper()
	var s string
	f.scan(t, `SELECT admin_state FROM ctrlz.endpoints WHERE id = $1`, []any{ep}, &s)
	return s
}

func TestE3NamedCases(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	L := f.newProfile(t, A, "locked")
	U := f.newProfile(t, A, "plain")
	patch := func(ep uuid.UUID, p endpoints.Patch) func(a endpoints.Auth) error {
		return func(a endpoints.Auth) error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep, p)
			return err
		}
	}
	schedule := func(ep uuid.UUID, tz string, ws ...endpoints.WindowIn) func(a endpoints.Auth) error {
		return func(a endpoints.Auth) error {
			_, err := f.env.SetSchedule(f.ctx, f.st, A, opts, a, ep, endpoints.ScheduleIn{Timezone: tz, Windows: ws})
			return err
		}
	}
	noWindows := func(ep uuid.UUID) func() bool {
		return func() bool {
			return f.count(t, `SELECT count(*) FROM ctrlz.schedule_windows WHERE endpoint_id = $1`, ep) == 0
		}
	}
	unchangedBase := func(ep uuid.UUID, want uuid.UUID) func() bool {
		return func() bool {
			p, _ := f.profileOf(t, ep)
			return p == want.String()
		}
	}

	// A full-week window of an unlocked profile over a locked base pushes the base aside at every instant.
	over := f.createWith(t, endpoints.CreateIn{ProfileID: L})
	f.lock(t, L)
	f.needsPassword(t, "a full-week window of an unlocked profile over a locked base", L, true,
		schedule(over.ID, "Asia/Tehran", endpoints.WindowIn{Start: 0, End: 10080, ProfileID: U}), noWindows(over.ID))
	// The other way, a window of the locked profile over an unlocked base only adds it.
	under := f.createWith(t, endpoints.CreateIn{ProfileID: U})
	f.needsPassword(t, "a window of a locked profile over an unlocked base", L, false,
		schedule(under.ID, "Asia/Tehran", endpoints.WindowIn{Start: 0, End: 10080, ProfileID: L}), nil)

	// A client moved to an unlocked profile, and one sent back to the base, each lose the locked profile they had.
	kids := f.createWith(t, endpoints.CreateIn{ProfileID: U})
	mk := func(alias string) store.ClientRow {
		c, err := f.env.CreateClient(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), kids.ID, endpoints.ClientCreate{Alias: alias, ProfileID: L})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	moved, cleared := mk("moved"), mk("cleared")
	f.needsPassword(t, "a client moved to an unlocked profile", L, true, func(a endpoints.Auth) error {
		_, err := f.env.PatchClient(f.ctx, f.st, A, opts, a, kids.ID, moved.ID, endpoints.ClientChange{ProfileID: &U})
		return err
	}, func() bool {
		return f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE id = $1 AND profile_id = $2`, moved.ID, L) == 1
	})
	f.needsPassword(t, "a client sent back to the base", L, true, func(a endpoints.Auth) error {
		_, err := f.env.PatchClient(f.ctx, f.st, A, opts, a, kids.ID, cleared.ID, endpoints.ClientChange{ClearProfile: true})
		return err
	}, func() bool {
		return f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE id = $1 AND profile_id = $2`, cleared.ID, L) == 1
	})
	// A client of the same Endpoint that has no stack of its own is renamed for nothing.
	plain, err := f.env.CreateClient(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), kids.ID, endpoints.ClientCreate{Alias: "no stack"})
	if err != nil {
		t.Fatal(err)
	}
	newAlias := "renamed"
	f.needsPassword(t, "a client with no stack renamed", L, false, func(a endpoints.Auth) error {
		_, err := f.env.PatchClient(f.ctx, f.st, A, opts, a, kids.ID, plain.ID, endpoints.ClientChange{Alias: &newAlias})
		return err
	}, nil)

	// The two slots: a swap that moves the locked profile later needs the password, one that moves it earlier does not, and
	// taking Profile 2 away does.
	late := f.createWith(t, endpoints.CreateIn{ProfileID: L, Profile2ID: U})
	f.needsPassword(t, "the two slots swapped, the locked profile last", L, true,
		patch(late.ID, endpoints.Patch{ProfileID: &U, Profile2ID: &L}), unchangedBase(late.ID, L))
	early := f.createWith(t, endpoints.CreateIn{ProfileID: U, Profile2ID: L})
	f.needsPassword(t, "the two slots swapped, the locked profile first", L, false,
		patch(early.ID, endpoints.Patch{ProfileID: &L, Profile2ID: &U}), nil)
	slot2 := f.createWith(t, endpoints.CreateIn{ProfileID: U, Profile2ID: L})
	f.needsPassword(t, "Profile 2 cleared while it is the locked one", L, true,
		patch(slot2.ID, endpoints.Patch{ClearProfile2: true}), func() bool { _, p2 := f.profileOf(t, slot2.ID); return p2 == L.String() })

	// A zone change moves a window of the locked profile off the instants it covered.
	zone := f.createWith(t, endpoints.CreateIn{ProfileID: U})
	if err := schedule(zone.ID, "Asia/Tehran", endpoints.WindowIn{Start: 600, End: 660, ProfileID: L})(f.auth(A, &fakeVerifier{})); err != nil {
		t.Fatal(err)
	}
	tokyo := "Asia/Tokyo"
	f.needsPassword(t, "a timezone change that moves a locked profile's window", L, true,
		patch(zone.ID, endpoints.Patch{ScheduleTimezone: &tokyo}), func() bool {
			return f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND schedule_timezone = 'Asia/Tehran'`, zone.ID) == 1
		})

	// A disabled Endpoint is read from its rows: edited so the locked profile goes, or deleted, it needs the password; renamed it does not.
	soft, hard, enabled := "soft_disabled", "hard_disabled", "enabled"
	dis := f.createWith(t, endpoints.CreateIn{ProfileID: U})
	if err := patch(dis.ID, endpoints.Patch{ProfileID: &L})(f.auth(A, &fakeVerifier{})); err != nil {
		t.Fatal(err)
	}
	f.needsPassword(t, "a switch to Soft Disabled", L, true, patch(dis.ID, endpoints.Patch{AdminState: &soft}), func() bool { return f.stateOf(t, dis.ID) == enabled })
	name := "still mine"
	f.needsPassword(t, "a rename of a disabled Endpoint", L, false, patch(dis.ID, endpoints.Patch{Name: &name}), nil)
	f.needsPassword(t, "an edit of a disabled Endpoint that takes the locked profile off", L, true,
		patch(dis.ID, endpoints.Patch{ProfileID: &U}), unchangedBase(dis.ID, L))
	gone := f.createWith(t, endpoints.CreateIn{ProfileID: L})
	f.exec(t, `UPDATE ctrlz.endpoints SET admin_state = 'soft_disabled' WHERE id = $1`, gone.ID)
	f.needsPassword(t, "a delete of a disabled Endpoint", L, true, func(a endpoints.Auth) error {
		return f.env.Delete(f.ctx, f.st, A, opts, a, []uuid.UUID{gone.ID})
	}, func() bool { return f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1`, gone.ID) == 1 })

	// Hard to soft turns a dead Endpoint into unfiltered DNS, and soft to hard is a move between two disabled states: both need it.
	h2s := f.createWith(t, endpoints.CreateIn{ProfileID: U})
	if err := patch(h2s.ID, endpoints.Patch{ProfileID: &L})(f.auth(A, &fakeVerifier{})); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE ctrlz.endpoints SET admin_state = 'hard_disabled' WHERE id = $1`, h2s.ID)
	f.needsPassword(t, "hard to soft", L, true, patch(h2s.ID, endpoints.Patch{AdminState: &soft}), func() bool { return f.stateOf(t, h2s.ID) == hard })
	s2h := f.createWith(t, endpoints.CreateIn{ProfileID: L})
	f.exec(t, `UPDATE ctrlz.endpoints SET admin_state = 'soft_disabled' WHERE id = $1`, s2h.ID)
	f.needsPassword(t, "soft to hard", L, true, patch(s2h.ID, endpoints.Patch{AdminState: &hard}), func() bool { return f.stateOf(t, s2h.ID) == soft })
	// Back to enabled adds a profile to the traffic: nothing is needed.
	f.needsPassword(t, "soft back to enabled", L, false, patch(s2h.ID, endpoints.Patch{AdminState: &enabled}), nil)
}

// The Plain DNS identities of an Endpoint: one per active claim while Legacy DNS is on, each answered by the base stack (spec
// 3.3, SC 5.2a), so each goes when its claim goes and all go when Legacy DNS goes off.
func TestE3PlainDNSIdentities(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	L := f.newProfile(t, A, "locked")
	f.lock(t, L)
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 20 WHERE tenant_id = $1`, A)
	claim := func(ep uuid.UUID, cidr string) store.ClaimRow {
		r, err := f.env.RequestClaim(f.ctx, f.st, A, opts, ep, endpoints.ClaimAsk{Cidr: &cidr})
		if err != nil || r.Claim.State != "active" {
			t.Fatalf("claim %s: %v %+v", cidr, err, r)
		}
		return r.Claim
	}
	off := false
	legacyOff := func(ep uuid.UUID) func(a endpoints.Auth) error {
		return func(a endpoints.Auth) error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep, endpoints.Patch{LegacyDNS: &off})
			return err
		}
	}
	release := func(ep, claim uuid.UUID) func(a endpoints.Auth) error {
		return func(a endpoints.Auth) error { return f.env.ReleaseClaim(f.ctx, f.st, A, opts, a, ep, claim) }
	}
	live := func(c uuid.UUID) func() bool {
		return func() bool {
			return f.count(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE id = $1 AND state = 'active'`, c) == 1
		}
	}

	// Legacy DNS off with an active claim takes that claim's devices off the locked base.
	withClaim := f.createWith(t, endpoints.CreateIn{ProfileID: L, LegacyDNS: true})
	claim(withClaim.ID, "203.0.113.70/32")
	f.needsPassword(t, "Legacy DNS off with an active claim", L, true, legacyOff(withClaim.ID), func() bool {
		return f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND legacy_dns`, withClaim.ID) == 1
	})
	// With no claim there is no Plain DNS identity, so switching it off takes nobody off.
	bare := f.createWith(t, endpoints.CreateIn{ProfileID: L, LegacyDNS: true})
	f.needsPassword(t, "Legacy DNS off with no claim", L, false, legacyOff(bare.ID), nil)

	// A claim goes whatever other claims remain: the second of two is as guarded as the last.
	two := f.createWith(t, endpoints.CreateIn{ProfileID: L, LegacyDNS: true})
	a1, a2 := claim(two.ID, "203.0.113.71/32"), claim(two.ID, "203.0.113.72/32")
	f.needsPassword(t, "the release of one of two active claims", L, true, release(two.ID, a1.ID), live(a1.ID))
	f.needsPassword(t, "the release of the last active claim", L, true, release(two.ID, a2.ID), live(a2.ID))

	// With Legacy DNS off a claim carries no identity, so releasing it takes nothing away.
	quiet := f.createWith(t, endpoints.CreateIn{ProfileID: L, LegacyDNS: true})
	q := claim(quiet.ID, "203.0.113.73/32")
	f.exec(t, `UPDATE ctrlz.endpoints SET legacy_dns = false WHERE id = $1`, quiet.ID)
	f.needsPassword(t, "the release of a claim while Legacy DNS is off", L, false, release(quiet.ID, q.ID), nil)
}

// The concurrent pair of E3: a change of the base and the removal of a window each leave the locked profile somewhere when they
// run alone, and removed from both when they both commit. The Endpoint lock makes the second see the first, so one of them is
// refused every time; a pair that both pass has removed a locked profile with no password.
func TestE3ConcurrentPairNeverRemovesALockedProfile(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	L := f.newProfile(t, A, "locked")
	U := f.newProfile(t, A, "plain")
	ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
	f.lock(t, L)
	reset := func() {
		t.Helper()
		a := f.auth(A, &fakeVerifier{})
		if _, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{ProfileID: &L}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.env.SetSchedule(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ScheduleIn{Timezone: "Asia/Tehran",
			Windows: []endpoints.WindowIn{{Start: 0, End: 10080, ProfileID: L}}}); err != nil {
			t.Fatal(err)
		}
	}
	for round := 0; round < 6; round++ {
		reset()
		errs := make([]error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, errs[0] = f.env.Patch(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), ep.ID, endpoints.Patch{ProfileID: &U})
		}()
		go func() {
			defer wg.Done()
			_, errs[1] = f.env.SetSchedule(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), ep.ID, endpoints.ScheduleIn{Timezone: "Asia/Tehran"})
		}()
		wg.Wait()
		for i, err := range errs {
			var e *endpoints.Error
			if err != nil && !errors.As(err, &e) {
				t.Fatalf("round %d request %d ended in %v, which is no refusal of the write path", round, i, err)
			}
		}
		if errs[0] == nil && errs[1] == nil {
			t.Fatalf("round %d: both requests passed, and the locked profile is on neither the base nor a window", round)
		}
		base, _ := f.profileOf(t, ep.ID)
		windows := f.count(t, `SELECT count(*) FROM ctrlz.schedule_windows WHERE endpoint_id = $1 AND profile_id = $2`, ep.ID, L)
		if base != L.String() && windows == 0 {
			t.Fatalf("round %d: the locked profile was removed with no password (base %s, %d windows)", round, base, windows)
		}
	}
}

// E6 (spec 5, 11.2) at the database: the three rules against concurrent pairs. An Endpoint that requires its list never ends with
// none, whichever of the deleters, the Require switch and a DDNS host delete reach the Endpoint lock first.
func TestE6ConcurrentPairsNeverLeaveARequiringEndpointWithNone(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	remaining := func(ep uuid.UUID) int {
		return f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1`, ep)
	}
	requires := func(ep uuid.UUID) bool {
		return f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND require_authorized_ips`, ep) == 1
	}
	refusedOrNil := func(round int, what string, err error) {
		t.Helper()
		var e *endpoints.Error
		if err != nil && !errors.As(err, &e) {
			t.Fatalf("round %d, %s: %v is no refusal of the write path", round, what, err)
		}
	}
	a := func() endpoints.Auth { return f.auth(A, &fakeVerifier{}) }
	del := func(ep uuid.UUID, ids ...uuid.UUID) error {
		return f.env.DeleteAuthorized(f.ctx, f.st, A, opts, a(), ep, ids, netip.Addr{})
	}

	// Delete against delete of the last two.
	for round := 0; round < 6; round++ {
		ep := f.createWith(t, endpoints.CreateIn{ProfileID: f.A.Profile})
		rows := f.addAuthorized(t, A, ep.ID, "203.0.113.80", "203.0.113.81")
		if err := f.require(t, A, ep.ID, &fakeVerifier{}, true); err != nil {
			t.Fatal(err)
		}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range rows {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = del(ep.ID, rows[i].ID)
			}()
		}
		wg.Wait()
		refusedOrNil(round, "delete one", errs[0])
		refusedOrNil(round, "delete two", errs[1])
		if errs[0] == nil && errs[1] == nil || remaining(ep.ID) < 1 {
			t.Fatalf("round %d: both of the last two rows of an Endpoint that requires them were deleted (%d left)", round, remaining(ep.ID))
		}
	}

	// Delete against Require on: the Endpoint has one row, and the row goes while Require comes on, or the other way round.
	for round := 0; round < 6; round++ {
		ep := f.createWith(t, endpoints.CreateIn{ProfileID: f.A.Profile})
		rows := f.addAuthorized(t, A, ep.ID, "203.0.113.82")
		on := true
		var wg sync.WaitGroup
		var e1, e2 error
		wg.Add(2)
		go func() {
			defer wg.Done()
			e1 = del(ep.ID, rows[0].ID)
		}()
		go func() {
			defer wg.Done()
			_, e2 = f.env.Patch(f.ctx, f.st, A, opts, a(), ep.ID, endpoints.Patch{RequireAuthorizedIPs: &on})
		}()
		wg.Wait()
		refusedOrNil(round, "delete", e1)
		refusedOrNil(round, "require on", e2)
		if requires(ep.ID) && remaining(ep.ID) == 0 {
			t.Fatalf("round %d: Require Authorized IPs is on and the Endpoint has no row", round)
		}
	}

	// A DDNS host delete among the deleters: the host's learned rows and a manual row are all the Endpoint has.
	for round := 0; round < 6; round++ {
		ep := f.createWith(t, endpoints.CreateIn{ProfileID: f.A.Profile})
		host, err := f.env.CreateDDNSHost(f.ctx, f.st, A, opts, ep.ID, "round.example.org")
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, ddns_host_id) VALUES ($1, $2, '203.0.113.90/32', 'ddns', $3)`, A, ep.ID, host.ID)
		manual := f.addAuthorized(t, A, ep.ID, "203.0.113.91")
		if err := f.require(t, A, ep.ID, &fakeVerifier{}, true); err != nil {
			t.Fatal(err)
		}
		var e1, e2 error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			e1 = f.env.DeleteDDNSHost(f.ctx, f.st, A, opts, a(), ep.ID, host.ID, netip.Addr{})
		}()
		go func() {
			defer wg.Done()
			e2 = del(ep.ID, manual[0].ID)
		}()
		wg.Wait()
		refusedOrNil(round, "ddns host delete", e1)
		refusedOrNil(round, "manual delete", e2)
		if remaining(ep.ID) < 1 {
			t.Fatalf("round %d: a DDNS host delete and a delete left an Endpoint that requires its list with none", round)
		}
	}
}
