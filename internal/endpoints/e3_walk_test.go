package endpoints_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// E3 as a walk (docs/specs/p3-endpoints.md 11.2; review round 1 of D6, p3-D6-r1-2, -11 and -13). Every operation of 3.3 that
// can take a locked profile out of a stack, in its single, batch and by-selector forms, is run against rows that stand on a locked
// profile, and each must give the answers of the rule:
//
//   - no password: 423 profile_locked, nothing verified, nothing written;
//   - a wrong password: 401 invalid_credentials naming /lock_passwords/0, the failure recorded (the charge of profile_unlock is the
//     verifier's), nothing written;
//   - an API token, with a password or without: 403 token_not_allowed, nothing verified, nothing written;
//   - the profile relocked with another password, or unlocked, between the check and the write: 409 conflict, nothing written, and
//     the password that was confirmed still recorded as used;
//   - the right password: the change is made and the verifier hears of the accepted password.
//
// A walk, not named cases: a route that skips Guard.Check, a batch whose before and after are taken on the wrong side of the write,
// or a guard that drops the hash comparison of Guard.Begin, fails the one case that runs it.

// e3Case makes the rows of one operation while the profile L is not locked yet (so that rows may stand on it), and returns the
// request.
type e3Case struct {
	name  string
	setup func(t *testing.T, f *fx, L, U uuid.UUID) (run func(a endpoints.Auth) error)
}

// fingerprint is the state a request may change, as one hash over the rows of the tables that the write path writes and the
// outbox: a refused request leaves it as it was, and the one that is accepted moves it.
func (f *fx) fingerprint(t *testing.T) string {
	t.Helper()
	var h string
	f.scan(t, `SELECT md5(coalesce(string_agg(r, '|' ORDER BY r), '')) FROM (
  SELECT row_to_json(e)::text AS r FROM ctrlz.endpoints e WHERE tenant_id = $1
  UNION ALL SELECT row_to_json(c)::text FROM ctrlz.clients c WHERE tenant_id = $1
  UNION ALL SELECT row_to_json(w)::text FROM ctrlz.schedule_windows w WHERE tenant_id = $1
  UNION ALL SELECT row_to_json(a)::text FROM ctrlz.authorized_ips a WHERE tenant_id = $1
  UNION ALL SELECT row_to_json(d)::text FROM ctrlz.endpoint_ddns_hosts d WHERE tenant_id = $1
  UNION ALL SELECT row_to_json(i)::text FROM ctrlz.ip_claims i WHERE tenant_id = $1
  UNION ALL SELECT row_to_json(o)::text FROM ctrlz.policy_outbox o WHERE tenant_id = $1) s`, []any{f.A.Tenant}, &h)
	return h
}

func asRefusal(err error) *endpoints.Error {
	var e *endpoints.Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

func TestE3WalkEveryOperationFiveAnswers(t *testing.T) {
	soft := "soft_disabled"
	on := true
	cases := []e3Case{
		{"an edit of the base profile", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.Patch{ProfileID: &U})
				return err
			}
		}},
		{"a batch edit of two Endpoints", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			e1, e2 := f.createWith(t, endpoints.CreateIn{ProfileID: L}), f.createWith(t, endpoints.CreateIn{ProfileID: L})
			return func(a endpoints.Auth) error {
				_, err := f.env.Batch(f.ctx, f.st, f.A.Tenant, opts, a, endpoints.BatchIn{IDs: []uuid.UUID{e1.ID, e2.ID}, Op: "edit", Set: endpoints.Patch{ProfileID: &U}})
				return err
			}
		}},
		{"a batch delete of two Endpoints", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			e1, e2 := f.createWith(t, endpoints.CreateIn{ProfileID: L}), f.createWith(t, endpoints.CreateIn{ProfileID: U})
			return func(a endpoints.Auth) error {
				_, err := f.env.Batch(f.ctx, f.st, f.A.Tenant, opts, a, endpoints.BatchIn{IDs: []uuid.UUID{e1.ID, e2.ID}, Op: "delete"})
				return err
			}
		}},
		{"the delete of one Endpoint", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
			return func(a endpoints.Auth) error {
				return f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, a, []uuid.UUID{ep.ID})
			}
		}},
		{"a rotation", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
			return func(a endpoints.Auth) error {
				_, err := f.env.Rotate(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID)
				return err
			}
		}},
		{"a switch to Soft Disabled", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.Patch{AdminState: &soft})
				return err
			}
		}},
		{"a schedule that covers the week with another profile", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
			return func(a endpoints.Auth) error {
				_, err := f.env.SetSchedule(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID,
					endpoints.ScheduleIn{Timezone: "Asia/Tehran", Windows: []endpoints.WindowIn{{Start: 0, End: 10080, ProfileID: U}}})
				return err
			}
		}},
		{"a client made with a stack of its own over a locked base", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
			return func(a endpoints.Auth) error {
				_, err := f.env.CreateClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ClientCreate{Alias: "own stack", ProfileID: U})
				return err
			}
		}},
		{"a client moved off a locked profile", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, c := f.withClients(t, L, U, 1)
			return func(a endpoints.Auth) error {
				_, err := f.env.PatchClient(f.ctx, f.st, f.A.Tenant, opts, a, ep, c[0].ID, endpoints.ClientChange{ProfileID: &U})
				return err
			}
		}},
		{"a batch delete of clients by id", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, c := f.withClients(t, L, U, 2)
			return func(a endpoints.Auth) error {
				_, _, err := f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep, endpoints.ClientBatchIn{Op: "delete", IDs: []uuid.UUID{c[0].ID, c[1].ID}})
				return err
			}
		}},
		{"a batch edit of clients by id", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, c := f.withClients(t, L, U, 2)
			return func(a endpoints.Auth) error {
				_, _, err := f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep,
					endpoints.ClientBatchIn{Op: "edit", IDs: []uuid.UUID{c[0].ID, c[1].ID}, Change: endpoints.ClientChange{ClearProfile: true}})
				return err
			}
		}},
		{"a batch edit of clients by selector", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, _ := f.withClients(t, L, U, 2)
			return func(a endpoints.Auth) error {
				_, _, err := f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep, endpoints.ClientBatchIn{Op: "edit", All: true, Change: endpoints.ClientChange{ProfileID: &U}})
				return err
			}
		}},
		{"a batch delete of clients by selector", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, _ := f.withClients(t, L, U, 2)
			return func(a endpoints.Auth) error {
				_, _, err := f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep, endpoints.ClientBatchIn{Op: "delete", All: true})
				return err
			}
		}},
		{"Require Authorized IPs switched on", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
			f.addAuthorized(t, f.A.Tenant, ep.ID, "203.0.113.110")
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.Patch{RequireAuthorizedIPs: &on})
				return err
			}
		}},
		{"a delete of an authorized row under Require", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, rows := f.requiring(t, L, "203.0.113.111", "203.0.113.112")
			return func(a endpoints.Auth) error {
				return f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep, []uuid.UUID{rows[0].ID}, netip.Addr{})
			}
		}},
		{"a cleanup opt-in under Require", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, rows := f.requiring(t, L, "203.0.113.113", "203.0.113.114")
			return func(a endpoints.Auth) error {
				_, err := f.env.SetCleanupOptIn(f.ctx, f.st, f.A.Tenant, opts, a, ep, rows[1].ID, true, netip.Addr{})
				return err
			}
		}},
		{"a DDNS host delete under Require, with learned rows", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, _ := f.requiring(t, L, "203.0.113.115")
			host, err := f.env.CreateDDNSHost(f.ctx, f.st, f.A.Tenant, opts, ep, "walk.example.org")
			if err != nil {
				t.Fatal(err)
			}
			f.exec(t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, ddns_host_id) VALUES ($1, $2, '203.0.113.116/32', 'ddns', $3)`, f.A.Tenant, ep, host.ID)
			return func(a endpoints.Auth) error {
				return f.env.DeleteDDNSHost(f.ctx, f.st, f.A.Tenant, opts, a, ep, host.ID, netip.Addr{})
			}
		}},
		// An Endpoint whose only reference to the locked profile is a client's own stack: the client's identity goes with the Endpoint,
		// its credential or its filtering, so the password of 3.3 is asked for although the base is unlocked (p3-D6-r2-2).
		{"the delete of an Endpoint whose only locked profile is a client's", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, _ := f.withClients(t, L, U, 1)
			return func(a endpoints.Auth) error {
				return f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, a, []uuid.UUID{ep})
			}
		}},
		{"a batch delete of an Endpoint whose only locked profile is a client's", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, _ := f.withClients(t, L, U, 2)
			free := f.createWith(t, endpoints.CreateIn{ProfileID: U})
			return func(a endpoints.Auth) error {
				_, err := f.env.Batch(f.ctx, f.st, f.A.Tenant, opts, a, endpoints.BatchIn{IDs: []uuid.UUID{ep, free.ID}, Op: "delete"})
				return err
			}
		}},
		{"a rotation of an Endpoint whose only locked profile is a client's", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, _ := f.withClients(t, L, U, 1)
			return func(a endpoints.Auth) error {
				_, err := f.env.Rotate(f.ctx, f.st, f.A.Tenant, opts, a, ep)
				return err
			}
		}},
		{"a switch to Soft Disabled of an Endpoint whose only locked profile is a client's", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, _ := f.withClients(t, L, U, 1)
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep, endpoints.Patch{AdminState: &soft})
				return err
			}
		}},
		{"a batch switch to Soft Disabled of an Endpoint whose only locked profile is a client's", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep, _ := f.withClients(t, L, U, 1)
			return func(a endpoints.Auth) error {
				_, err := f.env.Batch(f.ctx, f.st, f.A.Tenant, opts, a, endpoints.BatchIn{IDs: []uuid.UUID{ep}, Op: "edit", Set: endpoints.Patch{AdminState: &soft}})
				return err
			}
		}},
		// The operations that are named in 3.3 and were only checked for 423 and success in the named cases (p3-D6-r2-4 and -8).
		{"a timezone change that moves a window of the locked profile", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: U})
			if _, err := f.env.SetSchedule(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), ep.ID,
				endpoints.ScheduleIn{Timezone: "Asia/Tehran", Windows: []endpoints.WindowIn{{Start: 600, End: 660, ProfileID: L}}}); err != nil {
				t.Fatal(err)
			}
			tokyo := "Asia/Tokyo"
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.Patch{ScheduleTimezone: &tokyo})
				return err
			}
		}},
		{"the two slots swapped with the locked profile last", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L, Profile2ID: U})
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.Patch{ProfileID: &U, Profile2ID: &L})
				return err
			}
		}},
		{"Profile 2 cleared while it is the locked one", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: U, Profile2ID: L})
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.Patch{ClearProfile2: true})
				return err
			}
		}},
		{"Legacy DNS off with an active claim", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L, LegacyDNS: true})
			f.claimOf(t, ep.ID, "203.0.113.130/32")
			off := false
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.Patch{LegacyDNS: &off})
				return err
			}
		}},
		{"the release of the last active claim", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L, LegacyDNS: true})
			c := f.claimOf(t, ep.ID, "203.0.113.131/32")
			return func(a endpoints.Auth) error {
				return f.env.ReleaseClaim(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, c.ID)
			}
		}},
		{"hard to soft", func(t *testing.T, f *fx, L, U uuid.UUID) func(endpoints.Auth) error {
			ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
			f.exec(t, `UPDATE ctrlz.endpoints SET admin_state = 'hard_disabled' WHERE id = $1`, ep.ID)
			return func(a endpoints.Auth) error {
				_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.Patch{AdminState: &soft})
				return err
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFx(t)
			f.walk(t, c)
		})
	}
}

// withClients makes an Endpoint on the unlocked profile U with n manual clients that stand on L, and returns the Endpoint and them.
func (f *fx) withClients(t *testing.T, L, U uuid.UUID, n int) (uuid.UUID, []store.ClientRow) {
	t.Helper()
	ep := f.createWith(t, endpoints.CreateIn{ProfileID: U})
	var out []store.ClientRow
	for i := 0; i < n; i++ {
		c, err := f.env.CreateClient(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), ep.ID,
			endpoints.ClientCreate{Alias: "walk " + uuid.NewString()[:6], ProfileID: L})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return ep.ID, out
}

// requiring makes an Endpoint on L with the given authorized rows and Require Authorized IPs on.
func (f *fx) requiring(t *testing.T, L uuid.UUID, cidrs ...string) (uuid.UUID, []store.AuthorizedRow) {
	t.Helper()
	ep := f.createWith(t, endpoints.CreateIn{ProfileID: L})
	rows := f.addAuthorized(t, f.A.Tenant, ep.ID, cidrs...)
	if err := f.require(t, f.A.Tenant, ep.ID, &fakeVerifier{}, true); err != nil {
		t.Fatal(err)
	}
	return ep.ID, rows
}

func (f *fx) walk(t *testing.T, c e3Case) {
	t.Helper()
	A := f.A.Tenant
	L := f.newProfile(t, A, "walk locked")
	U := f.newProfile(t, A, "walk plain")
	run := c.setup(t, f, L, U)
	f.lock(t, L)
	start := f.fingerprint(t)
	untouched := func(step string) {
		t.Helper()
		if f.fingerprint(t) != start {
			t.Errorf("%s: a refused request wrote", step)
		}
	}
	kind := func(step string, err error, want endpoints.Kind) *endpoints.Error {
		t.Helper()
		e := asRefusal(err)
		if e == nil || e.Kind != want {
			t.Fatalf("%s: want %v, got %v", step, want, err)
		}
		return e
	}

	// 1. No password.
	v := &fakeVerifier{right: rightPassword}
	e := kind("no password", run(f.auth(A, v)), endpoints.KindLocked)
	if !hasField(e, "/lock_passwords", endpoints.CodeRequired) || len(v.calls) != 0 || len(v.failed) != 0 {
		t.Errorf("no password: %+v, verified %d, failed %d", e, len(v.calls), len(v.failed))
	}
	untouched("no password")

	// 2. A wrong password: the failure is recorded and the request is 401 on the first password.
	v = &fakeVerifier{right: rightPassword}
	e = kind("a wrong password", run(f.auth(A, v, pw(L, "wrong"))), endpoints.KindInvalidCredentials)
	if !hasField(e, "/lock_passwords/0", endpoints.CodeInvalid) || !slices.Equal(v.failed, []uuid.UUID{L}) || len(v.accepted) != 0 {
		t.Errorf("a wrong password: %+v, failed %v, accepted %v", e, v.failed, v.accepted)
	}
	untouched("a wrong password")

	// 3. A token carries no lock password: with none or with one, it is 403 and nothing is verified.
	for _, pws := range [][]endpoints.Password{nil, {pw(L, rightPassword)}} {
		v = &fakeVerifier{right: rightPassword}
		tokenAuth := endpoints.Auth{Passwords: pws, Actor: endpoints.Actor{User: f.A.User, Token: true}, Verifier: v}
		kind("a token", run(tokenAuth), endpoints.KindTokenNotAllowed)
		if len(v.calls) != 0 || len(v.failed) != 0 {
			t.Errorf("a token: %d passwords verified, %d failures recorded", len(v.calls), len(v.failed))
		}
		untouched("a token")
	}

	// 4. The password is changed between the check and the write.
	v = &fakeVerifier{right: rightPassword}
	v.onCheck = func() { f.exec(t, `UPDATE ctrlz.profiles SET lock_password_hash = 'h-changed' WHERE id = $1`, L) }
	kind("a rotated lock password", run(f.auth(A, v, pw(L, rightPassword))), endpoints.KindConflict)
	if !slices.Equal(v.used, []uuid.UUID{L}) || len(v.accepted) != 0 {
		t.Errorf("a rotated lock password: used %v, accepted %v", v.used, v.accepted)
	}
	untouched("a rotated lock password")
	f.lock(t, L)

	// 5. The profile is unlocked between the check and the write: what was verified stands for nothing.
	v = &fakeVerifier{right: rightPassword}
	v.onCheck = func() {
		f.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'unlocked', lock_password_hash = NULL WHERE id = $1`, L)
	}
	kind("an unlocked profile", run(f.auth(A, v, pw(L, rightPassword))), endpoints.KindConflict)
	if !slices.Equal(v.used, []uuid.UUID{L}) || len(v.accepted) != 0 {
		t.Errorf("an unlocked profile: used %v, accepted %v", v.used, v.accepted)
	}
	untouched("an unlocked profile")
	f.lock(t, L)

	// 6. The right password.
	v = &fakeVerifier{right: rightPassword}
	if err := run(f.auth(A, v, pw(L, rightPassword))); err != nil {
		t.Fatalf("the right password was refused: %v", err)
	}
	if !slices.Contains(v.accepted, L) {
		t.Errorf("the verifier was not told the password was accepted: %v", v.accepted)
	}
	if f.fingerprint(t) == start {
		t.Error("the right password was accepted and nothing was written")
	}
}

// The two switches that stop the hub from adding rows leave every row alone: with Require on and a locked base, turning
// Authorize by Secure DNS or by Dynamic DNS off needs no password and deletes nothing (spec 3.3, 5; p3-D6-r1-13).
func TestE3AuthorizeSwitchesOffNeedNoPasswordAndKeepEveryRow(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	L := f.newProfile(t, A, "switches locked")
	ep, _ := f.requiring(t, L, "203.0.113.120", "203.0.113.121")
	on, off := true, false
	if _, err := f.env.Patch(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), ep, endpoints.Patch{AuthorizeSecureDNS: &on, AuthorizeDDNS: &on}); err != nil {
		t.Fatal(err)
	}
	f.lock(t, L)
	rows := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1`, ep)
	for name, p := range map[string]endpoints.Patch{
		"Authorize by Secure DNS off":      {AuthorizeSecureDNS: &off},
		"Authorize by Dynamic DNS off":     {AuthorizeDDNS: &off},
		"both off in one request":          {AuthorizeSecureDNS: &off, AuthorizeDDNS: &off},
		"both on again, with Require left": {AuthorizeSecureDNS: &on, AuthorizeDDNS: &on},
	} {
		v := &fakeVerifier{right: rightPassword}
		if _, err := f.env.Patch(f.ctx, f.st, A, opts, f.auth(A, v), ep, p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if len(v.calls) != 0 {
			t.Errorf("%s: a password was verified", name)
		}
		if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1`, ep); n != rows {
			t.Errorf("%s: %d rows, want the %d it had", name, n, rows)
		}
	}
}

// claimOf makes an active claim of the tenant on the Endpoint (a Plain DNS identity while Legacy DNS is on), raising the limit first.
func (f *fx) claimOf(t *testing.T, ep uuid.UUID, cidr string) store.ClaimRow {
	t.Helper()
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 20 WHERE tenant_id = $1`, f.A.Tenant)
	r, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, ep, endpoints.ClaimAsk{Cidr: &cidr})
	if err != nil || r.Claim.State != "active" {
		t.Fatalf("claim %s: %v %+v", cidr, err, r)
	}
	return r.Claim
}
