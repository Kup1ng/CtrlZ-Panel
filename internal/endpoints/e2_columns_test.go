package endpoints_test

import (
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
)

// E2 (docs/specs/p3-endpoints.md 11.2) at the database, one case per column of the compile map of 3.2: a change of a compiled
// source writes exactly one endpoint_set row, a change of any other column writes none, and a request that is refused writes
// none. TestCompiledColumns (validate_test.go) holds the comparison itself; this holds that every route that can set a column
// really reaches the outbox once, or not at all, in the database.

// marks runs one change and counts the endpoint_set rows it left for the tenant.
func (f *fx) marks(t *testing.T, tenant uuid.UUID, change func() error) (int, error) {
	t.Helper()
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	err := change()
	return f.outbox(t, tenant), err
}

func TestE2EveryCompiledColumnMarksOnce(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	ep := f.create(t, A, f.A.Profile, "e2")[0]
	v := &fakeVerifier{}
	a := f.auth(A, v)
	patch := func(p endpoints.Patch) func() error {
		return func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, p)
			return err
		}
	}
	yes, no := true, false
	level, soft, enabled, utc := "none", "soft_disabled", "enabled", "UTC"
	p2, other, base := f.A.Profile2, f.A.Profile2, f.A.Profile

	// A row for Require Authorized IPs to stand on. The add marks too, and is itself a compiled change (rule "authorized").
	if n, err := f.marks(t, A, func() error {
		_, err := f.env.AddAuthorized(f.ctx, f.st, A, opts, ep.ID, []string{"203.0.113.5", "198.18.0.0/16"}, netip.Addr{})
		return err
	}); err != nil || n != 1 {
		t.Fatalf("an add of authorized rows marked %d (%v)", n, err)
	}

	for _, c := range []struct {
		column string
		change func() error
	}{
		{"profile_id", patch(endpoints.Patch{ProfileID: &other})},
		{"profile2_id", patch(endpoints.Patch{Profile2ID: &p2, ProfileID: &base})},
		{"analytics_level", patch(endpoints.Patch{AnalyticsLevel: &level})},
		{"legacy_dns", patch(endpoints.Patch{LegacyDNS: &yes})},
		{"expose_ip", patch(endpoints.Patch{ExposeIP: &yes})},
		{"authorize_secure_dns", patch(endpoints.Patch{AuthorizeSecureDNS: &yes})},
		{"require_authorized_ips", patch(endpoints.Patch{RequireAuthorizedIPs: &yes})},
		{"schedule_timezone", patch(endpoints.Patch{ScheduleTimezone: &utc})},
		{"admin_state", patch(endpoints.Patch{AdminState: &soft})},
		{"admin_state back", patch(endpoints.Patch{AdminState: &enabled})},
		{"require_authorized_ips off", patch(endpoints.Patch{RequireAuthorizedIPs: &no})},
		{"rotation", func() error { _, err := f.env.Rotate(f.ctx, f.st, A, opts, a, ep.ID); return err }},
		{"a schedule", func() error {
			_, err := f.env.SetSchedule(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ScheduleIn{Timezone: "UTC",
				Windows: []endpoints.WindowIn{{Start: 60, End: 120, ProfileID: f.A.Profile2}}})
			return err
		}},
		{"a client with a profile of its own", func() error {
			_, err := f.env.CreateClient(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientCreate{Alias: "with profile", ProfileID: f.A.Profile2})
			return err
		}},
	} {
		n, err := f.marks(t, A, c.change)
		if err != nil {
			t.Errorf("%s: %v", c.column, err)
			continue
		}
		if n != 1 {
			t.Errorf("a change of %s marked %d endpoint_set rows, want 1", c.column, n)
		}
	}

	// The same values again change nothing and mark nothing: the outbox follows the value, not the request.
	for _, c := range []struct {
		column string
		change func() error
	}{
		{"legacy_dns", patch(endpoints.Patch{LegacyDNS: &yes})},
		{"analytics_level", patch(endpoints.Patch{AnalyticsLevel: &level})},
		{"schedule_timezone", patch(endpoints.Patch{ScheduleTimezone: &utc})},
	} {
		if n, err := f.marks(t, A, c.change); err != nil || n != 0 {
			t.Errorf("setting %s to the value it has marked %d (%v)", c.column, n, err)
		}
	}
}

func TestE2NoColumnOutsideTheMapMarks(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	ep := f.create(t, A, f.A.Profile, "quiet")[0]
	a := f.auth(A, &fakeVerifier{})
	var second string
	f.scan(t, `SELECT key FROM ctrlz.endpoint_types ORDER BY position OFFSET 1 LIMIT 1`, nil, &second)
	g, err := f.env.CreateGroup(f.ctx, f.st, A, opts, "quiet group", nil)
	if err != nil {
		t.Fatal(err)
	}
	yes, name, comment := true, "renamed", "a note"
	for _, c := range []struct {
		column string
		change func() error
	}{
		{"name", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{Name: &name})
			return err
		}},
		{"type", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{Type: &second})
			return err
		}},
		{"comment", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{Comment: &comment})
			return err
		}},
		{"group_id", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{GroupID: &g.ID})
			return err
		}},
		{"authorize_ddns", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{AuthorizeDDNS: &yes})
			return err
		}},
		{"prevent_deactivation", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{PreventDeactivation: &yes})
			return err
		}},
		{"a group rename", func() error { _, err := f.env.RenameGroup(f.ctx, f.st, A, opts, g.ID, "renamed group"); return err }},
		{"a group created with the Endpoint in it", func() error {
			_, err := f.env.CreateGroup(f.ctx, f.st, A, opts, "second group", []uuid.UUID{ep.ID})
			return err
		}},
		{"a DDNS host", func() error {
			_, err := f.env.CreateDDNSHost(f.ctx, f.st, A, opts, ep.ID, "home.example.org")
			return err
		}},
		{"a client with no stack of its own", func() error {
			_, err := f.env.CreateClient(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientCreate{Alias: "plain"})
			return err
		}},
		{"a batch move", func() error {
			_, err := f.env.Batch(f.ctx, f.st, A, opts, a, endpoints.BatchIn{IDs: []uuid.UUID{ep.ID}, Op: "move", ClearGroup: true})
			return err
		}},
	} {
		n, err := f.marks(t, A, c.change)
		if err != nil {
			t.Errorf("%s: %v", c.column, err)
			continue
		}
		if n != 0 {
			t.Errorf("a change of %s, which is not compiled, marked %d endpoint_set rows", c.column, n)
		}
	}
	// Deleting a group sends its Endpoints to no group, which is not a compiled change either.
	if n, err := f.marks(t, A, func() error { return f.env.DeleteGroup(f.ctx, f.st, A, opts, g.ID) }); err != nil || n != 0 {
		t.Errorf("a group delete marked %d (%v)", n, err)
	}
}

// A request that is refused marks nothing, whichever refusal it is.
func TestE2ARefusedRequestMarksNothing(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	ep := f.create(t, A, f.A.Profile, "refused")[0]
	locked := f.newProfile(t, A, "locked")
	guarded := f.create(t, A, locked, "guarded")[0]
	f.lock(t, locked)
	v := &fakeVerifier{right: "right-password"}
	a := f.auth(A, v)
	yes, soft, bad := true, "soft_disabled", "no-such-level"
	other := f.B.Profile
	for _, c := range []struct {
		what   string
		change func() error
	}{
		{"Require with no address (422)", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{RequireAuthorizedIPs: &yes})
			return err
		}},
		{"a value outside the enum (422)", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{AnalyticsLevel: &bad})
			return err
		}},
		{"another tenant's profile (404)", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, ep.ID, endpoints.Patch{ProfileID: &other})
			return err
		}},
		{"a locked profile with no password (423)", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, a, guarded.ID, endpoints.Patch{AdminState: &soft})
			return err
		}},
		{"a locked profile with a wrong password (401)", func() error {
			_, err := f.env.Patch(f.ctx, f.st, A, opts, f.auth(A, v, pw(locked, "wrong")), guarded.ID, endpoints.Patch{AdminState: &soft})
			return err
		}},
		{"a delete with no password (423)", func() error {
			return f.env.Delete(f.ctx, f.st, A, opts, a, []uuid.UUID{guarded.ID})
		}},
		{"a missing Endpoint (404)", func() error {
			_, err := f.env.Rotate(f.ctx, f.st, A, opts, a, uuid.New())
			return err
		}},
	} {
		n, err := f.marks(t, A, c.change)
		if err == nil {
			t.Errorf("%s was accepted", c.what)
		}
		if n != 0 {
			t.Errorf("%s marked %d endpoint_set rows", c.what, n)
		}
	}
}
