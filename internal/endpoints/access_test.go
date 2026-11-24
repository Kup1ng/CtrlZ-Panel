package endpoints_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The access list and the claims of an Endpoint (docs/specs/p3-endpoints.md 4, 5): the three rules of the authorized list, a
// DDNS host delete that goes through them, the cap of five hosts, and the routes' half of the claim outcomes.

func TestParseAuthorized(t *testing.T) {
	for _, c := range []struct {
		in, want, code string
	}{
		{"203.0.113.5", "203.0.113.5/32", ""},
		{" 203.0.113.0/24 ", "203.0.113.0/24", ""},
		{"198.18.0.0/16", "198.18.0.0/16", ""},
		{"198.18.0.0/15", "", endpoints.CodeOutOfRange},
		{"203.0.113.1/24", "", endpoints.CodeInvalid}, // host bits
		{"2001:db8::/32", "2001:db8::/32", ""},
		{"2001:db8::/31", "", endpoints.CodeOutOfRange},
		{"2001:db8::1", "2001:db8::1/128", ""},
		{"::ffff:203.0.113.5", "", endpoints.CodeInvalid}, // mapped
		{"203.0.113.5/33", "", endpoints.CodeInvalid},
		{"nonsense", "", endpoints.CodeInvalid},
		{"", "", endpoints.CodeInvalid},
		{"fe80::1%eth0", "", endpoints.CodeInvalid}, // zone
	} {
		p, code := endpoints.ParseAuthorized(c.in)
		if code != c.code || (code == "" && p.String() != c.want) {
			t.Errorf("%q: got %s %q, want %s %q", c.in, p, code, c.want, c.code)
		}
	}
}

func TestParseClaimPrefix(t *testing.T) {
	for _, c := range []struct {
		in, want, code string
	}{
		{"203.0.113.5", "203.0.113.5/32", ""},
		{"203.0.113.0/28", "203.0.113.0/28", ""},
		{"203.0.113.1/28", "", endpoints.CodeInvalid},
		{"2001:db8::/64", "2001:db8::/64", ""}, // the database function answers unsupported
		{"::ffff:203.0.113.5", "", endpoints.CodeInvalid},
		{"x", "", endpoints.CodeInvalid},
	} {
		p, code := endpoints.ParseClaimPrefix(c.in)
		if code != c.code || (code == "" && p.String() != c.want) {
			t.Errorf("%q: got %s %q, want %s %q", c.in, p, code, c.want, c.code)
		}
	}
	if p := endpoints.PrefixOfAddress(netip.MustParseAddr("::ffff:203.0.113.9")); p.String() != "203.0.113.9/32" {
		t.Errorf("a mapped address is the client's IPv4 form: %s", p)
	}
}

func TestCheckDDNSHostname(t *testing.T) {
	for _, c := range []struct {
		in, zone, want, code string
	}{
		{"Home.Example.org", "dns.ctrlz.test", "home.example.org", ""},
		{"home.example.org.", "", "home.example.org", ""},
		{"dns.ctrlz.test", "dns.ctrlz.test", "", endpoints.CodeInvalid},
		{"abc.dns.ctrlz.test", "dns.ctrlz.test", "", endpoints.CodeInvalid},
		{"localhost", "", "", endpoints.CodeInvalid},
		{"203.0.113.5", "", "", endpoints.CodeInvalid},
		{"", "", "", endpoints.CodeInvalid},
		{strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + "." + strings.Repeat("e", 60) + ".org", "", "", ""},
	} {
		got, code := endpoints.CheckDDNSHostname(c.in, c.zone)
		if c.want == "" && c.code == "" {
			// Too long for DNS: whichever refusal the parser or the bound gives, it is a refusal.
			if code == "" {
				t.Errorf("%.20q… accepted", c.in)
			}
			continue
		}
		if got != c.want || code != c.code {
			t.Errorf("%q: got %q %q, want %q %q", c.in, got, code, c.want, c.code)
		}
	}
}

func (f *fx) addAuthorized(t *testing.T, tenant, ep uuid.UUID, cidrs ...string) []store.AuthorizedRow {
	t.Helper()
	rows, err := f.env.AddAuthorized(f.ctx, f.st, tenant, opts, ep, cidrs, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func (f *fx) require(t *testing.T, tenant, ep uuid.UUID, v *fakeVerifier, on bool, pws ...endpoints.Password) error {
	t.Helper()
	_, err := f.env.Patch(f.ctx, f.st, tenant, opts, f.auth(tenant, v, pws...), ep, endpoints.Patch{RequireAuthorizedIPs: &on})
	return err
}

func ids(rows ...store.AuthorizedRow) []uuid.UUID {
	out := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out
}

// Spec 5: the three rules, each decided under the Endpoint's row.
func TestAuthorizedRules(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	v := &fakeVerifier{}
	a := f.auth(f.A.Tenant, v)
	me := netip.MustParseAddr("203.0.113.5")

	// Rule 3: Require cannot be turned on for an Endpoint with no row.
	err := f.require(t, f.A.Tenant, ep.ID, v, true)
	if e := refusal(t, err); !hasField(e, "/require_authorized_ips", endpoints.CodeNeedsAuthorizedIP) {
		t.Errorf("require with no row: %v", e)
	}

	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	rows := f.addAuthorized(t, f.A.Tenant, ep.ID, "203.0.113.5", "198.18.0.0/16")
	if len(rows) != 2 {
		t.Fatalf("%d rows added", len(rows))
	}
	// The rows come back in id order, which is the order the statement inserted them in (by prefix), so they are found by prefix.
	var cur, wide store.AuthorizedRow
	for _, r := range rows {
		if r.CIDR.String() == "203.0.113.5/32" {
			cur = r
		} else {
			wide = r
		}
	}
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("an add of two rows marked %d times", n)
	}
	// The request is judged whole, each refusal at its index.
	_, err = f.env.AddAuthorized(f.ctx, f.st, f.A.Tenant, opts, ep.ID, []string{"198.19.0.0/16", "203.0.113.5", "198.18.0.0/15", "bad", "198.19.0.0/16"}, netip.Addr{})
	e := refusal(t, err)
	for name, code := range map[string]string{"/cidrs/2": endpoints.CodeOutOfRange, "/cidrs/3": endpoints.CodeInvalid, "/cidrs/4": endpoints.CodeDuplicate} {
		if !hasField(e, name, code) {
			t.Errorf("%s %s missing from %v", name, code, e)
		}
	}
	_, err = f.env.AddAuthorized(f.ctx, f.st, f.A.Tenant, opts, ep.ID, []string{"198.19.0.0/16", "203.0.113.5"}, netip.Addr{})
	if e := refusal(t, err); !hasField(e, "/cidrs/1", endpoints.CodeExists) {
		t.Errorf("a prefix the Endpoint has: %v", e)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1`, ep.ID); n != 2 {
		t.Errorf("a refused add left %d rows", n)
	}
	if _, err := f.env.AddAuthorized(f.ctx, f.st, f.A.Tenant, opts, ep.ID, make([]string, 101), netip.Addr{}); refusal(t, err).Kind != endpoints.KindValidation {
		t.Error("101 prefixes")
	}

	// Rule 1: the row that holds the caller's address stays.
	err = f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, ids(cur), me)
	if e := refusal(t, err); !hasField(e, "/ids/0", endpoints.CodeCurrentAddress) {
		t.Errorf("the current address: %v", e)
	}
	// The list marks that row.
	var current int
	err = f.st.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		list, err := tx.AuthorizedList(store.AuthorizedFilter{Endpoint: ep.ID, Current: me, Limit: 10})
		for _, r := range list {
			if r.IsCurrent {
				current++
			}
		}
		return err
	})
	if err != nil || current != 1 {
		t.Errorf("%d rows marked current (%v)", current, err)
	}

	// Rule 2: the last row of an Endpoint that requires authorized IPs stays, and one that is not last goes.
	if err := f.require(t, f.A.Tenant, ep.ID, v, true); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	err = f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, ids(cur, wide), netip.Addr{})
	e = refusal(t, err)
	if !hasField(e, "/ids/0", endpoints.CodeLastAuthorized) || !hasField(e, "/ids/1", endpoints.CodeLastAuthorized) {
		t.Errorf("both rows of an Endpoint that requires them: %v", e)
	}
	if n := f.outbox(t, f.A.Tenant); n != 0 {
		t.Errorf("a refused delete marked %d times", n)
	}
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, ids(wide), me); err != nil {
		t.Fatalf("one of two rows: %v", err)
	}
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("a delete marked %d times", n)
	}
	err = f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, ids(cur), netip.Addr{})
	if e := refusal(t, err); !hasField(e, "/ids/0", endpoints.CodeLastAuthorized) {
		t.Errorf("the last row: %v", e)
	}
	// With Require off the last row goes.
	if err := f.require(t, f.A.Tenant, ep.ID, v, false); err != nil {
		t.Fatal(err)
	}
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, ids(cur), netip.Addr{}); err != nil {
		t.Fatalf("the last row with Require off: %v", err)
	}
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, ids(cur), netip.Addr{}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a row that is gone")
	}
}

// Two tenants: B's Endpoint and B's rows are 404 for A, and an add on A's Endpoint changes nothing of B's.
func TestAuthorizedAnotherTenantsRows(t *testing.T) {
	f := newFx(t)
	own := f.create(t, f.A.Tenant, f.A.Profile, "own")[0]
	theirs := f.create(t, f.B.Tenant, f.B.Profile, "theirs")[0]
	bRows := f.addAuthorized(t, f.B.Tenant, theirs.ID, "203.0.113.9")
	v := &fakeVerifier{}
	a := f.auth(f.A.Tenant, v)
	bBefore := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1`, f.B.Tenant)

	if _, err := f.env.AddAuthorized(f.ctx, f.st, f.A.Tenant, opts, theirs.ID, []string{"203.0.113.10"}, netip.Addr{}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("add on another tenant's Endpoint")
	}
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, theirs.ID, ids(bRows[0]), netip.Addr{}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("delete on another tenant's Endpoint")
	}
	// B's row under A's own Endpoint is not found either.
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, own.ID, ids(bRows[0]), netip.Addr{}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("another tenant's row under one's own Endpoint")
	}
	if _, err := f.env.SetCleanupOptIn(f.ctx, f.st, f.A.Tenant, opts, a, own.ID, bRows[0].ID, true, netip.Addr{}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("opt-in of another tenant's row")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1`, f.B.Tenant); n != bBefore {
		t.Errorf("B holds %d rows, had %d", n, bBefore)
	}
}

// The tenant-wide cap of manual rows is the plan's, the override beats it, and learned rows are not counted (spec 3.5).
func TestAuthorizedCap(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	have := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'manual'`, f.A.Tenant)
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_authorized_ips = $2 WHERE tenant_id = $1`, f.A.Tenant, have+2)
	f.exec(t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source) VALUES ($1, $2, '203.0.113.200/32', 'secure_dns')`, f.A.Tenant, ep.ID)
	_, err := f.env.AddAuthorized(f.ctx, f.st, f.A.Tenant, opts, ep.ID, []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, netip.Addr{})
	if e := refusal(t, err); !hasField(e, "max_authorized_ips", endpoints.CodeExceeded) {
		t.Errorf("three into two free slots: %v", e)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'manual'`, f.A.Tenant); n != have {
		t.Errorf("a refused add wrote %d rows", n-have)
	}
	f.addAuthorized(t, f.A.Tenant, ep.ID, "203.0.113.1", "203.0.113.2")
	// B's room is its own.
	bEp := f.create(t, f.B.Tenant, f.B.Profile, "b")[0]
	f.addAuthorized(t, f.B.Tenant, bEp.ID, "203.0.113.1")
}

// Lock passwords (spec 3.3): with Require on, deleting a row turns every identity away, so it needs the password of a locked
// profile in their stacks; with Require off it needs nothing; opting a row into the cleanup is the same.
func TestAuthorizedDeleteNeedsLockPasswords(t *testing.T) {
	f := newFx(t)
	locked := f.newProfile(t, f.A.Tenant, "locked")
	f.lock(t, locked)
	ep := f.create(t, f.A.Tenant, locked, "e")[0]
	rows := f.addAuthorized(t, f.A.Tenant, ep.ID, "203.0.113.1", "203.0.113.2", "203.0.113.3")
	v := &fakeVerifier{right: "pw"}
	// Turning Require on turns everybody away: it needs the password too.
	if err := f.require(t, f.A.Tenant, ep.ID, v, true); refusal(t, err).Kind != endpoints.KindLocked {
		t.Error("require on without the password")
	}
	if err := f.require(t, f.A.Tenant, ep.ID, v, true, pw(locked, "pw")); err != nil {
		t.Fatal(err)
	}
	a := f.auth(f.A.Tenant, v)
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, ids(rows[0]), netip.Addr{}); refusal(t, err).Kind != endpoints.KindLocked {
		t.Error("a delete under Require without the password")
	}
	if _, err := f.env.SetCleanupOptIn(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, rows[1].ID, true, netip.Addr{}); refusal(t, err).Kind != endpoints.KindLocked {
		t.Error("opt-in under Require without the password")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1 AND cleanup_opt_in`, ep.ID); n != 0 {
		t.Error("a refused opt-in was written")
	}
	wrong := f.auth(f.A.Tenant, v, pw(locked, "nope"))
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, wrong, ep.ID, ids(rows[0]), netip.Addr{}); refusal(t, err).Kind != endpoints.KindInvalidCredentials {
		t.Error("a wrong password")
	}
	right := f.auth(f.A.Tenant, v, pw(locked, "pw"))
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, right, ep.ID, ids(rows[0]), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.SetCleanupOptIn(f.ctx, f.st, f.A.Tenant, opts, right, ep.ID, rows[1].ID, true, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	// Turning it off, and every change with Require off, needs nothing.
	if _, err := f.env.SetCleanupOptIn(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, rows[1].ID, false, netip.Addr{}); err != nil {
		t.Errorf("opt-in off: %v", err)
	}
	if err := f.require(t, f.A.Tenant, ep.ID, v, false); err != nil {
		t.Fatal(err)
	}
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, ids(rows[1]), netip.Addr{}); err != nil {
		t.Errorf("a delete with Require off: %v", err)
	}
}

// DDNS hosts (spec 4.5, 5): five at most, a name of ours is refused, and a delete goes through the rules of the rows it learned.
func TestDDNSHosts(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	var hosts []store.DDNSHostRow
	make1 := func(n string) {
		t.Helper()
		h, err := f.env.CreateDDNSHost(f.ctx, f.st, f.A.Tenant, opts, ep.ID, n+".example.org")
		if err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h)
	}
	for _, n := range []string{"a", "b", "c", "d"} {
		make1(n)
	}
	// The name is folded, so a spelling of a host the Endpoint has is that host.
	if _, err := f.env.CreateDDNSHost(f.ctx, f.st, f.A.Tenant, opts, ep.ID, "A.example.org"); !hasField(refusal(t, err), "/hostname", endpoints.CodeExists) {
		t.Error("a repeated host")
	}
	make1("e")
	if _, err := f.env.CreateDDNSHost(f.ctx, f.st, f.A.Tenant, opts, ep.ID, "f.example.org"); !hasField(refusal(t, err), "max_ddns_hosts", endpoints.CodeExceeded) {
		t.Error("a sixth host")
	}
	if _, err := f.env.CreateDDNSHost(f.ctx, f.st, f.A.Tenant, opts, f.B.Endpoint, "x.example.org"); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a host on another tenant's Endpoint")
	}

	// A host with learned rows: its delete goes through rule 1 and rule 2, and then the host goes with them.
	v := &fakeVerifier{}
	a := f.auth(f.A.Tenant, v)
	learn := func(host uuid.UUID, cidr string) {
		f.exec(t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, ddns_host_id) VALUES ($1, $2, $3::cidr, 'ddns', $4)`, f.A.Tenant, ep.ID, cidr, host)
	}
	learn(hosts[0].ID, "203.0.113.50/32")
	learn(hosts[0].ID, "203.0.113.51/32")
	err := f.env.DeleteDDNSHost(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, hosts[0].ID, netip.MustParseAddr("203.0.113.51"))
	if e := refusal(t, err); !hasField(e, "/id", endpoints.CodeCurrentAddress) {
		t.Errorf("a host that learned the caller's address: %v", e)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoint_ddns_hosts WHERE id = $1`, hosts[0].ID); n != 1 {
		t.Error("a refused host delete deleted the host")
	}
	// Require on, and the host's rows are all the Endpoint has.
	if err := f.require(t, f.A.Tenant, ep.ID, v, true); err != nil {
		t.Fatal(err)
	}
	err = f.env.DeleteDDNSHost(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, hosts[0].ID, netip.Addr{})
	if e := refusal(t, err); !hasField(e, "/id", endpoints.CodeLastAuthorized) {
		t.Errorf("the last rows of an Endpoint that requires them: %v", e)
	}
	f.addAuthorized(t, f.A.Tenant, ep.ID, "203.0.113.99")
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	if err := f.env.DeleteDDNSHost(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, hosts[0].ID, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE ddns_host_id = $1`, hosts[0].ID); n != 0 {
		t.Error("the host's rows stayed")
	}
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("a host delete that removed rows marked %d times", n)
	}
	// A host with no rows goes without a mark.
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	if err := f.env.DeleteDDNSHost(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, hosts[1].ID, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if n := f.outbox(t, f.A.Tenant); n != 0 {
		t.Errorf("a host with no rows marked %d times", n)
	}
	// The Endpoint's delete and the tenant's cascades must pass the deferred key with learned rows in place.
	learn(hosts[2].ID, "203.0.113.60/32")
	if err := f.env.DeleteAuthorized(f.ctx, f.st, f.A.Tenant, opts, a, f.A.Endpoint, nil, netip.Addr{}); refusal(t, err).Kind != endpoints.KindValidation {
		t.Error("an empty delete")
	}
	if err := f.require(t, f.A.Tenant, ep.ID, v, false); err != nil {
		t.Fatal(err)
	}
	if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, a, []uuid.UUID{ep.ID}); err != nil {
		t.Fatalf("an Endpoint with a host that learned rows: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1`, ep.ID); n != 0 {
		t.Error("the Endpoint's rows stayed")
	}
}

// Claims (spec 4.3): each outcome of the functions as the route's refusal, the marks, and the two tenants.
func TestClaimOutcomes(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	bEp := f.create(t, f.B.Tenant, f.B.Profile, "b")[0]
	request := func(tenant, endpoint uuid.UUID, cidr string) (endpoints.ClaimResult, error) {
		return f.env.RequestClaim(f.ctx, f.st, tenant, opts, endpoint, endpoints.ClaimAsk{Cidr: &cidr})
	}
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	r, err := request(f.A.Tenant, ep.ID, "203.0.113.7/32")
	if err != nil || r.Outcome != "active" || r.Claim.State != "active" || r.Claim.NeedsAdmin {
		t.Fatalf("a request in closed mode: %v %+v", err, r)
	}
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("an active claim marked %d times", n)
	}
	cases := []struct {
		cidr, field, code string
	}{
		{"203.0.113.7/32", "/cidr", endpoints.CodeExists},
		{"203.0.113.0/24", "/cidr", endpoints.CodeExists}, // a wider prefix over one's own claim is the same
		{"10.0.0.1/32", "/cidr", endpoints.CodeReservedRange},
		{"2001:db8::/64", "/cidr", endpoints.CodeUnsupportedFamily},
	}
	for _, c := range cases {
		_, err := request(f.A.Tenant, ep.ID, c.cidr)
		if e := refusal(t, err); !hasField(e, c.field, c.code) {
			t.Errorf("%s: %v", c.cidr, e)
		}
	}
	// A /28 is allowed in closed mode and needs an admin to be proven.
	w, err := request(f.A.Tenant, ep.ID, "203.0.114.0/28")
	if err != nil || w.Outcome != "active" {
		t.Fatalf("a /28 in closed mode: %v %+v", err, w)
	}
	// Over the cap.
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 1 WHERE tenant_id = $1`, f.A.Tenant)
	if _, err := request(f.A.Tenant, ep.ID, "203.0.115.1/32"); !hasField(refusal(t, err), "max_ip_claims", endpoints.CodeExceeded) {
		t.Error("over max_ip_claims")
	}
	// Another tenant's claim and Endpoint are 404 for A.
	if _, err := request(f.A.Tenant, bEp.ID, "203.0.116.1/32"); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a claim on another tenant's Endpoint")
	}
	if _, err := f.env.OpenChallenge(f.ctx, f.st, f.B.Tenant, opts, bEp.ID, r.Claim.ID); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a challenge on another tenant's claim")
	}
	if _, err := f.env.TakeClaim(f.ctx, f.st, f.A.Tenant, opts, bEp.ID, r.Claim.ID, ""); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a take under another tenant's Endpoint")
	}
	if _, err := f.env.TakeClaim(f.ctx, f.st, f.A.Tenant, opts, f.A.Endpoint, r.Claim.ID, ""); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a take under another Endpoint of the same tenant")
	}

	// B asks for an address A holds, unproven: B waits for proof (D35). With no evidence the take is no_proof, and the code
	// count stays; with evidence from inside the address it displaces A's unproven claim.
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 10 WHERE tenant_id = $1`, f.B.Tenant)
	br, err := request(f.B.Tenant, bEp.ID, "203.0.113.7/32")
	if err != nil || br.Outcome != "pending_proof" || br.Claim.State != "pending_proof" {
		t.Fatalf("B over A's claim: %v %+v", err, br)
	}
	ch, err := f.env.OpenChallenge(f.ctx, f.st, f.B.Tenant, opts, bEp.ID, br.Claim.ID)
	if err != nil || ch.Challenge.Label == "" {
		t.Fatalf("open challenge: %v", err)
	}
	if tk, err := f.env.TakeClaim(f.ctx, f.st, f.B.Tenant, opts, bEp.ID, br.Claim.ID, ""); err != nil || tk.Outcome != "no_proof" {
		t.Fatalf("no evidence: %v %+v", err, tk)
	}
	f.exec(t, `UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = '203.0.113.7', observed_protocol = 'tcp' WHERE claim_id = $1`, br.Claim.ID)
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	tk, err := f.env.TakeClaim(f.ctx, f.st, f.B.Tenant, opts, bEp.ID, br.Claim.ID, "")
	if err != nil || tk.Outcome != "active" || tk.Claim.ProvenAt == nil {
		t.Fatalf("with evidence: %v %+v", err, tk)
	}
	if f.outbox(t, f.B.Tenant) == 0 || f.outbox(t, f.A.Tenant) == 0 {
		t.Error("a takeover wrote no endpoint_set row for the taker or the displaced tenant")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE id = $1 AND state = 'released'`, r.Claim.ID); n != 1 {
		t.Error("A's unproven claim was not displaced")
	}
	// A proven claim is not displaced by a third request's proof.
	if _, err := f.env.TakeClaim(f.ctx, f.st, f.B.Tenant, opts, bEp.ID, br.Claim.ID, ""); err != nil {
		t.Errorf("a second take of an active claim: %v", err)
	}
}

// Release (spec 4.3): a mark for every release, and the lock passwords when the claim was a Plain DNS identity.
func TestClaimRelease(t *testing.T) {
	f := newFx(t)
	locked := f.newProfile(t, f.A.Tenant, "locked")
	f.lock(t, locked)
	rows, err := f.env.Create(f.ctx, f.st, f.A.Tenant, opts, endpoints.CreateIn{Type: f.typ, Names: []string{"plain"}, ProfileID: locked, LegacyDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	ep := rows[0]
	c1 := "203.0.113.30/32"
	r, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, endpoints.ClaimAsk{Cidr: &c1})
	if err != nil {
		t.Fatal(err)
	}
	v := &fakeVerifier{right: "pw"}
	if err := f.env.ReleaseClaim(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v), ep.ID, r.Claim.ID); refusal(t, err).Kind != endpoints.KindLocked {
		t.Error("the last Plain DNS identity of a locked profile goes without its password")
	}
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	if err := f.env.ReleaseClaim(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(locked, "pw")), ep.ID, r.Claim.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("a release marked %d times", n)
	}
	if err := f.env.ReleaseClaim(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v), ep.ID, r.Claim.ID); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a claim that is released")
	}
	// A suspended claim is not released by its tenant.
	c2 := "203.0.113.31/32"
	r2, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, endpoints.ClaimAsk{Cidr: &c2})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1`, r2.Claim.ID)
	if err := f.env.ReleaseClaim(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(locked, "pw")), ep.ID, r2.Claim.ID); refusal(t, err).Kind != endpoints.KindIPSuspended {
		t.Error("a suspended claim")
	}
	if _, err := f.env.OpenChallenge(f.ctx, f.st, f.A.Tenant, opts, ep.ID, r2.Claim.ID); refusal(t, err).Kind != endpoints.KindIPSuspended {
		t.Error("a challenge for a suspended claim")
	}
}

// Challenges are capped by the database (ten live per claim), and the refusal says when one ends.
func TestChallengeCapSaysWhenToRetry(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	c1 := "203.0.113.40/32"
	r, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, endpoints.ClaimAsk{Cidr: &c1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := f.env.OpenChallenge(f.ctx, f.st, f.A.Tenant, opts, ep.ID, r.Claim.ID); err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
	}
	_, err = f.env.OpenChallenge(f.ctx, f.st, f.A.Tenant, opts, ep.ID, r.Claim.ID)
	if e := refusal(t, err); e.Kind != endpoints.KindTooManyChallenges || e.RetryAfter < 1 || e.RetryAfter > 600 {
		t.Errorf("the eleventh challenge: %v retry %d", e, e.RetryAfter)
	}
}

// Open registration (spec 4.1, T-268): a request starts pending_proof and marks nothing; proof from inside the address makes it
// active and marks; a prefix wider than /32 waits for an admin whatever the evidence.
func TestClaimsInOpenMode(t *testing.T) {
	f := newFx(t)
	f.exec(t, `UPDATE ctrlz.system_settings SET registration_mode = 'open'`)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	ask := func(cidr string) endpoints.ClaimAsk { return endpoints.ClaimAsk{Cidr: &cidr} }
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	r, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, ask("203.0.113.80"))
	if err != nil || r.Outcome != "pending_proof" || r.Claim.State != "pending_proof" || r.Claim.NeedsAdmin {
		t.Fatalf("a request in open mode: %v %+v", err, r)
	}
	if n := f.outbox(t, f.A.Tenant); n != 0 {
		t.Errorf("a pending claim marked %d times", n)
	}
	if _, err := f.env.OpenChallenge(f.ctx, f.st, f.A.Tenant, opts, ep.ID, r.Claim.ID); err != nil {
		t.Fatal(err)
	}
	// An address outside the claim proves nothing.
	f.exec(t, `UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = '203.0.113.81', observed_protocol = 'tcp' WHERE claim_id = $1`, r.Claim.ID)
	if tk, err := f.env.TakeClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, r.Claim.ID, ""); err != nil || tk.Outcome != "no_proof" {
		t.Fatalf("evidence from another address: %v %+v", err, tk)
	}
	f.exec(t, `UPDATE ctrlz.ip_proof_challenges SET observed_ip = '203.0.113.80' WHERE claim_id = $1`, r.Claim.ID)
	tk, err := f.env.TakeClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, r.Claim.ID, "")
	if err != nil || tk.Outcome != "active" || tk.Claim.State != "active" || tk.Claim.ProvenAt == nil {
		t.Fatalf("evidence from inside: %v %+v", err, tk)
	}
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("a proven claim marked %d times", n)
	}
	// A /29 is wider than the mode allows: a pending row that needs an admin, and the proof is refused until one approves it.
	w, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, ask("203.0.113.88/29"))
	if err != nil || w.Outcome != "wide_requires_approval" || !w.Claim.NeedsAdmin {
		t.Fatalf("a /29: %v %+v", err, w)
	}
	if _, err := f.env.OpenChallenge(f.ctx, f.st, f.A.Tenant, opts, ep.ID, w.Claim.ID); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = '203.0.113.88', observed_protocol = 'tcp' WHERE claim_id = $1`, w.Claim.ID)
	if _, err := f.env.TakeClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, w.Claim.ID, ""); refusal(t, err).Kind != endpoints.KindNeedsAdmin {
		t.Error("a take of a wide claim with no approval")
	}
	f.exec(t, `UPDATE ctrlz.ip_claims SET approved_by_admin = true WHERE id = $1`, w.Claim.ID)
	if tk, err := f.env.TakeClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, w.Claim.ID, ""); err != nil || tk.Outcome != "active" {
		t.Errorf("an approved wide claim: %v %+v", err, tk)
	}
}

// The answer of an add marks the row that holds the caller's address, as the list does (p3-D3-r1-7): a client that sees
// is_current false would offer to delete the row it is on.
func TestAddAuthorizedMarksTheCurrentRow(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	me := netip.MustParseAddr("203.0.113.5")
	rows, err := f.env.AddAuthorized(f.ctx, f.st, f.A.Tenant, opts, ep.ID, []string{"203.0.113.5", "198.18.0.0/16"}, me)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows added", len(rows))
	}
	for _, r := range rows {
		if want := r.CIDR.String() == "203.0.113.5/32"; r.IsCurrent != want {
			t.Errorf("%s: is_current %v, want %v", r.CIDR, r.IsCurrent, want)
		}
	}
}

// A challenge refused because another suspended claim of the tenant overlaps the claim is 409 ip_suspended, not a wait that never
// ends (p3-D3-r1-2, p3-D3-r1-6). The state is made by hand: the request function refuses to make it.
func TestChallengeForClaimOverlappingASuspendedOne(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	wide, narrow := "203.0.113.64/28", "203.0.113.200/32"
	x, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, endpoints.ClaimAsk{Cidr: &wide})
	if err != nil {
		t.Fatal(err)
	}
	y, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, ep.ID, endpoints.ClaimAsk{Cidr: &narrow})
	if err != nil {
		t.Fatal(err)
	}
	// The wide claim leaves the exclusion of active claims first, then the narrow one moves into it as pending.
	f.exec(t, `UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1`, x.Claim.ID)
	f.exec(t, `UPDATE ctrlz.ip_claims SET cidr = '203.0.113.70/32', state = 'pending_proof' WHERE id = $1`, y.Claim.ID)
	_, err = f.env.OpenChallenge(f.ctx, f.st, f.A.Tenant, opts, ep.ID, y.Claim.ID)
	if e := refusal(t, err); e.Kind != endpoints.KindIPSuspended {
		t.Errorf("a challenge over a suspended claim: %v", e)
	}
}
