package catalogtest_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Tests of the smaller database corrections of the second review round. Each
// runs in a transaction that is rolled back.

// try runs one statement as role (or as the superuser when role is "") inside a
// rolled-back transaction and returns the SQLSTATE of its error, "" for none.
func (h *harness) try(role string, guc *string, sql string, args ...any) string {
	h.t.Helper()
	code := ""
	run := func(tx pgx.Tx) {
		_, err := tx.Exec(h.ctx, sql, args...)
		if pe := pgErr(err); pe != nil {
			code = pe.Code
		} else if err != nil {
			h.t.Fatalf("%s: %v", sql, err)
		}
	}
	if role == "" {
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			h.t.Fatal(err)
		}
		defer tx.Rollback(h.ctx)
		run(tx)
		return code
	}
	h.inTx(h.super, role, guc, run)
	return code
}

// TestTenantCannotChangeItsPhone: the phone is the identity (D23), and
// changing it needs a verified OTP for the old and the new number. A column
// write needs neither, so the tenant role has no UPDATE on either column. The
// phone change function arrives in P1.
func TestTenantCannotChangeItsPhone(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aStr, bStr := a.Tenant.String(), b.Tenant.String()
	for _, col := range []string{"phone_e164 = '+989120009999'", "phone_verified_at = now()", "phone_verified_at = NULL"} {
		if code := h.try("tenant", &aStr, "UPDATE ctrlz.users SET "+col+" WHERE id = $1", a.User); code != "42501" {
			t.Errorf("tenant A: SET %s gave %q, want permission denied", col, code)
		}
		// The other tenant's user is hidden by row security, but the column
		// privilege is checked first, so the answer is the same.
		if code := h.try("tenant", &bStr, "UPDATE ctrlz.users SET "+col+" WHERE id = $1", a.User); code != "42501" {
			t.Errorf("tenant B on A's user: SET %s gave %q", col, code)
		}
	}
	if code := h.try("tenant", &aStr, "UPDATE ctrlz.users SET locale = 'en' WHERE id = $1", a.User); code != "" {
		t.Errorf("an ordinary column: %q", code)
	}
	if code := h.try("tenant", &aStr, "INSERT INTO ctrlz.users (tenant_id, phone_e164, password_hash) VALUES ($1, '+989120008888', 'x')", a.Tenant); code != "42501" {
		t.Errorf("a tenant inserting a user: %q", code)
	}
}

// TestAdminHoldIsReadableButNotWritableByTheTenant (L1-F18): the tenant must be
// able to see why an Endpoint is off, so admin_hold is readable through the
// Endpoint, and only an admin writes it. The decision is recorded in the spec.
func TestAdminHoldIsReadableButNotWritableByTheTenant(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A
	aStr := a.Tenant.String()
	for _, sql := range []string{
		"UPDATE ctrlz.endpoints SET admin_hold = true WHERE id = $1",
		"UPDATE ctrlz.endpoints SET admin_hold = false WHERE id = $1",
	} {
		if code := h.try("tenant", &aStr, sql, a.Endpoint); code != "42501" {
			t.Errorf("%s as the tenant: %q, want permission denied", sql, code)
		}
	}
	if code := h.try("tenant", &aStr, "INSERT INTO ctrlz.endpoints (tenant_id, id, name, type, admin_hold) VALUES ($1, gen_random_uuid(), 'x', 'doh_client', true)", a.Tenant); code != "42501" {
		t.Errorf("an insert that sets admin_hold: %q", code)
	}
	for _, sql := range []string{
		"SELECT admin_hold FROM ctrlz.endpoints WHERE id = $1",
		"SELECT admin_hold FROM ctrlz.tenant_endpoint_status WHERE id = $1",
	} {
		if code := h.try("tenant", &aStr, sql, a.Endpoint); code != "" {
			t.Errorf("%s as the tenant: %q, want readable", sql, code)
		}
	}
	// The tenant's own hold stays hidden: that one is an enforcement action on
	// the account, not on a device.
	if code := h.try("tenant", &aStr, "SELECT admin_hold FROM ctrlz.tenants"); code != "42501" {
		t.Errorf("tenants.admin_hold as the tenant: %q, want permission denied", code)
	}
	if code := h.try("admin", &aStr, "UPDATE ctrlz.endpoints SET admin_hold = true WHERE id = $1", a.Endpoint); code != "" {
		t.Errorf("an admin setting the hold: %q", code)
	}
}

// TestSmallConstraints: the profile 2 CHECKs (L1-F20), the resolve mode
// (L1-F14) and the block page limits (L2-F19).
func TestSmallConstraints(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A
	const checkViolation = "23514"
	want := func(what, code, expect string) {
		t.Helper()
		if code != expect {
			t.Errorf("%s: SQLSTATE %q, want %q", what, code, expect)
		}
	}

	// clients: profile 2 needs profile 1, and may not equal it.
	want("clients: profile 2 without profile 1", h.try("", nil, "UPDATE ctrlz.clients SET profile_id = NULL, profile2_id = $1 WHERE tenant_id = $2", a.Profile2, a.Tenant), checkViolation)
	want("clients: profile 2 equal to profile 1", h.try("", nil, "UPDATE ctrlz.clients SET profile_id = $1, profile2_id = $1 WHERE tenant_id = $2", a.Profile, a.Tenant), checkViolation)
	want("clients: a proper stack", h.try("", nil, "UPDATE ctrlz.clients SET profile_id = $1, profile2_id = $2 WHERE tenant_id = $3", a.Profile, a.Profile2, a.Tenant), "")
	want("clients: profile 1 alone", h.try("", nil, "UPDATE ctrlz.clients SET profile_id = $1, profile2_id = NULL WHERE tenant_id = $2", a.Profile, a.Tenant), "")
	// schedule windows: profile 2 may not equal profile 1.
	want("windows: profile 2 equal to profile 1", h.try("", nil, "UPDATE ctrlz.schedule_windows SET profile2_id = profile_id WHERE tenant_id = $1", a.Tenant), checkViolation)
	want("windows: a proper stack", h.try("", nil, "UPDATE ctrlz.schedule_windows SET profile_id = $1, profile2_id = $2 WHERE tenant_id = $3", a.Profile, a.Profile2, a.Tenant), "")

	// nodes.resolve_mode says hybrid, as the contract and the proto do.
	want("nodes: mixed", h.try("", nil, "UPDATE ctrlz.nodes SET resolve_mode = 'mixed'"), checkViolation)
	want("nodes: hybrid", h.try("", nil, "UPDATE ctrlz.nodes SET resolve_mode = 'hybrid'"), "")
	for _, m := range []string{"recursive", "upstream"} {
		want("nodes: "+m, h.try("", nil, "UPDATE ctrlz.nodes SET resolve_mode = $1", m), "")
	}

	// block pages: bounded text, an https link in URL mode and nothing in the
	// others, and the table agrees with wire.ValidateBlockPage: a row it accepts
	// is a record the validator accepts, and the rows the validator refuses are
	// refused by the table.
	setBlock := func(mode string, url any) string {
		return h.try("", nil, "UPDATE ctrlz.block_pages SET unblock_mode = $1, unblock_url = $2 WHERE tenant_id = $3", mode, url, a.Tenant)
	}
	modes := map[string]policyv1.UnblockMode{"none": policyv1.UnblockMode_UNBLOCK_MODE_NONE, "default": policyv1.UnblockMode_UNBLOCK_MODE_REQUEST, "custom": policyv1.UnblockMode_UNBLOCK_MODE_URL}
	validates := func(mode, url string) bool {
		return wire.ValidateBlockPage(&policyv1.BlockPage{Title: "t", Message: "m", UnblockMode: modes[mode], UnblockUrl: url}) == nil
	}
	longURL := "https://example.com/" + strings.Repeat("a", 2040)
	for _, c := range []struct {
		what string
		mode string
		url  any
		str  string // the same url as text for the validator
		ok   bool
	}{
		{"a good link", "custom", "https://example.com/unblock?id=1", "https://example.com/unblock?id=1", true},
		{"a link with a port", "custom", "https://example.com:8443/x", "https://example.com:8443/x", true},
		{"a host only", "custom", "https://example.com", "https://example.com", true},
		{"a punycode host", "custom", "https://xn--mgbh0fb.example/x", "https://xn--mgbh0fb.example/x", true},
		{"an IPv6 host", "custom", "https://[2001:db8::1]/x", "https://[2001:db8::1]/x", true},
		{"mode none without a link", "none", nil, "", true},
		{"mode default without a link", "default", nil, "", true},
		// The rows of the finding.
		{"mode custom without a link", "custom", nil, "", false},
		{"mode none with a link", "none", "https://example.com/x", "https://example.com/x", false},
		{"mode default with a link", "default", "https://example.com/x", "https://example.com/x", false},
		{"a link with a non-ASCII host", "custom", "https://مثال.com/x", "https://مثال.com/x", false},
		{"a link with a non-ASCII path", "custom", "https://example.com/é", "https://example.com/é", false},
		// The older limits.
		{"javascript", "custom", "javascript:alert(1)", "javascript:alert(1)", false},
		{"http", "custom", "http://example.com/", "http://example.com/", false},
		{"a user part", "custom", "https://user@example.com/", "https://user@example.com/", false},
		{"no host", "custom", "https:///x", "https:///x", false},
		{"only a port", "custom", "https://:80/x", "https://:80/x", false},
		{"a space", "custom", "https://example.com/a b", "https://example.com/a b", false},
		{"a scheme-relative link", "custom", "//example.com/", "//example.com/", false},
		{"a link of 2060 bytes", "custom", longURL + strings.Repeat("a", 20), longURL + strings.Repeat("a", 20), false},
	} {
		want(c.what, setBlock(c.mode, c.url), map[bool]string{true: "", false: checkViolation}[c.ok])
		if got := validates(c.mode, c.str); got != c.ok {
			t.Errorf("%s: wire.ValidateBlockPage says %v, the table says %v; they must agree", c.what, got, c.ok)
		}
	}
	want("block page: a link of 2048 bytes", setBlock("custom", longURL[:2048]), "")
	if !validates("custom", longURL[:2048]) {
		t.Error("the validator refuses a link of 2048 bytes that the table accepts")
	}
	// The text limits alone, with the mode and link left valid.
	setBlock("none", nil)
	set := func(col, val string) string {
		return h.try("", nil, "UPDATE ctrlz.block_pages SET "+col+" = $1 WHERE tenant_id = $2", val, a.Tenant)
	}
	want("block page: title of 120 characters", set("title", strings.Repeat("س", 120)), "")
	want("block page: title of 121 characters", set("title", strings.Repeat("a", 121)), checkViolation)
	want("block page: message of 2000", set("message", strings.Repeat("a", 2000)), "")
	want("block page: message of 2001", set("message", strings.Repeat("a", 2001)), checkViolation)
}
