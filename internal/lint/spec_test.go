package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

// Rule spec-fact-drift (P1 auth review, round 5; docs/reviews/p1-auth/rules.md topic 18).
//
// The spec's fact tables are copies of facts that live in code: grants, audit events,
// route fields, keyring labels and their lifetimes, the admin-fresh set, the coverage
// map. Each fix of a round changed the code and left one copy stale, in every round, so
// a copy is no longer allowed to be unchecked. The tables below carry a marker line
// (<!-- spec-fact: NAME -->) and this test compares each with the registry it copies,
// in both directions, naming the row of the spec that differs:
//
//	audit-tenant, audit-admin   internal/auth/audit registry (TenantEvents, AdminEvents)
//	keyring-domains, keyring-uses   keyring.Domains, keyring.Uses (the lifetimes also
//	                            feed the cookies, sessions, OTP and tickets, and the
//	                            text of `ctrlz-admin keys status` and `rekey`)
//	grants                      migrations/catalog/grants.yaml
//	routes-tenant, routes-admin   api/openapi.yaml, api/admin-openapi.yaml
//	admin-fresh                 the admin-fresh operations of api/admin-openapi.yaml
//	coverage                    the Test functions of the repository
//	functions                   the security_definer list of migrations/catalog/functions.yaml
//
// A marker that goes missing fails (the list below), so the rule cannot be switched off
// by deleting a line of the spec. TestSpecFactsCanFail changes each side in turn and
// requires the comparison to notice.

// factTables names every table the spec must mark.
var factTables = []string{
	"audit-tenant", "audit-admin", "keyring-domains", "keyring-uses", "grants",
	"routes-tenant", "routes-admin", "admin-fresh", "coverage", "functions",
}

// proseSections are the sections whose prose may not repeat a life of keyring.Uses.
var proseSections = []string{"8.1", "8.2", "8.3", "8.4", "8.5"}

func TestSpecFactTables(t *testing.T) {
	lines := readSpec(t)
	tables, problems := markedTables(lines)
	for _, n := range factTables {
		if _, ok := tables[n]; !ok {
			problems = append(problems, "the spec has no table marked <!-- spec-fact: "+n+" -->")
		}
	}
	if len(tables) != len(factTables) {
		for n := range tables {
			if !slices.Contains(factTables, n) {
				problems = append(problems, "the spec marks a table "+n+" that this test does not know")
			}
		}
	}
	if len(problems) > 0 {
		t.Fatal("\n" + strings.Join(problems, "\n"))
	}

	tenantAudit, adminAudit := auditFacts()
	grants := grantFacts(t)
	sections := map[string]string{}
	for _, s := range proseSections {
		text, ok := section(lines, s)
		if !ok {
			t.Fatalf("spec section %s not found", s)
		}
		sections[s] = text
	}
	run := func(name string, got []string) {
		t.Run(name, func(t *testing.T) {
			if len(got) > 0 {
				t.Errorf("%d differences between the spec and the code:\n%s", len(got), strings.Join(got, "\n"))
			}
		})
	}
	run("audit-tenant", compareAudit(tables["audit-tenant"], tenantAudit, false))
	run("audit-admin", compareAudit(tables["audit-admin"], adminAudit, true))
	run("keyring-domains", compareDomains(tables["keyring-domains"], keyring.Domains()))
	run("keyring-uses", compareUses(tables["keyring-uses"], keyring.Uses()))
	run("keyring-prose", compareLifetimeProse(sections, keyring.Uses()))
	run("grants", compareGrants(tables["grants"], grants, grantTables(lines, grants)))
	run("routes-tenant", compareRoutes(tables["routes-tenant"], tenantRoutes(t)))
	run("routes-admin", compareRoutes(tables["routes-admin"], adminRoutes(t)))
	run("admin-fresh", compareFresh(tables["admin-fresh"], adminRoutes(t)))
	ix := buildTestIndex(t)
	run("coverage", compareCoverage(tables["coverage"], ix))
	run("test-names", compareTestNames(lines, ix))
	run("functions", compareFunctions(tables["functions"], functionFacts(t)))
}

// TestSpecFactsCanFail proves each comparison fails when either side drifts, by changing
// the real table or the real registry and requiring a difference. A comparison that
// passes everything would leave the rule dead; this is the mutant the rule names (add a
// field to an audit event without changing 13.2) and its siblings for every family.
func TestSpecFactsCanFail(t *testing.T) {
	lines := readSpec(t)
	tables, problems := markedTables(lines)
	if len(problems) > 0 {
		t.Fatal(strings.Join(problems, "\n"))
	}
	tenantAudit, adminAudit := auditFacts()
	grants := grantFacts(t)
	gtables := grantTables(lines, grants)
	tenantRoutesNow, adminRoutesNow := tenantRoutes(t), adminRoutes(t)
	ix := buildTestIndex(t)

	// edit returns a copy of the table with one cell replaced.
	edit := func(tb specTable, row, col int, cell string) specTable {
		c := tb
		c.rows = append([][]string(nil), tb.rows...)
		c.rows[row] = append([]string(nil), tb.rows[row]...)
		c.rows[row][col] = cell
		return c
	}
	// drop returns a copy without one row.
	drop := func(tb specTable, row int) specTable {
		c := tb
		c.rows = append(append([][]string(nil), tb.rows[:row]...), tb.rows[row+1:]...)
		c.lines = append(append([]int(nil), tb.lines[:row]...), tb.lines[row+1:]...)
		return c
	}
	// rowOf finds the first row whose cell col contains s.
	rowOf := func(tb specTable, col int, s string) int {
		for i, r := range tb.rows {
			if strings.Contains(r[col], s) {
				return i
			}
		}
		t.Fatalf("table %s has no row with %q in column %d", tb.name, s, col)
		return -1
	}
	expectFail := func(name string, got []string) {
		t.Helper()
		if len(got) == 0 {
			t.Errorf("mutant %q was not noticed", name)
		}
	}

	// Audit. The rule's mutant: a field added to an event, the spec unchanged.
	at := tables["audit-tenant"]
	withExtra := append([]auditFact(nil), tenantAudit...)
	for i := range withExtra {
		if withExtra[i].Action == "login.ok" {
			withExtra[i].Params = append(append([]string(nil), withExtra[i].Params...), "added_field")
		}
	}
	expectFail("a field added to login.ok in code", compareAudit(at, withExtra, false))
	expectFail("an event added in code", compareAudit(at, append(append([]auditFact(nil), tenantAudit...), auditFact{Action: "x.new"}), false))
	expectFail("a params cell emptied", compareAudit(edit(at, rowOf(at, 0, "`login.ok`"), 1, ""), tenantAudit, false))
	expectFail("an event row dropped", compareAudit(drop(at, rowOf(at, 0, "`register`")), tenantAudit, false))
	expectFail("an event the code lacks", compareAudit(edit(at, rowOf(at, 0, "`register`"), 0, "`registerr`"), tenantAudit, false))
	aa := tables["audit-admin"]
	expectFail("a target changed", compareAudit(edit(aa, rowOf(aa, 0, "`invite.revoke`"), aa.column("Target"), "`tenant:<id>`"), adminAudit, true))
	expectFail("invite.revoke params no longer none", compareAudit(edit(aa, rowOf(aa, 0, "`invite.revoke`"), aa.column("Params"), "`send_sms`"), adminAudit, true))

	// Keyring.
	kd := tables["keyring-domains"]
	expectFail("a domain dropped from the table", compareDomains(drop(kd, 0), keyring.Domains()))
	expectFail("a domain added in code", compareDomains(kd, append(keyring.Domains(), "new_domain")))
	ku := tables["keyring-uses"]
	expectFail("a lifetime changed in the table", compareUses(edit(ku, rowOf(ku, 1, "`device`"), 3, "30 days"), keyring.Uses()))
	expectFail("a use dropped from the table", compareUses(drop(ku, rowOf(ku, 1, "`passkey_ceremony`")), keyring.Uses()))
	changed := keyring.Uses()
	changed[1].Life /= 2
	expectFail("a lifetime changed in the registry", compareUses(ku, changed))
	expectFail("a label added to the registry", compareUses(ku, append(keyring.Uses(), keyring.Use{Domain: "auth_mac", Label: "new", What: "x", Life: 1, IfRemoved: "y"})))
	expectFail("a life spelled in prose", compareLifetimeProse(map[string]string{"8.4": "the marker lasts 365 days"}, keyring.Uses()))

	// Grants.
	gt := tables["grants"]
	expectFail("a privilege changed in the table", compareGrants(edit(gt, 0, 2, "`S I U D`"), grants, gtables))
	expectFail("a grant row dropped", compareGrants(drop(gt, 0), grants, gtables))
	grown := map[string]map[string]string{}
	for tbl, roles := range grants {
		grown[tbl] = map[string]string{}
		for r, p := range roles {
			grown[tbl][r] = p
		}
	}
	grown[gtables[0]]["worker"] = "S D"
	expectFail("a role granted in grants.yaml only", compareGrants(gt, grown, gtables))
	expectFail("a table the spec never copied", compareGrants(drop(gt, rowOf(gt, 0, "`auth_tickets`")), grants, gtables))

	// Routes.
	rt := tables["routes-tenant"]
	login := rowOf(rt, 0, "`/auth/login/password`")
	expectFail("an auth class changed", compareRoutes(edit(rt, login, rt.column("Auth"), "`session`"), tenantRoutesNow))
	expectFail("a rate class changed", compareRoutes(edit(rt, login, rt.column("Rate"), "`public-read`"), tenantRoutesNow))
	expectFail("an optional field made required", compareRoutes(edit(rt, login, rt.column("Request"), "{phone, password, remember_me}"), tenantRoutesNow))
	expectFail("a request field dropped", compareRoutes(edit(rt, login, rt.column("Request"), "{phone, password}"), tenantRoutesNow))
	expectFail("an error dropped", compareRoutes(edit(rt, login, rt.column("Specific errors"), "`invalid_credentials`"), tenantRoutesNow))
	expectFail("a status changed", compareRoutes(edit(rt, login, rt.column("Success"), "201 `LoginResult`"), tenantRoutesNow))
	expectFail("a route dropped", compareRoutes(drop(rt, login), tenantRoutesNow))
	grownRoutes := map[string]routeFact{}
	for k, v := range tenantRoutesNow {
		grownRoutes[k] = v
	}
	grownRoutes["GET /new"] = routeFact{Key: "GET /new", Auth: "none", Rate: "public-read", Status: "204"}
	expectFail("a route added to the document", compareRoutes(rt, grownRoutes))
	ra := tables["routes-admin"]
	expectFail("an admin route's auth changed", compareRoutes(edit(ra, rowOf(ra, 0, "PUT `/settings/registration`"), ra.column("Auth"), "`admin`"), adminRoutesNow))

	// The admin-fresh set.
	af := tables["admin-fresh"]
	expectFail("a fresh route dropped from the list", compareFresh(edit(af, rowOf(af, 0, "Registration switch"), af.column("Route"), ""), adminRoutesNow))
	downgraded := map[string]routeFact{}
	for k, v := range adminRoutesNow {
		downgraded[k] = v
	}
	f := downgraded["PUT /settings/registration"]
	f.Auth = "admin"
	downgraded["PUT /settings/registration"] = f
	expectFail("a route downgraded in the document", compareFresh(af, downgraded))
	upgraded := map[string]routeFact{}
	for k, v := range adminRoutesNow {
		upgraded[k] = v
	}
	g := upgraded["GET /alerts"]
	g.Auth = "admin-fresh"
	upgraded["GET /alerts"] = g
	expectFail("a route upgraded in the document", compareFresh(af, upgraded))

	// The definer functions (db-r5-4).
	ft := tables["functions"]
	facts := functionFacts(t)
	byName := func(name string, f func(*functionFact)) []functionFact {
		out := append([]functionFact(nil), facts...)
		for i := range out {
			if out[i].Name == name {
				f(&out[i])
			}
		}
		return out
	}
	lookup := rowOf(ft, 0, "`auth_user_by_phone`")
	expectFail("a result column dropped in the spec", compareFunctions(edit(ft, lookup, ft.column("Returns"), "`TABLE(tenant_id uuid)`"), facts))
	expectFail("a result column added in functions.yaml", compareFunctions(ft, byName("auth_user_by_phone", func(f *functionFact) { f.Returns += " " })))
	expectFail("an argument changed in functions.yaml", compareFunctions(ft, byName("auth_user_by_phone", func(f *functionFact) { f.Args = "p_phone text, p_extra text" })))
	expectFail("a role added to EXECUTE in functions.yaml", compareFunctions(ft, byName("auth_totp_seed", func(f *functionFact) { f.Execute = append(f.Execute, "admin") })))
	expectFail("a role dropped from EXECUTE in the spec", compareFunctions(edit(ft, rowOf(ft, 0, "`auth_tickets_revoke`"), ft.column("EXECUTE"), "tenant"), facts))
	expectFail("a function dropped from the table", compareFunctions(drop(ft, lookup), facts))
	expectFail("a function added to functions.yaml", compareFunctions(ft, append(append([]functionFact(nil), facts...), functionFact{Name: "auth_new", Execute: []string{"tenant"}})))
	expectFail("a function the file lacks", compareFunctions(edit(ft, lookup, 0, "`auth_user_by_phone2`"), facts))

	// Tests named anywhere in the spec (sms-r7-2).
	expectFail("a test named in the prose that does not exist", compareTestNames([]string{"1. Something is checked (`TestThatNoLongerExists`)."}, ix))
	expectFail("a test with a subtest that does not exist", compareTestNames([]string{"see `TestNoSuchThing/a_case`"}, ix))
	if got := compareTestNames([]string{"a family `TestAbuseA...` and `TestReissue*`, a real one `TestPasswordLogin`, and a word `Testing`"}, ix); len(got) != 0 {
		t.Errorf("names that must pass were refused: %v", got)
	}

	// The coverage map.
	cv := tables["coverage"]
	row := rowOf(cv, 1, "`TestPasswordLogin`")
	expectFail("a test renamed", compareCoverage(edit(cv, row, 1, "`TestPasswordLoginRenamed`"), ix))
	expectFail("a test in the wrong package", compareCoverage(edit(cv, rowOf(cv, 1, "`internal/lint` `TestLockOrderRule`"), 1, "`internal/api` `TestLockOrderRule`"), ix))
	expectFail("a package that is gone", compareCoverage(edit(cv, row, 1, "`internal/gone` `TestPasswordLogin`"), ix))
}

// TestThrottleLifeCoversEveryWindow ties the throttle row of keyring.Uses to the budget
// registry: a throttle window longer than the life the operator is told to wait would
// make the text wrong, and a life longer than any window would make it needlessly long.
func TestThrottleLifeCoversEveryWindow(t *testing.T) {
	// The long ceiling counts under the same key as the window (round 8), so it is a window of the label too;
	// the test took b.Window only and passed while the operator text understated the longest count by 24
	// (round 9, primitives-r9-2).
	var longest int64
	for _, b := range budget.All() {
		longest = max(longest, int64(b.Window), int64(b.CeilingWindow))
	}
	if longest != int64(keyring.LifeThrottle) {
		t.Fatalf("the longest throttle window is %d ns and keyring.LifeThrottle is %d ns", longest, int64(keyring.LifeThrottle))
	}
}

// operatorLifeAllowed are the string literals of the key commands that may spell a time,
// each with the reason it is not a life of keyring.Uses. A listed literal that is no
// longer in the file fails, so the list cannot outlive its reason.
var operatorLifeAllowed = map[string]string{
	"  sms_outbox.params_ct: not readable by the admin role; a pending row ends within 1 hour": "the outbox ends a pending row in SQL (worker_sms.go, interval '1 hour'), not under a key label",
}

var operatorLifeRE = regexp.MustCompile(`(?i)\b(\d+ ?(seconds?|minutes?|hours?|days?)|an? (hour|day)|hourly|daily)\b`)

// TestOperatorTextSpellsNoLife keeps the text of `ctrlz-admin keys status` and `rekey`
// (internal/admincli/keys.go) from growing a hand-written life again: any string literal
// that names a time fails unless it is on the list above. The lives come from
// keyring.Uses through removalLines (rule spec-fact-drift).
func TestOperatorTextSpellsNoLife(t *testing.T) {
	problems := operatorTextLives(t, filepath.Join(repoRoot(t), "internal", "admincli", "keys.go"), nil)
	if len(problems) > 0 {
		t.Fatal("\n" + strings.Join(problems, "\n"))
	}
	// The lint can fail: a literal with a life, no allowance.
	src := "package x\nconst s = \"wait 1 hour after a rotation\"\nconst fine = \"nothing to re-encrypt\"\n"
	if got := operatorTextLivesOfWith(t, src, map[string]string{}); len(got) != 1 {
		t.Fatalf("a literal that spells a life was not flagged: %v", got)
	}
}

func operatorTextLives(t *testing.T, file string, allowed map[string]string) []string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if allowed == nil {
		allowed = operatorLifeAllowed
	}
	return operatorTextLivesOfWith(t, string(b), allowed)
}

func operatorTextLivesOfWith(t *testing.T, src string, allowed map[string]string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "keys.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	used := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil || !operatorLifeRE.MatchString(s) {
			return true
		}
		if _, ok := allowed[s]; ok {
			used[s] = true
			return true
		}
		problems = append(problems, "keys.go spells a time in the string "+lit.Value+": render it from keyring.Uses")
		return true
	})
	for s := range allowed {
		if !used[s] {
			problems = append(problems, "operatorLifeAllowed lists a string that keys.go no longer has: "+s)
		}
	}
	return problems
}
