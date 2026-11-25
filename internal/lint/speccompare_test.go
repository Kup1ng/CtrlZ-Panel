package lint_test

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

// The comparisons of rule spec-fact-drift. Each takes the marked table and the data of
// its registry and returns the differences in both directions, one line each, naming the
// row of the spec. Nothing here reads a file, so TestSpecFactsCanFail can change either
// side and see the result change.

func setOf(l []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range l {
		m[s] = true
	}
	return m
}

func sameSet(a, b []string) bool {
	x, y := setOf(a), setOf(b)
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if !y[k] {
			return false
		}
	}
	return true
}

func show(l []string) string {
	l = append([]string(nil), l...)
	sort.Strings(l)
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

// namesCell reads the names of a cell that lists backticked words; "none" or empty is no
// names.
func namesCell(cell string) []string { return ticks(cell) }

// ---- keyring domains and uses (8.1, 8.2) ------------------------------------

func compareDomains(tb specTable, domains []string) []string {
	problems := tb.needColumns("Domain")
	if len(problems) > 0 {
		return problems
	}
	var got []string
	for i, r := range tb.rows {
		for _, d := range ticks(r[0]) {
			got = append(got, d)
			if !setOf(domains)[d] {
				problems = append(problems, fmt.Sprintf("%s: domain %s is not in keyring.Domains", specAt(tb.name, tb.lines[i]), d))
			}
		}
	}
	for _, d := range domains {
		if !setOf(got)[d] {
			problems = append(problems, fmt.Sprintf("spec-fact %s: keyring.Domains has %s, the table does not", tb.name, d))
		}
	}
	return problems
}

func useKey(domain, label string) string {
	if label == "" {
		label = "(none)"
	}
	return domain + "/" + label
}

// compareUses holds the labels table of 8.2 to keyring.Uses: the same rows, the same
// order is not required, and every cell equal.
func compareUses(tb specTable, uses []keyring.Use) []string {
	problems := tb.needColumns("Domain", "Label", "Tags", "Lifetime", "If the old key line is removed")
	if len(problems) > 0 {
		return problems
	}
	want := map[string]keyring.Use{}
	for _, u := range uses {
		want[useKey(u.Domain, u.Label)] = u
	}
	seen := map[string]bool{}
	for i, r := range tb.rows {
		at := specAt(tb.name, tb.lines[i])
		label := unticked(r[1])
		if label == "none" {
			label = ""
		}
		k := useKey(unticked(r[0]), label)
		u, ok := want[k]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: %s is not in keyring.Uses", at, k))
			continue
		}
		if seen[k] {
			problems = append(problems, fmt.Sprintf("%s: %s is listed twice", at, k))
		}
		seen[k] = true
		if r[2] != u.What {
			problems = append(problems, fmt.Sprintf("%s: %s tags %q, the registry says %q", at, k, r[2], u.What))
		}
		if r[3] != keyring.LifeText(u.Life) {
			problems = append(problems, fmt.Sprintf("%s: %s lasts %q, the registry says %q", at, k, r[3], keyring.LifeText(u.Life)))
		}
		if r[4] != u.IfRemoved {
			problems = append(problems, fmt.Sprintf("%s: %s removal effect is %q, the registry says %q", at, k, r[4], u.IfRemoved))
		}
	}
	for k := range want {
		if !seen[k] {
			problems = append(problems, fmt.Sprintf("spec-fact %s: keyring.Uses has %s, the table does not", tb.name, k))
		}
	}
	return problems
}

// compareLifetimeProse fails a sentence in the given sections that spells a life the
// registry owns. The lives sit in the table; prose that repeats them is the copy that
// went stale (rounds 1 to 4).
func compareLifetimeProse(sections map[string]string, uses []keyring.Use) []string {
	var problems []string
	lives := map[string]bool{}
	for _, u := range uses {
		lives[keyring.LifeText(u.Life)] = true
	}
	for name, text := range sections {
		for life := range lives {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(life) + `\b`).MatchString(text) {
				problems = append(problems, fmt.Sprintf("section %s spells the life %q in prose; say which label (the table of 8.2 holds the lives)", name, life))
			}
		}
	}
	sort.Strings(problems)
	return problems
}

// ---- audit events (13.2) ----------------------------------------------------

func compareAudit(tb specTable, facts []auditFact, admin bool) []string {
	cols := []string{"Action", "Params"}
	if admin {
		cols = append(cols, "Target")
	}
	if problems := tb.needColumns(cols...); len(problems) > 0 {
		return problems
	}
	byAction := map[string]auditFact{}
	for _, f := range facts {
		byAction[f.Action] = f
	}
	seen := map[string]bool{}
	var problems []string
	for i, r := range tb.rows {
		at := specAt(tb.name, tb.lines[i])
		params := namesCell(r[tb.column("Params")])
		for _, a := range ticks(r[tb.column("Action")]) {
			f, ok := byAction[a]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: action %s is not in the audit registry", at, a))
				continue
			}
			if seen[a] {
				problems = append(problems, fmt.Sprintf("%s: action %s is listed twice", at, a))
			}
			seen[a] = true
			if !sameSet(params, f.Params) {
				problems = append(problems, fmt.Sprintf("%s: %s has params {%s} in the spec, {%s} in the code", at, a, show(params), show(f.Params)))
			}
			if admin {
				target := unticked(r[tb.column("Target")])
				if target != f.Target {
					problems = append(problems, fmt.Sprintf("%s: %s has target %q in the spec, %q in the code", at, a, target, f.Target))
				}
			}
		}
	}
	for _, f := range facts {
		if !seen[f.Action] {
			problems = append(problems, fmt.Sprintf("spec-fact %s: the audit registry has %s, the table does not", tb.name, f.Action))
		}
	}
	return problems
}

// ---- grants (16.2) ----------------------------------------------------------

var createdTableRE = regexp.MustCompile(`(?:CREATE|ALTER) TABLE ctrlz\.([a-z_]+)`)

// grantTables is the set of tables the grants table must cover: the tables 16.1 creates
// or alters, and every table the auth role has a grant on (the role migration 0011
// exists for). A table that either rule names and the spec table lacks is a copy that
// was never made.
func grantTables(lines []string, grants map[string]map[string]string) []string {
	set := map[string]bool{}
	if sec, ok := section(lines, "16.1"); ok {
		for _, m := range createdTableRE.FindAllStringSubmatch(sec, -1) {
			set[m[1]] = true
		}
	}
	for t, roles := range grants {
		if _, ok := roles["auth"]; ok {
			set[t] = true
		}
	}
	var out []string
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func compareGrants(tb specTable, grants map[string]map[string]string, tables []string) []string {
	if problems := tb.needColumns("Table", "Role", "Privileges"); len(problems) > 0 {
		return problems
	}
	var problems []string
	got := map[string]map[string]bool{}
	for i, r := range tb.rows {
		at := specAt(tb.name, tb.lines[i])
		table, role, privs := unticked(r[0]), unticked(r[1]), unticked(r[2])
		roles, ok := grants[table]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: table %s is not in grants.yaml", at, table))
			continue
		}
		want, ok := roles[role]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: grants.yaml gives %s no privilege on %s", at, role, table))
			continue
		}
		if got[table] == nil {
			got[table] = map[string]bool{}
		}
		if got[table][role] {
			problems = append(problems, fmt.Sprintf("%s: %s/%s is listed twice", at, table, role))
		}
		got[table][role] = true
		if privs != want {
			problems = append(problems, fmt.Sprintf("%s: %s/%s is %q in the spec, %q in grants.yaml", at, table, role, privs, want))
		}
	}
	for _, table := range tables {
		for role := range grants[table] {
			if !got[table][role] {
				problems = append(problems, fmt.Sprintf("spec-fact %s: grants.yaml gives %s on %s, the table does not", tb.name, role, table))
			}
		}
		if _, ok := grants[table]; !ok {
			problems = append(problems, fmt.Sprintf("spec-fact %s: %s is expected in grants.yaml and is not there", tb.name, table))
		}
	}
	for table := range got {
		if !setOf(tables)[table] {
			problems = append(problems, fmt.Sprintf("spec-fact %s: the table lists %s, which neither 16.1 creates nor the auth role is granted on", tb.name, table))
		}
	}
	return problems
}

// ---- routes (14.2, 15.2) ----------------------------------------------------

// topLevel splits s at commas that are outside any bracket.
func topLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[', '{', '(', '<':
			depth++
		case ']', '}', ')', '>':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// objectFields reads "{a, b?: x, c: [d]}" into names with whether each is required.
func objectFields(s string) (map[string]bool, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, false
	}
	out := map[string]bool{}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return out, true
	}
	for _, item := range topLevel(inner) {
		name, _, _ := strings.Cut(item, ":")
		name = strings.TrimSpace(name)
		required := !strings.HasSuffix(name, "?")
		out[strings.TrimSuffix(name, "?")] = required
	}
	return out, true
}

var schemaNameRE = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

func compareRequest(cell string, f routeFact) string {
	c := strings.TrimSpace(unticked(cell))
	switch {
	case c == "":
		if f.Body != "" || len(f.BodyFields) > 0 || len(f.Query) > 0 {
			return fmt.Sprintf("the spec has no request, the document has body %q fields {%s} query {%s}", f.Body, show(keysOfBool(f.BodyFields)), show(f.Query))
		}
	case strings.HasPrefix(c, "{"):
		fields, ok := objectFields(c)
		if !ok {
			return fmt.Sprintf("request %q is not an object list", c)
		}
		if len(f.Query) > 0 {
			return fmt.Sprintf("the spec lists a body, the document also has query parameters {%s}", show(f.Query))
		}
		if len(fields) != len(f.BodyFields) {
			return fmt.Sprintf("request fields {%s} in the spec, {%s} in the document", show(describe(fields)), show(describe(f.BodyFields)))
		}
		for k, req := range fields {
			if r, ok := f.BodyFields[k]; !ok || r != req {
				return fmt.Sprintf("request fields {%s} in the spec, {%s} in the document", show(describe(fields)), show(describe(f.BodyFields)))
			}
		}
	case strings.HasPrefix(c, "?"):
		var q []string
		for _, p := range strings.Split(strings.TrimPrefix(c, "?"), "&") {
			name, _, _ := strings.Cut(p, "=")
			q = append(q, strings.TrimSpace(name))
		}
		if !sameSet(q, f.Query) || f.Body != "" {
			return fmt.Sprintf("query {%s} in the spec, {%s} (body %q) in the document", show(q), show(f.Query), f.Body)
		}
	case schemaNameRE.MatchString(c):
		if f.Body != c {
			return fmt.Sprintf("request schema %s in the spec, %q in the document", c, f.Body)
		}
	default:
		return fmt.Sprintf("request %q is neither a field list, a query list nor a schema name", c)
	}
	return ""
}

func keysOfBool(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func describe(m map[string]bool) []string {
	var out []string
	for k, req := range m {
		if !req {
			k += "?"
		}
		out = append(out, k)
	}
	return out
}

func compareSuccess(cell string, f routeFact) string {
	c := strings.TrimSpace(unticked(cell))
	status, rest, _ := strings.Cut(c, " ")
	rest = strings.TrimSpace(rest)
	if status != f.Status {
		return fmt.Sprintf("success status %s in the spec, %s in the document", status, f.Status)
	}
	switch {
	case rest == "":
		if f.Result != "" || len(f.ResultKeys) > 0 {
			return fmt.Sprintf("the spec has no body, the document returns %q {%s}", f.Result, show(f.ResultKeys))
		}
	case strings.HasPrefix(rest, "{"):
		fields, ok := objectFields(rest)
		if !ok {
			return fmt.Sprintf("success %q is not an object list", rest)
		}
		var names []string
		for k := range fields {
			names = append(names, k)
		}
		if !sameSet(names, f.ResultKeys) {
			return fmt.Sprintf("response fields {%s} in the spec, {%s} in the document", show(names), show(f.ResultKeys))
		}
	case schemaNameRE.MatchString(rest):
		if f.Result != rest {
			return fmt.Sprintf("response schema %s in the spec, %q in the document", rest, f.Result)
		}
	default:
		return fmt.Sprintf("success %q is neither a status, a field list nor a schema name", c)
	}
	return ""
}

var routeCellRE = regexp.MustCompile("^([A-Z]+) `([^`]+)`$")

func compareRoutes(tb specTable, routes map[string]routeFact) []string {
	if problems := tb.needColumns("Method, path", "Auth", "Request", "Success", "Specific errors", "Rate"); len(problems) > 0 {
		return problems
	}
	var problems []string
	seen := map[string]bool{}
	for i, r := range tb.rows {
		at := specAt(tb.name, tb.lines[i])
		m := routeCellRE.FindStringSubmatch(r[0])
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s: %q is not METHOD `path`", at, r[0]))
			continue
		}
		key := m[1] + " " + m[2]
		f, ok := routes[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: %s is not in the OpenAPI document", at, key))
			continue
		}
		if seen[key] {
			problems = append(problems, fmt.Sprintf("%s: %s is listed twice", at, key))
		}
		seen[key] = true
		if a := unticked(r[tb.column("Auth")]); a != f.Auth {
			problems = append(problems, fmt.Sprintf("%s: %s has auth %q in the spec, %q in the document", at, key, a, f.Auth))
		}
		if rate := unticked(r[tb.column("Rate")]); rate != f.Rate {
			problems = append(problems, fmt.Sprintf("%s: %s has rate %q in the spec, %q in the document", at, key, rate, f.Rate))
		}
		if p := compareRequest(r[tb.column("Request")], f); p != "" {
			problems = append(problems, fmt.Sprintf("%s: %s: %s", at, key, p))
		}
		if p := compareSuccess(r[tb.column("Success")], f); p != "" {
			problems = append(problems, fmt.Sprintf("%s: %s: %s", at, key, p))
		}
		if errs := ticks(r[tb.column("Specific errors")]); !sameSet(errs, f.Errors) {
			problems = append(problems, fmt.Sprintf("%s: %s has errors {%s} in the spec, {%s} in the document", at, key, show(errs), show(f.Errors)))
		}
	}
	for key := range routes {
		if !seen[key] {
			problems = append(problems, fmt.Sprintf("spec-fact %s: the OpenAPI document has %s, the table does not", tb.name, key))
		}
	}
	return problems
}

// ---- admin-fresh set (10.5) -------------------------------------------------

var methodPathRE = regexp.MustCompile(`^(GET|PUT|POST|PATCH|DELETE) (/.*)$`)

func compareFresh(tb specTable, routes map[string]routeFact) []string {
	if problems := tb.needColumns("Route", "Phase"); len(problems) > 0 {
		return problems
	}
	var problems []string
	listed := map[string]bool{}
	for i, r := range tb.rows {
		at := specAt(tb.name, tb.lines[i])
		for _, rt := range ticks(r[tb.column("Route")]) {
			if !methodPathRE.MatchString(rt) {
				continue
			}
			if r[tb.column("Phase")] != "P1" {
				// A later phase's route does not exist yet; one that does must say P1.
				if _, exists := routes[rt]; exists {
					problems = append(problems, fmt.Sprintf("%s: %s exists in the document but is marked %s", at, rt, r[tb.column("Phase")]))
				}
				continue
			}
			listed[rt] = true
			f, ok := routes[rt]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s: %s is listed for P1 and is not in the admin document", at, rt))
			case f.Auth != "admin-fresh":
				problems = append(problems, fmt.Sprintf("%s: %s is listed but its auth is %q", at, rt, f.Auth))
			}
		}
	}
	for key, f := range routes {
		if f.Auth == "admin-fresh" && !listed[key] {
			problems = append(problems, fmt.Sprintf("spec-fact %s: %s is admin-fresh in the document and not in the list", tb.name, key))
		}
	}
	return problems
}

// ---- coverage map (18.7) ----------------------------------------------------

var (
	testNameRE = regexp.MustCompile(`^Test[A-Za-z0-9_]*\*?$`)
	pathTokRE  = regexp.MustCompile(`^[a-z][A-Za-z0-9_.-]*(/[A-Za-z0-9_.-]+)+$`)
	bareWordRE = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
)

func compareCoverage(tb specTable, ix testIndex) []string {
	if problems := tb.needColumns("Row", "Test"); len(problems) > 0 {
		return problems
	}
	var problems []string
	for i, r := range tb.rows {
		at := specAt(tb.name, tb.lines[i])
		ctx := ""
		var rowDirs []string
		for _, tok := range ticks(r[tb.column("Test")]) {
			switch {
			case testNameRE.MatchString(tok):
				name := strings.TrimSuffix(tok, "*")
				prefix := strings.HasSuffix(tok, "*")
				pool := ix.all
				where := "anywhere in the repository"
				if ctx != "" {
					pool = ix.byDir[ctx]
					where = "in " + ctx
				}
				if !hasTest(pool, name, prefix) {
					problems = append(problems, fmt.Sprintf("%s: %s is not a test function %s", at, tok, where))
				}
			case pathTokRE.MatchString(tok):
				if !ix.files[tok] {
					problems = append(problems, fmt.Sprintf("%s: %s does not exist", at, tok))
					continue
				}
				if ix.dirs[tok] {
					ctx = tok
					rowDirs = append(rowDirs, tok)
				}
			case bareWordRE.MatchString(tok):
				ctx = resolveBare(tok, rowDirs, ix)
			}
		}
	}
	return problems
}

func hasTest(pool map[string]bool, name string, prefix bool) bool {
	if !prefix {
		return pool[name]
	}
	for n := range pool {
		if strings.HasPrefix(n, name) {
			return true
		}
	}
	return false
}

// resolveBare maps a package's short name (`sweep`, `store`) to its directory: the one of
// that name already named in the row, else the only directory of that name with tests.
// A name that does not resolve drops the package context, so the next test name is
// looked up everywhere, which is looser and never wrong in the stricter direction.
func resolveBare(word string, rowDirs []string, ix testIndex) string {
	var hits []string
	for _, d := range rowDirs {
		if path.Base(d) == word {
			hits = append(hits, d)
		}
	}
	if len(hits) == 1 {
		return hits[0]
	}
	hits = nil
	for d := range ix.byDir {
		if path.Base(d) == word {
			hits = append(hits, d)
		}
	}
	if len(hits) == 1 {
		return hits[0]
	}
	return ""
}

// ---- definer functions (16.3) -----------------------------------------------

// functionFact is one SECURITY DEFINER function of functions.yaml as the spec shows it.
type functionFact struct {
	Name, Args, Returns string
	Execute             []string
}

// compareFunctions holds the table of 16.3 to functions.yaml in both directions: every
// function of the allow list has a row, every row names a function of it, and the
// arguments, the result and the roles that may execute it are equal. The signatures were
// copied by hand into 5.7, 10.7 and 16.3 and were three migrations stale (db-r5-4); the
// text of a signature is now one the test reads.
func compareFunctions(tb specTable, facts []functionFact) []string {
	if problems := tb.needColumns("Function", "Args", "EXECUTE", "Returns"); len(problems) > 0 {
		return problems
	}
	want := map[string]functionFact{}
	for _, f := range facts {
		want[f.Name] = f
	}
	var problems []string
	seen := map[string]bool{}
	for i, r := range tb.rows {
		at := specAt(tb.name, tb.lines[i])
		name := unticked(r[tb.column("Function")])
		f, ok := want[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: %s is not in functions.yaml", at, name))
			continue
		}
		if seen[name] {
			problems = append(problems, fmt.Sprintf("%s: %s is listed twice", at, name))
		}
		seen[name] = true
		args := unticked(r[tb.column("Args")])
		if args == "none" {
			args = ""
		}
		if args != f.Args {
			problems = append(problems, fmt.Sprintf("%s: %s takes (%s) in the spec, (%s) in functions.yaml", at, name, args, f.Args))
		}
		if got := unticked(r[tb.column("Returns")]); got != f.Returns {
			problems = append(problems, fmt.Sprintf("%s: %s returns %q in the spec, %q in functions.yaml", at, name, got, f.Returns))
		}
		var roles []string
		for _, x := range strings.Split(r[tb.column("EXECUTE")], ",") {
			if x = strings.TrimSpace(x); x != "" {
				roles = append(roles, x)
			}
		}
		if !sameSet(roles, f.Execute) {
			problems = append(problems, fmt.Sprintf("%s: %s is executable by %s in the spec, %s in functions.yaml", at, name, show(roles), show(f.Execute)))
		}
	}
	for _, f := range facts {
		if !seen[f.Name] {
			problems = append(problems, fmt.Sprintf("spec-fact %s: functions.yaml has %s, the table does not", tb.name, f.Name))
		}
	}
	return problems
}

// specTestRef finds a test named in the spec's prose: a backticked identifier that starts with
// Test, whole, with an optional subtest path. `TestAbuseA...` and `TestReissue*` name a family
// and not one function, and are not read here.
var specTestRef = regexp.MustCompile("`(Test[A-Z0-9_][A-Za-z0-9_]*)(?:/[^`]*)?`")

// compareTestNames is the half of the coverage rule that the coverage table does not reach
// (sms-r7-2): every test the spec names ANYWHERE, in the numbered test list, the review notes or a
// finding's paragraph, must be a Test function of the repository. A test that is renamed or
// deleted in a fix commit otherwise leaves the spec claiming coverage that no longer runs. The
// table of 18.7 is judged by compareCoverage, with its package; this reads the rest by name.
func compareTestNames(lines []string, ix testIndex) []string {
	var problems []string
	seen := map[string]bool{}
	for i, line := range lines {
		for _, m := range specTestRef.FindAllStringSubmatch(line, -1) {
			if ix.all[m[1]] || seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			problems = append(problems, fmt.Sprintf("%s: %s is not a test function of the repository (renamed or deleted: change the spec, or give the property its test back)", specAt("test-names", i+1), m[1]))
		}
	}
	return problems
}
