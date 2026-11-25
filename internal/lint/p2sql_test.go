package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The structural lints of the P2 write path (docs/specs/p2-profiles.md 10.2 S1, S8, S9). Each one reads the constant SQL
// text of every database call of the module, by the value go/types computes (as TestMultiRowWritesLockInKeyOrder does), and
// judges it with the function that sends it:
//
//	S1  a statement that writes the content of a profile (profile_options, profile_filters, profile_services, rule_folders,
//	    rules, block_pages, and profiles outside its lock columns) is sent by a function that takes or returns the
//	    store.ProfileWrite of that profile, and names the profile it is bounded by; the only others are the system
//	    writers of the named list, each with its reason and the shape of its statement, and an entry that matches no
//	    statement fails.
//	S8  no statement names catalog_no_redirect_domain except the predicate's one lookup, which returns booleans, so no
//	    route can return the list.
//	S9  no statement writes lock_state, lock_password_hash, lock_message, locked_by or locked_at outside the Lock and
//	    Unlock methods, none reads lock_password_hash outside them, and none reads a whole row of ctrlz.profiles (a star,
//	    an alias star, RETURNING *, a row reference, to_jsonb or row_to_json of the row), because that row holds the hash.

// p2ContentTables are the tables a profile's content lives in, whose every write needs the permission of the profile.
func p2ContentTables() []string {
	return []string{"profile_options", "profile_filters", "profile_services", "rule_folders", "rules", "block_pages"}
}

// p2LockColumns are the five lock columns of ctrlz.profiles (spec 2.2 item 11).
func p2LockColumns() []string {
	return []string{"lock_state", "lock_password_hash", "lock_message", "locked_by", "locked_at"}
}

// p2LockWriters are the functions that may write the lock columns and read the hash, each with what it is. P7's
// admin removal of a lock (T-143) enters when it exists.
func p2LockWriters() map[string]string {
	return map[string]string{
		"ProfileLock":     "Lock (spec 7.1): sets the five lock columns of an unlocked profile",
		"ProfileUnlock":   "Unlock (spec 7.2): clears them where the hash is the one that was verified",
		"ProfileLockHash": "reads the hash for Unlock to verify (spec 7.2)",
	}
}

// p2SystemWriter is one statement that writes profile content without the permission of a profile: the expiry purge of
// P4 and the location flags of P4b enter here. Keyed by the name of the constant that holds the statement, pinned by its
// digest (stmtDigest), with the reason and the columns it may set or the shape of its DELETE (spec 3.1).
type p2SystemWriter struct {
	table, reason, shape, digest string
}

// p2SystemWriters is empty in P2.
func p2SystemWriters() map[string]p2SystemWriter { return map[string]p2SystemWriter{} }

// p2NoRedirectLookup is the function that sends the one statement that names catalog_no_redirect_domain, and the text of
// that statement: it selects the pattern and a boolean for the entries the caller names, and nothing else. A change to it is a
// decision, not a drift.
func p2NoRedirectLookup() (fn, norm string) {
	return "NoRedirectLookup", p2Norm("SELECT pattern, scope = 'host' FROM ctrlz.catalog_no_redirect_domain WHERE pattern = ANY ($1::text[])")
}

// p2Site is one database call whose statement is a constant, with the function that makes the call.
type p2Site struct {
	path, fn, name, norm string
	line                 int
	hasWrite             bool // the function takes or returns a ProfileWrite
}

var (
	reString   = regexp.MustCompile(`'(?:[^']|'')*'`)
	reSpaces   = regexp.MustCompile(`\s+`)
	reCountAll = regexp.MustCompile(`count\(\s*\*\s*\)`)
	// The one star a profile statement may carry that is not a profile row: the cap statements read the tenant's plan as
	// `WITH lim AS (SELECT * FROM ctrlz_fn.tenant_plan())`, and the caps lint reads a limit only as lim.<column> inside
	// ctrlz.cap_reached, so a column list there is refused. The function returns the plan's columns and never a profile.
	reTenantPlanStar = regexp.MustCompile(`\bselect\s+\*\s+from\s+ctrlz_fn\.tenant_plan\(\s*\)`)
	reInsertC        = regexp.MustCompile(`\binsert into (?:ctrlz\.)?(\w+)\s*(?:as \w+\s*)?\(([^)]*)\)`)
	reInsertT        = regexp.MustCompile(`\binsert into (?:ctrlz\.)?(\w+)\b`)
	reUpdateT        = regexp.MustCompile(`(?:^|[\s(;])update (?:only )?(?:ctrlz\.)?(\w+)(?: (?:as )?(\w+))? set `)
	reDeleteT        = regexp.MustCompile(`\bdelete from (?:only )?(?:ctrlz\.)?(\w+)`)
	reDoUpdate       = regexp.MustCompile(`\bon conflict\b.*?\bdo update set (.*)`)
	reProfiles       = regexp.MustCompile(`\b(?:from|join|update|into|using)\s+(?:only\s+)?(?:ctrlz\.)?profiles(?:\s+(?:as\s+)?(\w+))?\b`)
	reSetEnd         = regexp.MustCompile(` (?:where|from|returning|on conflict)\b`)
)

// p2Norm is a statement as the lints read it: comments and string contents gone, lower case, single spaces.
func p2Norm(sql string) string {
	s := stripSQLComments(sql)
	s = reString.ReplaceAllString(s, "''")
	s = strings.ToLower(s)
	s = reSpaces.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// p2Write is one write of a statement: the table, and for an INSERT or UPDATE the columns it sets.
type p2Write struct {
	kind, table string
	cols        []string
}

// topSplit splits on the commas outside parentheses.
func topSplit(s string) []string {
	var out []string
	depth, from := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[from:i])
				from = i + 1
			}
		}
	}
	return append(out, s[from:])
}

// setColumns reads the columns a SET list assigns.
func setColumns(set string) []string {
	if loc := reSetEnd.FindStringIndex(set); loc != nil {
		set = set[:loc[0]]
	}
	var cols []string
	for _, piece := range topSplit(set) {
		lhs, _, ok := strings.Cut(piece, "=")
		if !ok {
			continue
		}
		lhs = strings.Trim(strings.TrimSpace(lhs), "()")
		for _, c := range strings.Split(lhs, ",") {
			c = strings.TrimSpace(c)
			if i := strings.LastIndexByte(c, '.'); i >= 0 {
				c = c[i+1:]
			}
			if c != "" {
				cols = append(cols, c)
			}
		}
	}
	return cols
}

// p2Writes lists the writes a normalised statement makes.
func p2Writes(norm string) []p2Write {
	var out []p2Write
	seen := map[string]bool{}
	for _, m := range reInsertC.FindAllStringSubmatch(norm, -1) {
		var cols []string
		for _, c := range strings.Split(m[2], ",") {
			cols = append(cols, strings.TrimSpace(c))
		}
		out = append(out, p2Write{"insert", m[1], cols})
		seen[m[1]] = true
	}
	for _, m := range reInsertT.FindAllStringSubmatch(norm, -1) {
		if !seen[m[1]] {
			out = append(out, p2Write{"insert", m[1], nil})
		}
	}
	// Each UPDATE has its own SET list, which runs to the next UPDATE or to the end of the statement and is cut at its WHERE,
	// FROM or RETURNING by setColumns. A greedy match took the first UPDATE only, so a second one (the CTE form) went unseen.
	ups := reUpdateT.FindAllStringSubmatchIndex(norm, -1)
	for i, m := range ups {
		end := len(norm)
		if i+1 < len(ups) {
			end = ups[i+1][0]
		}
		out = append(out, p2Write{"update", norm[m[2]:m[3]], setColumns(norm[m[1]:end])})
	}
	for _, m := range reDoUpdate.FindAllStringSubmatch(norm, -1) {
		table := ""
		if t := reInsertT.FindStringSubmatch(norm); t != nil {
			table = t[1]
		}
		out = append(out, p2Write{"update", table, setColumns(m[1])})
	}
	for _, m := range reDeleteT.FindAllStringSubmatch(norm, -1) {
		out = append(out, p2Write{"delete", m[1], nil})
	}
	return out
}

func inList(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// takesProfileWrite says a function declares a ProfileWrite among its parameters or results.
func takesProfileWrite(fd *ast.FuncDecl) bool {
	has := func(fl *ast.FieldList) bool {
		if fl == nil {
			return false
		}
		for _, f := range fl.List {
			if strings.HasSuffix(exprText(f.Type), "ProfileWrite") {
				return true
			}
		}
		return false
	}
	return has(fd.Type.Params) || has(fd.Type.Results)
}

// p2Sites reads every database call of the module whose statement is constant.
func p2Sites(fset *token.FileSet, files []file) ([]p2Site, string) {
	info, ok := typeInfo(fset, files)
	if !ok {
		return nil, "type information unavailable"
	}
	var out []p2Site
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			pw := takesProfileWrite(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				idx, isSink := sqlSinks()[calleeName(call.Fun)]
				if !isSink || idx < 0 || len(call.Args) <= idx {
					return true
				}
				tv, known := info.Types[call.Args[idx]]
				if !known || tv.Value == nil || tv.Value.Kind() != constant.String {
					return true // the sql-const rule reports it
				}
				out = append(out, p2Site{path: f.path, fn: fd.Name.Name, name: stmtName(call.Args[idx]), norm: p2Norm(constant.StringVal(tv.Value)),
					line: fset.Position(call.Pos()).Line, hasWrite: pw})
				return true
			})
		}
	}
	return out, ""
}

// p2Problems is the three lints over a set of files, with the list of system writers it is given.
func p2Problems(fset *token.FileSet, files []file, writers map[string]p2SystemWriter) []string {
	sites, bad := p2Sites(fset, files)
	if bad != "" {
		return []string{bad}
	}
	var out []string
	add := func(s p2Site, format string, args ...any) {
		out = append(out, fmt.Sprintf("%s:%d (%s): %s", s.path, s.line, s.fn, fmt.Sprintf(format, args...)))
	}
	used := map[string]bool{}
	lookupFn, lookupNorm := p2NoRedirectLookup()
	for _, s := range sites {
		// S1: a write of profile content, reported once for each table a statement writes.
		reported := map[string]bool{}
		for _, w := range p2Writes(s.norm) {
			content := inList(p2ContentTables(), w.table)
			if w.table == "profiles" {
				// A write of the lock columns alone is S9's; any other write of profiles is content (a name, a version, the row).
				onlyLock := w.kind == "update" && len(w.cols) > 0
				for _, c := range w.cols {
					if !inList(p2LockColumns(), c) {
						onlyLock = false
					}
				}
				content = !onlyLock
			}
			if !content || reported[w.table] {
				continue
			}
			reported[w.table] = true
			if e, ok := writers[s.name]; ok && e.table == w.table && e.digest == stmtDigest(s.norm) {
				used[s.name] = true
				continue
			}
			if !s.hasWrite {
				add(s, "%s of ctrlz.%s (statement %q) is sent by a function that neither takes nor returns the store.ProfileWrite of the profile: write it through the guard, or list the statement in p2SystemWriters with its reason and its shape", w.kind, w.table, s.name)
			}
			if w.table != "profiles" && !strings.Contains(s.norm, "profile_id") {
				add(s, "%s of ctrlz.%s (statement %q) names no profile_id: every statement of the write path is bounded by the profile of its ProfileWrite", w.kind, w.table, s.name)
			}
		}
		// S8: the list of names that are never proxied is read by one lookup.
		if strings.Contains(s.norm, "catalog_no_redirect_domain") {
			if !(s.fn == lookupFn && s.norm == lookupNorm) {
				add(s, "statement %q names catalog_no_redirect_domain: only the lookup of %s, which returns booleans, may (spec 3.6, 10.2 S8)", s.name, lookupFn)
			}
		}
		// S9: the lock columns, the hash and the whole row.
		for _, w := range p2Writes(s.norm) {
			if w.table != "profiles" {
				continue
			}
			touched := false
			for _, c := range w.cols {
				touched = touched || inList(p2LockColumns(), c)
			}
			if _, ok := p2LockWriters()[s.fn]; touched && !ok {
				add(s, "%s of ctrlz.profiles (statement %q) writes a lock column outside the Lock and Unlock methods", w.kind, s.name)
			}
		}
		if strings.Contains(s.norm, "lock_password_hash") {
			if _, ok := p2LockWriters()[s.fn]; !ok {
				add(s, "statement %q mentions lock_password_hash outside Lock, Unlock and the read Unlock verifies against", s.name)
			}
		}
		if reason := wholeProfileRow(s.norm); reason != "" {
			add(s, "statement %q reads ctrlz.profiles as a whole row (%s): name the columns, the row holds the lock hash", s.name, reason)
		}
	}
	for name := range writers {
		if !used[name] {
			out = append(out, fmt.Sprintf("p2SystemWriters names %s, which matches no statement (or a statement whose digest changed): remove the entry or read the statement again", name))
		}
	}
	sort.Strings(out)
	return out
}

// wholeProfileRow says why a statement reads ctrlz.profiles as a whole row, or "" if it does not.
func wholeProfileRow(norm string) string {
	ms := reProfiles.FindAllStringSubmatch(norm, -1)
	if len(ms) == 0 {
		return ""
	}
	names := []string{"profiles", "ctrlz.profiles"}
	for _, m := range ms {
		if m[1] != "" {
			names = append(names, m[1])
		}
	}
	s := reCountAll.ReplaceAllString(norm, "count(1)")
	s = reTenantPlanStar.ReplaceAllString(s, "select 1")
	if regexp.MustCompile(`\breturning\s+\*`).MatchString(s) {
		return "RETURNING *"
	}
	if regexp.MustCompile(`\bselect\s+(?:distinct\s+)?\*`).MatchString(s) {
		return "SELECT *"
	}
	for _, n := range names {
		q := regexp.QuoteMeta(n)
		switch {
		case regexp.MustCompile(`(?:^|[^\w.])` + q + `\.\*`).MatchString(s):
			return n + ".*"
		case regexp.MustCompile(`\b(?:to_jsonb|to_json|row_to_json|jsonb_agg|json_agg|row|jsonb_build_array|array_agg)\s*\(\s*` + q + `\s*(?:\)|,)`).MatchString(s):
			return "a function of the row " + n
		case regexp.MustCompile(`\(\s*` + q + `\s*\)\s*\.\s*\*`).MatchString(s):
			return "the star of the row " + n
		case regexp.MustCompile(`(?:^|[^\w.])` + q + `\s*::\s*\w+`).MatchString(s):
			return "a cast of the row " + n
		case regexp.MustCompile(`\bselect\s+(?:distinct\s+)?` + q + `\s+from\b`).MatchString(s), regexp.MustCompile(`\breturning\s+` + q + `\b\s*(?:$|;|\))`).MatchString(s):
			return "the row reference " + n
		case regexp.MustCompile(`\bselect\s+(?:[\w.]+\s*,\s*)+`+q+`\s*(?:,|\bfrom\b)`).MatchString(s) && n != "profiles" && n != "ctrlz.profiles":
			return "the row reference " + n
		}
	}
	return ""
}

func TestProfileWritesTakeAProfileWrite(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range p2Problems(fset, files, p2SystemWriters()) {
		t.Error(p)
	}
	// The lints must have seen the write path: every content table, the guard, the lock and the lookup.
	sites, bad := p2Sites(fset, files)
	if bad != "" {
		t.Fatal(bad)
	}
	seen := map[string]bool{}
	for _, s := range sites {
		for _, w := range p2Writes(s.norm) {
			seen[w.table] = true
		}
		if strings.Contains(s.norm, "catalog_no_redirect_domain") {
			seen["lookup"] = true
		}
		if strings.Contains(s.norm, "lock_password_hash") {
			seen["lock"] = true
		}
	}
	for _, want := range append(p2ContentTables(), "profiles", "lookup", "lock") {
		if want == "block_pages" {
			continue // the block page is P4b's: no statement writes it yet, and the lint judges it when one does
		}
		if !seen[want] {
			t.Errorf("the P2 lints saw no statement of %s: they are looking in the wrong place", want)
		}
	}
}

// TestP2SQLLintsCanFail plants each shape and requires the verdict, as TestSQLLintCatchesWhatItShouldNot does.
func TestP2SQLLintsCanFail(t *testing.T) {
	const header = "package pkg\nimport \"context\"\ntype DB struct{}\nfunc (DB) Exec(context.Context, string, ...any) {}\nfunc (DB) Query(context.Context, string, ...any) {}\nfunc (DB) QueryRow(context.Context, string, ...any) {}\ntype ProfileWrite struct{}\nvar ctx = context.Background()\nvar db DB\n"
	cases := []struct {
		name string
		src  string
		bad  int
	}{
		{"a rule written by a method with the permission", `func RulesDelete(w ProfileWrite) { db.Exec(ctx, "DELETE FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND id = ANY($3)") }`, 0},
		{"a rule written with no permission", `func Sweep() { db.Exec(ctx, "DELETE FROM ctrlz.rules WHERE expires_at < now()") }`, 2},
		{"a folder insert from a method with no permission", `func Add() { db.Exec(ctx, "INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) VALUES ($1, $2, $3)") }`, 1},
		{"a service upsert with no permission", `func Put() { db.Exec(ctx, "INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug) VALUES ($1, $2, $3) ON CONFLICT (tenant_id, profile_id, service_slug) DO UPDATE SET action = excluded.action") }`, 1},
		{"the guard, which returns the permission", `func ProfileGuard() ProfileWrite { db.Exec(ctx, "UPDATE ctrlz.profiles SET version = version + 1 WHERE tenant_id = $1 AND id = $2 AND lock_state = 'unlocked' RETURNING id"); return ProfileWrite{} }`, 0},
		{"a rename with no permission", `func Rename() { db.Exec(ctx, "UPDATE ctrlz.profiles SET name = $3 WHERE tenant_id = $1 AND id = $2") }`, 1},
		{"a delete of profiles with no permission", `func Drop() { db.Exec(ctx, "DELETE FROM ctrlz.profiles WHERE tenant_id = $1 AND id = $2") }`, 1},
		{"options written by a method with the permission", `func OptionsSet(w ProfileWrite) { db.Exec(ctx, "INSERT INTO ctrlz.profile_options (tenant_id, profile_id, block_ttl) VALUES ($1, $2, $3)") }`, 0},
		{"a read of the rules is not a write", `func Rules() { db.Query(ctx, "SELECT id FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2") }`, 0},
		{"Lock", `func ProfileLock() { db.Exec(ctx, "UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = $3, lock_message = $4, locked_by = $5, locked_at = now() WHERE tenant_id = $1 AND id = $2 AND lock_state = 'unlocked' RETURNING id") }`, 0},
		{"the lock state cleared from another method", `func Reopen(w ProfileWrite) { db.Exec(ctx, "UPDATE ctrlz.profiles SET lock_state = 'unlocked' WHERE tenant_id = $1 AND id = $2") }`, 1},
		{"the lock written in a CTE of another method", `func Other() { db.Exec(ctx, "WITH x AS (UPDATE ctrlz.profiles SET locked_by = NULL WHERE tenant_id = $1 RETURNING id) SELECT 1") }`, 1},
		{"the lock cleared by the second UPDATE of a CTE", `func Other(w ProfileWrite) { db.Exec(ctx, "WITH x AS (UPDATE ctrlz.rules SET enabled = false WHERE tenant_id = $1 AND profile_id = $2 RETURNING id) UPDATE ctrlz.profiles SET lock_state = 'unlocked' WHERE tenant_id = $1 AND id = $2") }`, 1},
		{"a content write in the second UPDATE of a CTE with no permission", `func Other() { db.Exec(ctx, "WITH x AS (UPDATE ctrlz.profiles SET lock_state = 'unlocked' WHERE tenant_id = $1 AND id = $2 RETURNING id) UPDATE ctrlz.rules SET enabled = false WHERE tenant_id = $1 AND profile_id = $2") }`, 2},
		{"the row cast to text", `func Get() { db.Query(ctx, "SELECT p::text FROM ctrlz.profiles p WHERE p.tenant_id = $1") }`, 1},
		{"the star of a parenthesised row", `func Get() { db.Query(ctx, "SELECT (p).* FROM ctrlz.profiles p WHERE p.tenant_id = $1") }`, 1},
		{"a column cast is not the row", `func Get() { db.Query(ctx, "SELECT p.id::text FROM ctrlz.profiles p WHERE p.tenant_id = $1") }`, 0},
		{"the hash read by a route", `func Show() { db.Query(ctx, "SELECT lock_password_hash FROM ctrlz.profiles WHERE tenant_id = $1 AND id = $2") }`, 1},
		{"the hash read by Unlock's helper", `func ProfileLockHash() { db.Query(ctx, "SELECT lock_password_hash FROM ctrlz.profiles WHERE tenant_id = $1 AND id = $2 AND lock_state = 'locked'") }`, 0},
		{"a whole row", `func Get() { db.Query(ctx, "SELECT * FROM ctrlz.profiles WHERE tenant_id = $1") }`, 1},
		{"RETURNING * in the guard", `func ProfileGuard() ProfileWrite { db.Exec(ctx, "UPDATE ctrlz.profiles SET version = version + 1 WHERE tenant_id = $1 AND id = $2 RETURNING *"); return ProfileWrite{} }`, 1},
		{"an alias star", `func Get() { db.Query(ctx, "SELECT p.* FROM ctrlz.profiles p WHERE p.tenant_id = $1") }`, 1},
		{"the row as JSON", `func Get() { db.Query(ctx, "SELECT to_jsonb(p) FROM ctrlz.profiles p WHERE p.tenant_id = $1") }`, 1},
		{"the row by its alias", `func Get() { db.Query(ctx, "SELECT p FROM ctrlz.profiles p WHERE p.tenant_id = $1") }`, 1},
		{"named columns", `func Get() { db.Query(ctx, "SELECT id, name, lock_state = 'locked' FROM ctrlz.profiles WHERE tenant_id = $1") }`, 0},
		{"the star over the tenant plan beside a read of profiles", `func Room() { db.Query(ctx, "WITH lim AS (SELECT * FROM ctrlz_fn.tenant_plan()) SELECT p.id FROM ctrlz.profiles p WHERE p.tenant_id = $1 AND (SELECT lim.max_profiles FROM lim) > 0") }`, 0},
		{"a star over another function is still a row", `func Get() { db.Query(ctx, "WITH x AS (SELECT * FROM ctrlz_fn.profile_rows()) SELECT id FROM ctrlz.profiles p WHERE p.tenant_id = $1") }`, 1},
		{"the plan star next to a star over the profiles", `func Get() { db.Query(ctx, "WITH lim AS (SELECT * FROM ctrlz_fn.tenant_plan()) SELECT * FROM ctrlz.profiles WHERE tenant_id = $1") }`, 1},
		{"a count is not a row", `func Count() { db.Query(ctx, "SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1") }`, 0},
		{"a star on another table in a join", `func Get() { db.Query(ctx, "SELECT r.* FROM ctrlz.rules r JOIN ctrlz.profiles p ON p.id = r.profile_id WHERE p.tenant_id = $1") }`, 0},
		{"the list read by a route", `func List() { db.Query(ctx, "SELECT pattern FROM ctrlz.catalog_no_redirect_domain") }`, 1},
		{"the list joined into a read", `func Names() { db.Query(ctx, "SELECT d.domain FROM ctrlz.catalog_service_domain d WHERE NOT EXISTS (SELECT 1 FROM ctrlz.catalog_no_redirect_domain n WHERE n.pattern = d.domain)") }`, 1},
		{"the lookup", `func NoRedirectLookup() { db.Query(ctx, "SELECT pattern, scope = 'host' FROM ctrlz.catalog_no_redirect_domain WHERE pattern = ANY ($1::text[])") }`, 0},
		{"the lookup grown to return the scope as text", `func NoRedirectLookup() { db.Query(ctx, "SELECT pattern, scope FROM ctrlz.catalog_no_redirect_domain WHERE pattern = ANY ($1::text[])") }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		path := "internal/store/planted.go"
		af, err := parser.ParseFile(fset, path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := p2Problems(fset, []file{{path: path, ast: af}, filler(t, fset)}, map[string]p2SystemWriter{})
		if len(got) != c.bad {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.bad)
		}
	}
	// An entry of the system-writer list that matches no statement fails, and a statement with an entry is excused.
	fset := token.NewFileSet()
	path := "internal/store/planted.go"
	src := header + "const qPurge = \"DELETE FROM ctrlz.rules WHERE profile_id IS NOT NULL AND expires_at < now()\"\nfunc Purge() { db.Exec(ctx, qPurge) }\n"
	af, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	files := []file{{path: path, ast: af}, filler(t, fset)}
	if got := p2Problems(fset, files, map[string]p2SystemWriter{}); len(got) != 1 {
		t.Errorf("a purge with no entry: %v, want one problem", got)
	}
	entry := map[string]p2SystemWriter{"qPurge": {table: "rules", reason: "expiry purge", shape: "DELETE by expires_at", digest: stmtDigest("delete from ctrlz.rules where profile_id is not null and expires_at < now()")}}
	if got := p2Problems(fset, files, entry); len(got) != 0 {
		t.Errorf("a purge with its entry: %v, want none", got)
	}
	stale := map[string]p2SystemWriter{"qGone": {table: "rules", digest: "x"}}
	if got := p2Problems(fset, files, stale); len(got) != 2 {
		t.Errorf("an entry that matches nothing: %v, want it and the unlisted purge", got)
	}
	edited := map[string]p2SystemWriter{"qPurge": {table: "rules", digest: stmtDigest("delete from ctrlz.rules")}}
	if got := p2Problems(fset, files, edited); len(got) != 2 {
		t.Errorf("an entry whose digest is not the statement's: %v, want the statement and the stale entry", got)
	}
}
