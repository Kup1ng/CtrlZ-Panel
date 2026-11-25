package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// E9 of docs/specs/p3-endpoints.md 11.2: the sealed DoH token has one reader. No SQL statement reads endpoints.doh_token_ct except
// the lookup of the one function that hands the ciphertext to the key ring, no statement reads a whole row of ctrlz.endpoints
// (the row holds the ciphertext), and that function is called from one place, the Resolver view. The catalog half of E9 (no view
// exposes either secret column, no tenant grant on the proof observation columns) is in internal/store/catalogtest, where the
// catalog is.

// p3TokenReader is the one function that may read the sealed token, and the text of the statement it sends.
func p3TokenReader() (fn, norm string) {
	return "EndpointTokenCT", p2Norm("SELECT doh_token_ct FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = $2")
}

// p3TokenCaller is the one function that may call the reader: ResolverFor opens the token under the Endpoint's own id and hands
// the result to internal/setup, so the plaintext never leaves that path (path#function).
func p3TokenCaller() string { return "internal/endpoints/links.go#ResolverFor" }

var (
	reTokenAssign  = regexp.MustCompile(`\bdoh_token_ct\s*=\s*\$\d+(?:::\w+)?`)
	reInsertColsCT = regexp.MustCompile(`\binsert into (?:ctrlz\.)?endpoints\s*\([^)]*\bdoh_token_ct\b[^)]*\)`)
	reEndpoints    = regexp.MustCompile(`\b(?:from|join|update|into|using)\s+(?:only\s+)?(?:ctrlz\.)?endpoints(?:\s+(?:as\s+)?(\w+))?\b`)
)

// readsTheToken says a statement names doh_token_ct anywhere but the column list of an INSERT and the assignment of an UPDATE,
// which are writes of a ciphertext that was sealed before it reached the statement.
func readsTheToken(norm string) bool {
	s := reInsertColsCT.ReplaceAllString(norm, "insert into endpoints ()")
	// Only the SET list of an UPDATE may assign it: the same text in a WHERE is a filter on the ciphertext, which is a read.
	if m := reUpdateT.FindStringSubmatchIndex(s); m != nil && m[6] >= 0 {
		set, rest := s[m[6]:m[7]], ""
		if end := reSetEnd.FindStringIndex(set); end != nil {
			set, rest = set[:end[0]], set[end[0]:]
		}
		s = s[:m[6]] + reTokenAssign.ReplaceAllString(set, "") + rest
	}
	return strings.Contains(s, "doh_token_ct")
}

// wholeEndpointRow says why a statement reads ctrlz.endpoints as a whole row, or "" if it does not (the shapes of wholeProfileRow,
// for the table that holds doh_token_ct).
func wholeEndpointRow(norm string) string {
	ms := reEndpoints.FindAllStringSubmatch(norm, -1)
	if len(ms) == 0 {
		return ""
	}
	names := []string{"endpoints", "ctrlz.endpoints"}
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
		case regexp.MustCompile(`\bselect\s+(?:distinct\s+)?` + q + `\s+from\b`).MatchString(s), regexp.MustCompile(`\breturning\s+` + q + `\b\s*(?:$|;|\))`).MatchString(s):
			return "the row reference " + n
		}
	}
	return ""
}

// p3TokenCalls lists the functions that call EndpointTokenCT, as path#function. The declaration itself is not a call.
func p3TokenCalls(files []file) []string {
	var out []string
	for _, f := range files {
		if f.test {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && calleeName(call.Fun) == "EndpointTokenCT" {
					out = append(out, f.path+"#"+fd.Name.Name)
				}
				return true
			})
		}
	}
	return out
}

// p3SecretProblems is the lint over a set of files.
func p3SecretProblems(fset *token.FileSet, files []file) []string {
	sites, bad := p2Sites(fset, files)
	if bad != "" {
		return []string{bad}
	}
	var out []string
	add := func(s p2Site, format string, args ...any) {
		out = append(out, fmt.Sprintf("%s:%d (%s): %s", s.path, s.line, s.fn, fmt.Sprintf(format, args...)))
	}
	readerFn, readerNorm := p3TokenReader()
	for _, s := range sites {
		if readsTheToken(s.norm) && !(s.fn == readerFn && s.norm == readerNorm) {
			add(s, "statement %q reads endpoints.doh_token_ct: only %s may, with exactly the lookup that returns the ciphertext of one Endpoint (spec 11.2 E9)", s.name, readerFn)
		}
		if reason := wholeEndpointRow(s.norm); reason != "" {
			add(s, "statement %q reads ctrlz.endpoints as a whole row (%s): name the columns, the row holds the sealed DoH token", s.name, reason)
		}
	}
	for _, c := range p3TokenCalls(files) {
		if c != p3TokenCaller() {
			out = append(out, fmt.Sprintf("%s calls EndpointTokenCT: only %s may, so the sealed token is opened in one place", c, p3TokenCaller()))
		}
	}
	sort.Strings(out)
	return out
}

func TestTheSealedDoHTokenHasOneReader(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range p3SecretProblems(fset, files) {
		t.Error(p)
	}
	// The lint must have seen what it guards: the lookup, the INSERT and the rotation that write the column, and the caller.
	sites, bad := p2Sites(fset, files)
	if bad != "" {
		t.Fatal(bad)
	}
	reader, writers := 0, 0
	readerFn, readerNorm := p3TokenReader()
	for _, s := range sites {
		switch {
		case s.fn == readerFn && s.norm == readerNorm:
			reader++
		case strings.Contains(s.norm, "doh_token_ct"):
			writers++
		}
	}
	if reader != 1 || writers < 2 {
		t.Errorf("the lint saw %d lookups and %d writers of doh_token_ct, want 1 and at least 2 (create and rotate): it is looking in the wrong place", reader, writers)
	}
	if calls := p3TokenCalls(files); len(calls) != 1 || calls[0] != p3TokenCaller() {
		t.Errorf("EndpointTokenCT is called from %v, want only %s", calls, p3TokenCaller())
	}
}

// TestP3SecretLintCanFail plants each shape and requires the verdict.
func TestP3SecretLintCanFail(t *testing.T) {
	const header = "package pkg\nimport \"context\"\ntype DB struct{}\nfunc (DB) Exec(context.Context, string, ...any) {}\nfunc (DB) Query(context.Context, string, ...any) {}\nfunc (DB) QueryRow(context.Context, string, ...any) {}\nvar ctx = context.Background()\nvar db DB\ntype Tx struct{}\nfunc (Tx) EndpointTokenCT(id int) {}\n"
	cases := []struct {
		name string
		src  string
		bad  int
	}{
		{"the lookup", `func EndpointTokenCT() { db.QueryRow(ctx, "SELECT doh_token_ct FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = $2") }`, 0},
		{"the lookup grown a column", `func EndpointTokenCT() { db.QueryRow(ctx, "SELECT doh_token_ct, name FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = $2") }`, 1},
		{"the lookup in another function", `func Show() { db.QueryRow(ctx, "SELECT doh_token_ct FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = $2") }`, 1},
		{"a list that reads it", `func List() { db.Query(ctx, "SELECT id, doh_token_ct FROM ctrlz.endpoints WHERE tenant_id = $1") }`, 1},
		{"a return of it", `func Rotate() { db.QueryRow(ctx, "UPDATE ctrlz.endpoints SET doh_token_ct = $3 WHERE tenant_id = $1 AND id = $2 RETURNING doh_token_ct") }`, 1},
		{"a rotation that writes it", `func Rotate() { db.Exec(ctx, "UPDATE ctrlz.endpoints SET resolver_id = $3, doh_token_ct = $4, doh_token_hash = $5 WHERE tenant_id = $1 AND id = $2") }`, 0},
		{"an insert that writes it", `func Add() { db.Exec(ctx, "INSERT INTO ctrlz.endpoints (tenant_id, id, name, doh_token_ct, doh_token_hash) VALUES ($1, $2, $3, $4, $5)") }`, 0},
		{"a filter on it", `func Find() { db.Query(ctx, "SELECT id FROM ctrlz.endpoints WHERE doh_token_ct = $1") }`, 1},
		{"a star", `func Get() { db.Query(ctx, "SELECT * FROM ctrlz.endpoints WHERE tenant_id = $1") }`, 1},
		{"an alias star", `func Get() { db.Query(ctx, "SELECT e.* FROM ctrlz.endpoints e WHERE e.tenant_id = $1") }`, 1},
		{"RETURNING *", `func Put() { db.QueryRow(ctx, "UPDATE ctrlz.endpoints SET name = $3 WHERE tenant_id = $1 AND id = $2 RETURNING *") }`, 1},
		{"the row as JSON", `func Get() { db.Query(ctx, "SELECT to_jsonb(e) FROM ctrlz.endpoints e WHERE e.tenant_id = $1") }`, 1},
		{"named columns", `func Get() { db.Query(ctx, "SELECT id, name, resolver_id FROM ctrlz.endpoints WHERE tenant_id = $1") }`, 0},
		{"a count", `func Count() { db.Query(ctx, "SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1") }`, 0},
		{"a star on another table in a join", `func Get() { db.Query(ctx, "SELECT c.* FROM ctrlz.clients c JOIN ctrlz.endpoints e ON e.id = c.endpoint_id WHERE e.tenant_id = $1") }`, 0},
		{"a call from the wrong place", `func Show() { Tx{}.EndpointTokenCT(1) }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		path := "internal/store/planted.go"
		af, err := parser.ParseFile(fset, path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := p3SecretProblems(fset, []file{{path: path, ast: af}, filler(t, fset)})
		if len(got) != c.bad {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.bad)
		}
	}
	// The caller is judged by its place: ResolverFor of internal/endpoints/links.go passes, the same body elsewhere does not.
	fset := token.NewFileSet()
	src := header + "func ResolverFor() { Tx{}.EndpointTokenCT(1) }\n"
	for path, bad := range map[string]int{"internal/endpoints/links.go": 0, "internal/endpoints/other.go": 1} {
		af, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if got := p3SecretProblems(fset, []file{{path: path, ast: af}, filler(t, fset)}); len(got) != bad {
			t.Errorf("a call from %s: %v, want %d problems", path, got, bad)
		}
	}
}
