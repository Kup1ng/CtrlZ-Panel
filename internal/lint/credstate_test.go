package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The one-time-state rule (P1 auth review, round 5, topic 13; spec 4.4, 4.5, 10.1,
// 10.3, 10.7).
//
// What a user or an admin may do with a password depends on one question: is it a
// one-time password that is still good, one that has expired, a password the admin
// chose before a second factor exists, or an account that is ready. Rounds 1 to 3 found
// that question answered by separate boolean expressions over must_reset,
// must_change_password, password_expires_at, totp_enabled_at and the session's
// auth_method, each route with its own, and written by separate UPDATEs that each set or
// cleared a few of the fields. Now:
//
//   - The answer is ctrlz.credential_state (migration 0024), one SQL function on the
//     database clock that returns a closed set of four words. internal/auth/credstate is
//     the Go side of those words and the one table of what each may do.
//   - Go never reads the three columns. This file fails for a Go field, a selector or a
//     SQL constant that does.
//   - Nothing in Go writes them either: every transition is a definer function that
//     checks the edge (functions.yaml), which a SQL constant naming the columns would
//     bypass, so the same SQL scan refuses a statement that does.
//
// internal/auth/credstate (TestEveryOperationHasARow) and internal/store
// (TestCredentialStateEdges) are the behaviour half: every operation of both OpenAPI
// documents and of ctrlz-admin against every state, and every transition against every
// state, compared with the table.

// oneTimeFields are the Go names of the three columns. A field of this name outside the
// packages below is a second copy of the state.
var oneTimeFields = map[string]bool{"MustReset": true, "MustChangePassword": true, "PasswordExpiresAt": true}

// oneTimeColumnRE finds the columns in SQL text.
var oneTimeColumnRE = regexp.MustCompile(`(?i)\b(must_reset|must_change_password|password_expires_at)\b`)

// The only shapes in which a Go statement may name the columns: the arguments of the one
// state function, in the order and with the meaning it documents, and the one display
// helper (the admin's Users list shows when a one-time password ends). Anything else is
// a read or a write of the state by hand.
var oneTimeAllowedRE = []*regexp.Regexp{
	// users: (must_reset, password_expires_at, false)
	regexp.MustCompile(`(?is)credential_state\(\s*(?:\w+\.)?must_reset\s*,\s*(?:\w+\.)?password_expires_at\s*,\s*false\s*\)`),
	// admin_users: (must_change_password, password_expires_at, totp_enabled_at IS NULL)
	regexp.MustCompile(`(?is)credential_state\(\s*(?:\w+\.)?must_change_password\s*,\s*(?:\w+\.)?password_expires_at\s*,\s*(?:\w+\.)?totp_enabled_at\s+IS\s+NULL\s*\)`),
	// the display helper, for users
	regexp.MustCompile(`(?is)one_time_expiry\(\s*(?:\w+\.)?must_reset\s*,\s*(?:\w+\.)?password_expires_at\s*\)`),
}

// credstateFieldExempt are the files that may declare or read the fields: the generated
// response types (the frontend's contract names must_reset and must_change_password, and
// the routes only fill them in) and the package that owns the state.
func credstateFieldExempt(path string) bool {
	return strings.HasPrefix(path, "internal/auth/credstate/") ||
		strings.Contains(path, "/gen/") || strings.HasPrefix(path, "shared/")
}

// credstateProblems reports the Go fields, the selectors and the SQL constants that
// carry the one-time state by hand.
func credstateProblems(fset *token.FileSet, files []file) []string {
	var out []string
	add := func(f file, pos token.Pos, format string, args ...any) {
		out = append(out, fmt.Sprintf("%s:%d: %s", f.path, fset.Position(pos).Line, fmt.Sprintf(format, args...)))
	}
	for _, f := range files {
		if f.test || credstateFieldExempt(f.path) {
			continue
		}
		// Writes are the left-hand sides of an assignment: filling a response type is not
		// a read. Everything else that names the field is.
		lhs := map[ast.Node]bool{}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if x.Tok == token.ASSIGN || x.Tok == token.DEFINE {
					for _, l := range x.Lhs {
						lhs[l] = true
					}
				}
			case *ast.StructType:
				for _, fl := range x.Fields.List {
					for _, name := range fl.Names {
						if oneTimeFields[name.Name] {
							add(f, name.Pos(), "field %s declared here: the one-time state is read through internal/auth/credstate, not stored in a second field", name.Name)
						}
					}
				}
			case *ast.SelectorExpr:
				if oneTimeFields[x.Sel.Name] && !lhs[x] {
					add(f, x.Pos(), "%s read here: ask internal/auth/credstate (the State of the row), never the column", x.Sel.Name)
				}
			}
			return true
		})
	}
	// SQL constants: the columns appear only inside the allowed shapes.
	info, ok := typeInfo(fset, files)
	if !ok {
		return append(out, "type information unavailable")
	}
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
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
			text := stripSQLComments(constant.StringVal(tv.Value))
			for _, re := range oneTimeAllowedRE {
				text = re.ReplaceAllString(text, " ")
			}
			if m := oneTimeColumnRE.FindString(text); m != "" {
				add(f, call.Pos(), "SQL names %s outside ctrlz.credential_state(...): read the state through the function and change it through a definer function of ctrlz_fn", strings.ToLower(m))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// catalogReturnProblems reports a definer function whose result row carries one of the
// columns: a function that hands the raw column to Go is a read by another road.
func catalogReturnProblems(functionsYAML []byte) ([]string, error) {
	var doc struct {
		Definer []struct {
			Name    string `yaml:"name"`
			Returns string `yaml:"returns"`
		} `yaml:"security_definer"`
	}
	if err := yaml.Unmarshal(functionsYAML, &doc); err != nil {
		return nil, err
	}
	if len(doc.Definer) < 20 {
		return nil, fmt.Errorf("functions.yaml lists %d definer functions; the section is missing", len(doc.Definer))
	}
	var out []string
	for _, fn := range doc.Definer {
		if m := oneTimeColumnRE.FindString(fn.Returns); m != "" {
			out = append(out, fmt.Sprintf("functions.yaml: %s returns %s; return ctrlz.credential_state instead", fn.Name, strings.ToLower(m)))
		}
	}
	return out, nil
}

func TestOneTimeStateRule(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range credstateProblems(fset, files) {
		t.Error(p)
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "migrations", "catalog", "functions.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	probs, err := catalogReturnProblems(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probs {
		t.Error(p)
	}
}

// TestOneTimeStateRuleCanFail plants each shape the rule exists for and expects it to be
// reported, and the shapes it must allow to pass. A lint that cannot fail proves nothing.
func TestOneTimeStateRuleCanFail(t *testing.T) {
	const header = "package p\n"
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"a stored boolean", "internal/store/x.go", "type U struct { MustReset bool }", 1},
		{"a stored admin boolean", "internal/store/x.go", "type U struct { MustChangePassword bool }", 1},
		{"a stored expiry", "internal/adminapi/x.go", "type U struct { PasswordExpiresAt *int }", 1},
		{"a read in a condition", "internal/auth/login/x.go", "func f(l struct{ MustReset bool }) bool { return l.MustReset }", 2},
		{"a read through a pointer", "internal/api/x.go", "func f(u *struct{ PasswordExpiresAt *int }) bool { return u.PasswordExpiresAt != nil }", 2},
		{"a comparison", "internal/adminapi/x.go", "func f(u struct{ MustChangePassword bool }) bool { return !u.MustChangePassword }", 2},
		{"filling a response is a write", "internal/api/x.go", "type R struct{}\nfunc f(r *struct{ MustReset bool }) { r.MustReset = true }", 1},
		{"the state package may name them", "internal/auth/credstate/x.go", "type S struct { MustReset bool }\nfunc f(s S) bool { return s.MustReset }", 0},
		{"a generated type may name them", "internal/api/gen/x.go", "type S struct { MustReset bool }\nfunc f(s S) bool { return s.MustReset }", 0},
		{"a SQL select of the column", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT must_reset FROM ctrlz.users WHERE id = $1`) }", 1},
		{"a SQL select of the expiry", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT password_expires_at FROM ctrlz.users WHERE id = $1`) }", 1},
		{"a SQL comparison of the expiry", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT 1 FROM ctrlz.users WHERE must_reset AND password_expires_at > now()`) }", 1},
		{"a SQL write that clears them", "internal/store/x.go", "func f() { db.Exec(ctx, `UPDATE ctrlz.users SET must_reset = false, password_expires_at = NULL WHERE id = $1`) }", 1},
		{"a SQL write of the admin flag", "internal/store/x.go", "func f() { db.Exec(ctx, `UPDATE ctrlz.admin_users SET must_change_password = false WHERE id = $1`) }", 1},
		{"an insert", "internal/store/x.go", "func f() { db.Exec(ctx, `INSERT INTO ctrlz.admin_users (username, must_change_password) VALUES ($1, true)`) }", 1},
		{"a quoted-in-a-comment mention is not a read", "internal/store/x.go", "func f() { db.Exec(ctx, `SELECT 1 /* must_reset */ FROM ctrlz.users`) }", 0},
		{"the state function for users", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT ctrlz.credential_state(u.must_reset, u.password_expires_at, false) FROM ctrlz.users u`) }", 0},
		{"the state function for admins", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT ctrlz.credential_state(must_change_password, password_expires_at, totp_enabled_at IS NULL) FROM ctrlz.admin_users`) }", 0},
		{"the state function with the wrong arguments", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT ctrlz.credential_state(must_reset, password_expires_at, true) FROM ctrlz.users`) }", 1},
		{"the state function with the arguments swapped", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT ctrlz.credential_state(password_expires_at, must_reset, false) FROM ctrlz.users`) }", 1},
		{"the state function next to a raw read", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT ctrlz.credential_state(must_reset, password_expires_at, false), must_reset FROM ctrlz.users`) }", 1},
		{"the display helper", "internal/store/x.go", "func f() { db.QueryRow(ctx, `SELECT ctrlz.one_time_expiry(u.must_reset, u.password_expires_at) FROM ctrlz.users u`) }", 0},
		{"a constant joined from two parts", "internal/store/x.go", "const a = `SELECT must_reset `\nconst q = a + `FROM ctrlz.users`\nfunc f() { db.QueryRow(ctx, q) }", 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := credstateProblems(fset, []file{{path: c.path, ast: af}, filler(t, fset)})
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}

	// The catalog half.
	good := "security_definer:\n"
	for i := 0; i < 20; i++ {
		good += fmt.Sprintf("  - {name: f%d, returns: \"TABLE(a uuid)\"}\n", i)
	}
	for _, c := range []struct {
		name, extra string
		want        int
	}{
		{"clean", "", 0},
		{"a function that returns must_reset", "  - {name: leak, returns: \"TABLE(must_reset boolean)\"}\n", 1},
		{"a function that returns the expiry", "  - {name: leak, returns: \"TABLE(a uuid, password_expires_at timestamp with time zone)\"}\n", 1},
		{"a function that returns the admin flag", "  - {name: leak, returns: \"TABLE(must_change_password boolean)\"}\n", 1},
	} {
		got, err := catalogReturnProblems([]byte(good + c.extra))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
