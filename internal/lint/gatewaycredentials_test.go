package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
)

// The statements that touch the credentials of a gateway (P1 auth review round 18, admin-r18-1, rule
// unconfirmed-credentials-carry-nothing; D64 sms-gateway-takeover).
//
// sms_gateways.credentials_ct is what every sender, the routing, the breaker and the judgement of the
// worker read: whoever writes it decides which provider account receives the login, reset and
// phone-change code of every tenant. A PUT of the admin API therefore writes credentials_pending_ct,
// and only the console (`ctrlz-admin sms confirm`) copies it over the active column. The writers are a
// closed list pinned by digest, and every other statement that names either column is on it as a reader
// with a reason, so a new statement is a diff that has to say which of the two it is: a new writer of
// credentials_ct that is not confirm or a rekey fails here, and so does a second place that copies the
// pending pair.
//
// Contract. It judges every constant SQL text that reaches a database call in the non-test files, by the
// value go/types computes, and the two column names as whole words. It does not judge a migration, the
// role grants (the database area's: the admin role holds table-level UPDATE for the rekey), or SQL that is
// built at run time (a statement that is not a constant is refused by the SQL lints of rule 7).
// TestOnlyTheConsoleActivatesGatewayCredentials is the second half: the method that activates is
// referenced from the console package alone.

var credentialStatements = []struct{ Const, Pkg, Digest, What string }{
	{"qSMSGatewayStageCredentials", "internal/store", "e4f810183dc46068", "WRITES credentials_pending_ct only: what a PUT saves carries nothing"},
	{"qSMSGatewayConfirm", "internal/store", "4d19ba3b16870902", "WRITES credentials_ct from the pending pair: the one activation, called from the console only"},
	{"qSMSCredentialsReplace", "internal/store", "45d0f48ad69fc4fb", "WRITES credentials_ct with the re-seal of the same plaintext, compare-first (rekey)"},
	{"qSMSPendingCredentialsReplace", "internal/store", "31372e497a9c24fe", "WRITES credentials_pending_ct with the re-seal of the same plaintext, compare-first (rekey)"},
	{"qSMSCredentialsSealed", "internal/store", "16462972de9a1d61", "reads both sealed columns for rekey, keys status and declare-lost"},
	{"qSMSGatewayByProvider", "internal/store", "2591913c0ed5958e", "reads whether active credentials exist"},
	{"qSMSGateways", "internal/store", "c2a28d3a9626afa3", "reads whether active and pending credentials exist, for the page"},
	{"qSMSPendingGateways", "internal/store", "a4a50e733f239afc", "reads which providers wait for a confirmation, for the console"},
	{"qSMSRoutingAssign", "internal/store", "32bc927d2d66ed5b", "gives a role only to a gateway with ACTIVE credentials: the routing cannot reach an unconfirmed gateway"},
	{"qWorkerGateways", "internal/store", "c13f2ed43a96f200", "the worker reads the active credentials to send"},
	{"qGatewayHold", "internal/store", "2391ba82e9ef37fd", "the worker holds a gateway for the credentials it used"},
	{"qGatewayUnusable", "internal/store", "099036073b0b2826", "the worker's judgement, keyed on the active ciphertext"},
}

var credentialWord = regexp.MustCompile(`(?i)\bcredentials(_pending)?_ct\b`)

func gatewayCredentialProblems(fset *token.FileSet, files []file, list []struct{ Const, Pkg, Digest, What string }) []string {
	return closedStatementProblems(fset, files, list, closedStatements{
		word: credentialWord, list: "credentialStatements", what: "sms_gateways.credentials_ct or credentials_pending_ct",
		why:       "because the active column decides whose provider account receives every tenant's login code and only the console may change it (admin-r18-1)",
		invariant: "that nothing but the console's confirmation and a re-seal writes credentials_ct, and a PUT writes credentials_pending_ct only",
	})
}

func TestOnlyTheListedStatementsTouchGatewayCredentials(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range gatewayCredentialProblems(fset, files, credentialStatements) {
		t.Error(p)
	}
}

func TestGatewayCredentialsLintCanFail(t *testing.T) {
	const header = "package pkg\nimport \"context\"\ntype DB struct{}\nfunc (DB) Exec(context.Context, string, ...any) {}\nvar ctx = context.Background()\nvar db DB\n"
	const listedText = "UPDATE ctrlz.sms_gateways SET credentials_pending_ct = $2 WHERE id = $1"
	list := []struct{ Const, Pkg, Digest, What string }{{"qListed", "internal/store", caps.Digest(listedText), "planted"}}
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"the listed statement", "internal/store/x.go", `const qListed = "` + listedText + `"; func f() { db.Exec(ctx, qListed) }`, 0},
		{"a PUT that writes the active column", "internal/store/x.go", `const qPut = "UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1"; func f() { db.Exec(ctx, qPut) }`, 2},
		{"a text written at the call", "internal/store/x.go", `func f() { db.Exec(ctx, "UPDATE ctrlz.sms_gateways SET credentials_ct = credentials_pending_ct") }`, 2},
		{"a second copy of the pending pair", "internal/admin/y.go", `const qCopy = "UPDATE ctrlz.sms_gateways SET credentials_ct = credentials_pending_ct"; func f() { db.Exec(ctx, qCopy) }`, 2},
		{"the listed statement edited to write the active column", "internal/store/x.go", `const qListed = "UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1"; func f() { db.Exec(ctx, qListed) }`, 2},
		{"a statement that never names a credential column", "internal/store/x.go", `const qOther = "UPDATE ctrlz.sms_gateways SET hint = $2 WHERE id = $1"; func f() { db.Exec(ctx, qOther) }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := gatewayCredentialProblems(fset, []file{{path: c.path, ast: af}, filler(t, fset)}, list)
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

// consoleStatements are the constants of internal/store, on credentialStatements, whose statements only the
// console may run: the activation, the re-seal of the active column, and the read that is the compare-first
// input of that re-seal. The console package is the one directory that may call anything that runs one of them
// (D12; admin-r18-1, admin-r18-16): a route of the admin API that ran either would put the takeover back with
// two lines. They are keyed by the STATEMENT and not by a method name, because a name is what a later edit
// changes (a second method that runs the same constant under another name, a wrapper, an interface).
var consoleStatements = map[string]string{
	"qSMSGatewayConfirm":     "the activation",
	"qSMSCredentialsReplace": "the re-seal of the active column",
	"qSMSCredentialsSealed":  "the compare-first input of that re-seal",
}

const consoleDir = "internal/admincli"

// consoleFuncs derives, from go/types, the set of functions of internal/store that run a console-only
// statement: a function whose body (closures included) uses a tracked constant or variable. A constant or a
// package-level variable whose declaration uses a tracked one is tracked too, to a fixed point, so
// `const q2 = qSMSGatewayConfirm + " RETURNING id"` and `var run = func(...) { ...q2... }` run it as well.
// It returns the functions by object and the names of them, which the definitions of other kinds (an interface
// method of that name) are judged by.
func consoleFuncs(info *types.Info, files []file) (map[*types.Func]bool, map[string]bool) {
	isStore := func(o types.Object) bool {
		return o != nil && o.Pkg() != nil && o.Pkg().Path() == module+"/internal/store"
	}
	tracked := map[types.Object]bool{}
	valueSpecs := func(visit func(*ast.ValueSpec)) {
		for _, f := range files {
			if f.test {
				continue
			}
			for _, d := range f.ast.Decls {
				if gd, ok := d.(*ast.GenDecl); ok && (gd.Tok == token.CONST || gd.Tok == token.VAR) {
					for _, sp := range gd.Specs {
						visit(sp.(*ast.ValueSpec))
					}
				}
			}
		}
	}
	valueSpecs(func(vs *ast.ValueSpec) {
		for _, id := range vs.Names {
			if _, ok := consoleStatements[id.Name]; ok && isStore(info.Defs[id]) {
				tracked[info.Defs[id]] = true
			}
		}
	})
	uses := func(n ast.Node) bool {
		hit := false
		ast.Inspect(n, func(x ast.Node) bool {
			if id, ok := x.(*ast.Ident); ok && tracked[info.Uses[id]] {
				hit = true
			}
			return !hit
		})
		return hit
	}
	for changed := true; changed; {
		changed = false
		valueSpecs(func(vs *ast.ValueSpec) {
			if !uses(vs) {
				return
			}
			for _, id := range vs.Names {
				if o := info.Defs[id]; isStore(o) && !tracked[o] {
					tracked[o], changed = true, true
				}
			}
		})
	}
	fns, names := map[*types.Func]bool{}, map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || !uses(fd.Body) {
				continue
			}
			if fn, ok := info.Defs[fd.Name].(*types.Func); ok && isStore(fn) {
				fns[fn], names[fn.Name()] = true, true
			}
		}
	}
	return fns, names
}

// consoleOnlyProblems judges every identifier that go/types resolves to a function of the store that runs a
// console-only statement (consoleFuncs), whether it is called, taken as a method value or expression, promoted
// through an embedded field or passed on: it must be in consoleDir. That includes a call from another function
// of the store, so a wrapper that a route could call is itself the problem. A method of the same name declared
// anywhere but by the one FuncDecl of the store (an interface, a type of a route package) fails, since it would
// let a caller reach the function without naming it. Test files are outside the contract (typeInfo does not
// check them).
func consoleOnlyProblems(fset *token.FileSet, files []file) []string {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	fns, names := consoleFuncs(info, files)
	var out []string
	for _, f := range files {
		if f.test {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(f.path))
		ast.Inspect(f.ast, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if fn, ok := info.Uses[id].(*types.Func); ok && fns[fn.Origin()] && dir != consoleDir {
				out = append(out, fmt.Sprintf("%s:%d: %s runs a statement only the console may run (rule unconfirmed-credentials-carry-nothing): only %s may use it", f.path, fset.Position(id.Pos()).Line, fn.Name(), consoleDir))
			}
			if fn, ok := info.Defs[id].(*types.Func); ok && names[fn.Name()] && !fns[fn.Origin()] {
				out = append(out, fmt.Sprintf("%s:%d: %s declares a method of the name of a console-only function of the store, which would let a caller reach it without naming it", f.path, fset.Position(id.Pos()).Line, fn.Name()))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func TestOnlyTheConsoleRunsTheActivatingStatements(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range consoleOnlyProblems(fset, files) {
		t.Error(p)
	}
	// The derivation finds what it is meant to find: each statement is a constant of the store that is on the
	// digest list, and the functions it yields include the three that exist today (a rename or a moved
	// statement would otherwise leave the guard judging nothing).
	info, _ := typeInfo(fset, files)
	_, names := consoleFuncs(info, files)
	for _, want := range []string{"SMSGatewayConfirmCredentials", "SMSCredentialsReplace", "SMSCredentialsSealed"} {
		if !names[want] {
			t.Errorf("consoleFuncs does not find %s: the constants of consoleStatements no longer reach it", want)
		}
	}
	listed := map[string]bool{}
	for _, c := range credentialStatements {
		listed[c.Const] = true
	}
	defined := map[string]bool{}
	for id, obj := range info.Defs {
		if c, ok := obj.(*types.Const); ok && c.Pkg() != nil && c.Pkg().Path() == module+"/internal/store" && id.Name == c.Name() {
			defined[c.Name()] = true
		}
	}
	for name := range consoleStatements {
		if !listed[name] || !defined[name] {
			t.Errorf("consoleStatements lists %s, which is not a constant of the store on credentialStatements", name)
		}
	}
}

func TestConsoleOnlyLintCanFail(t *testing.T) {
	const store = `package store
import "context"
type tx struct{}
func (tx) Exec(context.Context, string, ...any) {}
type GlobalTx struct{ tx tx }
const qSMSGatewayConfirm = "UPDATE x"
const qDerived = qSMSGatewayConfirm + " RETURNING id"
var runner = func(g GlobalTx) { g.tx.Exec(nil, qDerived) }
func (g GlobalTx) SMSGatewayConfirmCredentials(string) bool { g.tx.Exec(nil, qSMSGatewayConfirm); return true }
func (g GlobalTx) SMSActivateOtherName(string) bool { g.tx.Exec(nil, qSMSGatewayConfirm); return true }
func (g GlobalTx) SMSViaDerived(string) bool { g.tx.Exec(nil, qDerived); return true }
func (g GlobalTx) SMSViaVar(string) bool { runner(g); return true }
func (g GlobalTx) Harmless(string) bool { return true }
func (g GlobalTx) PutSMS(string) bool { return g.SMSActivateOtherName("x") }
`
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"the console calls it", "internal/admincli/c.go", `func f(g store.GlobalTx) { g.SMSGatewayConfirmCredentials("x") }`, 0},
		{"a route calls a method that is not console-only", "internal/adminapi/r.go", `func f(g store.GlobalTx) { g.Harmless("x") }`, 0},
		{"a route calls it", "internal/adminapi/r.go", `func f(g store.GlobalTx) { g.SMSGatewayConfirmCredentials("x") }`, 1},
		{"a route calls a second method that runs the same constant", "internal/adminapi/r.go", `func f(g store.GlobalTx) { g.SMSActivateOtherName("x") }`, 1},
		{"a route calls a method that runs a constant derived from it", "internal/adminapi/r.go", `func f(g store.GlobalTx) { g.SMSViaDerived("x") }`, 1},
		{"a route calls a method that reaches it through a package variable", "internal/adminapi/r.go", `func f(g store.GlobalTx) { g.SMSViaVar("x") }`, 1},
		{"a route takes a method value", "internal/adminapi/r.go", `func f(g store.GlobalTx) { h := g.SMSActivateOtherName; h("x") }`, 1},
		{"a route takes a method expression", "internal/adminapi/r.go", `func f(g store.GlobalTx) { h := store.GlobalTx.SMSGatewayConfirmCredentials; h(g, "x") }`, 1},
		{"a route reaches it through an alias type", "internal/adminapi/r.go", `type tx = store.GlobalTx; func f(g tx) { g.SMSGatewayConfirmCredentials("x") }`, 1},
		{"a route reaches it through an embedded type", "internal/adminapi/r.go", `type w struct{ store.GlobalTx }; func f(g w) { g.SMSGatewayConfirmCredentials("x") }`, 1},
		{"a route declares an interface with the name", "internal/adminapi/r.go", `type confirmer interface{ SMSGatewayConfirmCredentials(string) bool }; func f(c confirmer) { c.SMSGatewayConfirmCredentials("x") }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		sf, err := parser.ParseFile(fset, "internal/store/s.go", store, 0)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, c.path, "package "+filepath.Base(filepath.Dir(c.path))+"\nimport \""+module+"/internal/store\"\n"+c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := consoleOnlyProblems(fset, []file{{path: "internal/store/s.go", ast: sf}, {path: c.path, ast: af}})
		// The store's own wrapper PutSMS calls a console-only function, so it is reported in every case.
		if len(got) != c.want+1 {
			t.Errorf("%s: %d problems %v, want %d (and the store's wrapper)", c.name, len(got), got, c.want)
		}
	}
}
