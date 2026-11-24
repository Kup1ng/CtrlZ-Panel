package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
)

// The writers of the worker's judgement (P1 auth review round 17, sms-r17-9; rules caps-and-endings and
// known-unknown-oracle).
//
// sms_gateways.unusable_ct_sum says "no sender can be built from THESE credentials". Two live workers with
// different key rings write and take it back against each other, and since round 16 a worker that wrote the
// judgement and later finds the row clear, with no sender of its own, concludes that a worker whose ring
// opens the credentials took it back, and stops writing for that ciphertext. That inference holds only if
// nothing else clears the column: any other statement that does (a reset action, a stray NULL written with
// new credentials) would leave a judgement the poll would have rewritten within 30 seconds cleared until
// the worker restarts, and the public flag would read "usable" for a gateway that cannot send.
//
// So the writers are a closed list. Every SQL constant of the module that names the column is one of the
// statements below, pinned by its digest, or fails: a new writer is a diff that has to say how it keeps the
// invariant "only a worker that can open the credentials clears the row". The two earlier writers that were
// not needed are gone: the statement that saves new credentials no longer writes NULL there (the judgement
// names the digest of the ciphertext, so new credentials end it with no write, spec 9.8).
//
// Contract. It judges every constant SQL text that reaches a database call in the non-test files, by the
// value go/types computes, and the column as a whole word. It does not judge a migration (the generated
// column blocked_now only reads it) nor the role grants, which are the database area's: ctrlz_admin keeps
// its table-level UPDATE for the rekey, which has to carry the column with the ciphertext.

// unusableStatements are the statements that name unusable_ct_sum, with what each does to it.
var unusableStatements = []struct{ Const, Pkg, Digest, What string }{
	{"qGatewayUnusable", "internal/store", "099036073b0b2826", "the worker writes the judgement against the digest it was made for, only if the row holds another"},
	{"qGatewayUsable", "internal/store", "5f4a8d723334bb8d", "the worker takes back a judgement about these very credentials, a compare-and-set"},
	{"qSMSCredentialsReplace", "internal/store", "45d0f48ad69fc4fb", "a rekey moves the digest with the ciphertext, only where the column named the old one"},
	{"qWorkerGateways", "internal/store", "c13f2ed43a96f200", "the worker reads it"},
}

var unusableWord = regexp.MustCompile(`(?i)\bunusable_ct_sum\b`)

func gatewayJudgementProblems(fset *token.FileSet, files []file, list []struct{ Const, Pkg, Digest, What string }) []string {
	return closedStatementProblems(fset, files, list, closedStatements{
		word: unusableWord, list: "unusableStatements", what: "sms_gateways.unusable_ct_sum, the worker's judgement",
		why:       "because the yield of a worker that wrote it reads \"cleared\" as \"a worker whose key ring opens the credentials took it back\" (sms-r17-9)",
		invariant: "that only a worker that can open the credentials clears the row",
	})
}

// closedStatements says what a closed list of SQL statements guards: the column word that selects them,
// the name of the list, and the words of the findings.
type closedStatements struct {
	word                       *regexp.Regexp
	list, what, why, invariant string
}

// closedStatementProblems judges every constant SQL text of the non-test files that names a column (by
// the value go/types computes) against a closed list pinned by digest.
func closedStatementProblems(fset *token.FileSet, files []file, list []struct{ Const, Pkg, Digest, What string }, c closedStatements) []string {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	allowed := map[string]string{}
	for _, s := range list {
		allowed[s.Pkg+"."+s.Const] = s.Digest
	}
	used := map[string]bool{}
	var out []string
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
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
				return true
			}
			text := constant.StringVal(tv.Value)
			if !c.word.MatchString(text) {
				return true
			}
			key := constKey(info, call.Args[idx])
			want, listed := allowed[key]
			switch {
			case key == "" || !listed:
				out = append(out, fmt.Sprintf("%s:%d: SQL (%s) names %s; the statements that may are a closed list (%s), %s", f.path, fset.Position(call.Pos()).Line, orLiteral(constName(info, call.Args[idx])), c.what, c.list, c.why))
			case want != caps.Digest(text):
				out = append(out, fmt.Sprintf("%s:%d: %s names %s and is not the text that was reviewed; read it again against the invariant %s, and set its digest to %s", f.path, fset.Position(call.Pos()).Line, constName(info, call.Args[idx]), c.what, c.invariant, caps.Digest(text)))
			default:
				used[key] = true
			}
			return true
		})
	}
	for _, s := range list {
		if !used[s.Pkg+"."+s.Const] {
			out = append(out, fmt.Sprintf("%s lists %s of %s, which no SQL constant of the module is, or whose digest is wrong: remove the entry", c.list, s.Const, s.Pkg))
		}
	}
	sort.Strings(out)
	return out
}

func TestOnlyTheListedStatementsWriteTheGatewayJudgement(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range gatewayJudgementProblems(fset, files, unusableStatements) {
		t.Error(p)
	}
}

func TestGatewayJudgementLintCanFail(t *testing.T) {
	const header = "package pkg\nimport \"context\"\ntype DB struct{}\nfunc (DB) Exec(context.Context, string, ...any) {}\nvar ctx = context.Background()\nvar db DB\n"
	const listedText = "UPDATE ctrlz.sms_gateways SET unusable_ct_sum = $2 WHERE id = $1"
	list := []struct{ Const, Pkg, Digest, What string }{{"qListed", "internal/store", caps.Digest(listedText), "planted"}}
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"the listed statement", "internal/store/x.go", `const qListed = "` + listedText + `"; func f() { db.Exec(ctx, qListed) }`, 0},
		{"the listed statement re-indented", "internal/store/x.go", `const qListed = "UPDATE ctrlz.sms_gateways   SET unusable_ct_sum = $2\n WHERE id = $1"; func f() { db.Exec(ctx, qListed) }`, 0},
		{"a reset statement nobody listed", "internal/store/x.go", `const qReset = "UPDATE ctrlz.sms_gateways SET unusable_ct_sum = NULL WHERE id = $1"; func f() { db.Exec(ctx, qReset) }`, 2},
		{"a text written at the call", "internal/store/x.go", `func f() { db.Exec(ctx, "UPDATE ctrlz.sms_gateways SET unusable_ct_sum = NULL") }`, 2},
		{"a listed constant edited to clear", "internal/store/x.go", `const qListed = "UPDATE ctrlz.sms_gateways SET unusable_ct_sum = NULL WHERE id = $1"; func f() { db.Exec(ctx, qListed) }`, 2},
		{"the same name in another package", "internal/admin/x.go", `const qListed = "` + listedText + `"; func f() { db.Exec(ctx, qListed) }`, 2},
		{"a statement that never names the column", "internal/store/x.go", `const qOther = "UPDATE ctrlz.sms_gateways SET hint = $2 WHERE id = $1"; func f() { db.Exec(ctx, qOther) }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := gatewayJudgementProblems(fset, []file{{path: c.path, ast: af}, filler(t, fset)}, list)
		// The want counts the "remove the entry" line a case that does not use the listed statement adds.
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
