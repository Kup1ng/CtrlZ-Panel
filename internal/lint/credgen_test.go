package lint_test

import (
	"fmt"
	"go/ast"
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

// The credential-generation rule (P1 auth review, round 5, topic 5; spec 3.7, 5.5,
// 5.7, 10.2, 16.1, 18.2).
//
// users and admin_users carry one credential_gen counter, moved by a trigger on the
// credential columns of migrations/catalog/guarded.yaml. Every artefact derived from a
// first-factor check carries the (subject, generation) it came from, and one helper
// (internal/credgen, applied under the row lock by store.Tx.UserLockFor and
// store.GlobalTx.AdminUserLockFor) refuses it when either differs. Catalog check 25
// compares the trigger with guarded.yaml, and TestCredentialGen* (internal/api,
// internal/adminapi, internal/store) change each column as the owner and show that a
// login waiting on the lock, an mfa ticket and a device marker issued before are all
// refused. This file is the source-level half:
//
//  1. The device marker is one package. keyring.LabelDevice and LabelAdminDevice, and
//     the cookie constructors session.DeviceCookie and session.AdminDeviceCookie, are
//     named in internal/auth/marker and nowhere else, so there is one implementation
//     of the marker and one place that decides what it is bound to.
//  2. No consumer compares a credential field. A comparison of PasswordChangedAt,
//     PasswordExpiresAt, PasswordHash, TOTPSecretCT, TOTPEnabledAt, MustReset,
//     MustChangePassword, DisabledAt, EnforcePasskey or EnforceLiftAt (the Go names of
//     the columns of credential_gen.*.columns) with another value is how each of the
//     hand-picked lists of rounds 1 to 4 (sameLock, sameCredentials, the rehash guard,
//     the reauth hash lookup, the two markers) missed a field. They are compared with
//     nil (is it set), never with each other; the generation says whether they moved.
//  3. An mfa ticket is made with the generation it was derived from (the composite
//     literal that names Kind: store.TicketMFA names Cred), and a function that reads
//     one back calls UserLockFor.

// credentialGenFile is the part of guarded.yaml this lint reads.
type credentialGenFile struct {
	CredentialGen map[string]struct {
		Columns []string `yaml:"columns"`
	} `yaml:"credential_gen"`
}

// credentialFieldSkip are credential columns whose Go field is an identifier that is
// compared everywhere for ordinary reasons (a username is looked up and matched, a
// phone number is normalised and matched). Their change still moves the generation;
// what the lint cannot do is tell an identity check from a credential comparison.
var credentialFieldSkip = map[string]bool{"phone_e164": true, "username": true}

// initialisms is how snake_case words become the Go names of the store structs.
var initialisms = map[string]string{"totp": "TOTP", "ct": "CT", "id": "ID"}

// goFieldName turns password_expires_at into PasswordExpiresAt and totp_secret_ct
// into TOTPSecretCT.
func goFieldName(column string) string {
	var b strings.Builder
	for _, w := range strings.Split(column, "_") {
		if w == "" {
			continue
		}
		if up, ok := initialisms[w]; ok {
			b.WriteString(up)
			continue
		}
		b.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	return b.String()
}

// credentialFields loads the Go field names of the credential columns.
func credentialFields(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "migrations", "catalog", "guarded.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var g credentialGenFile
	if err := yaml.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, tbl := range g.CredentialGen {
		for _, c := range tbl.Columns {
			if !credentialFieldSkip[c] {
				out[goFieldName(c)] = true
			}
		}
	}
	if len(out) < 6 {
		t.Fatalf("guarded.yaml credential_gen gave %d fields; the section is missing or empty", len(out))
	}
	return out
}

// markerOnly are the names that only the marker package may use.
var markerOnly = map[string]string{
	"keyring.LabelDevice":       "the marker seals under its own label",
	"keyring.LabelAdminDevice":  "the marker seals under its own label",
	"session.DeviceCookie":      "only the marker builds its cookie",
	"session.AdminDeviceCookie": "only the marker builds its cookie",
	"session.DeviceMaxAge":      "the marker owns its life",
	"session.AdminDeviceMaxAge": "the marker owns its life",
}

// markerHomes are the packages that may name them: the marker, and the packages that
// define the names.
func markerHome(path string) bool {
	return strings.HasPrefix(path, "internal/auth/marker/") ||
		strings.HasPrefix(path, "internal/keyring/") ||
		strings.HasPrefix(path, "internal/auth/session/")
}

// comparePackages are where a credential field must not be compared.
var comparePackages = []string{"internal/auth/", "internal/api/", "internal/adminapi/", "internal/store/", "internal/admincli/"}

func inComparePackage(path string) bool {
	if strings.HasPrefix(path, "internal/store/catalogtest/") {
		return false
	}
	for _, p := range comparePackages {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// touchesCredential says whether an expression reads one of the credential fields,
// through a selector chain, a pointer, a conversion or a call on it
// (x.PasswordHash.Reveal()).
func touchesCredential(e ast.Expr, fields map[string]bool) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return touchesCredential(x.X, fields)
	case *ast.StarExpr:
		return touchesCredential(x.X, fields)
	case *ast.UnaryExpr:
		return touchesCredential(x.X, fields)
	case *ast.SelectorExpr:
		return fields[x.Sel.Name] || touchesCredential(x.X, fields)
	case *ast.CallExpr:
		if touchesCredential(x.Fun, fields) {
			return true
		}
		for _, a := range x.Args {
			if touchesCredential(a, fields) {
				return true
			}
		}
	case *ast.IndexExpr:
		return touchesCredential(x.X, fields)
	case *ast.SliceExpr:
		return touchesCredential(x.X, fields)
	}
	return false
}

func isLiteral(e ast.Expr) bool {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "nil" || x.Name == "true" || x.Name == "false"
	case *ast.BasicLit:
		return true
	}
	return false
}

// presenceOfCredential is `(x.TOTPEnabledAt != nil)`: a boolean derived from a
// credential field. Compared with another value it is the same hand-picked list as a
// field comparison, only one step removed.
func presenceOfCredential(e ast.Expr, fields map[string]bool) bool {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	b, ok := e.(*ast.BinaryExpr)
	if !ok || (b.Op != token.EQL && b.Op != token.NEQ) {
		return false
	}
	if id, ok := b.Y.(*ast.Ident); ok && id.Name == "nil" {
		return touchesCredential(b.X, fields)
	}
	if id, ok := b.X.(*ast.Ident); ok && id.Name == "nil" {
		return touchesCredential(b.Y, fields)
	}
	return false
}

// equalityCallees are the functions whose arguments are compared as values.
var equalityCallees = map[string]bool{
	"bytes.Equal": true, "subtle.ConstantTimeCompare": true, "reflect.DeepEqual": true,
	"slices.Equal": true, "bytes.Compare": true, "strings.EqualFold": true,
}

func qualifiedName(fun ast.Expr) string {
	if sel, ok := fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return id.Name + "." + sel.Sel.Name
		}
	}
	return ""
}

var sameHelper = regexp.MustCompile(`^(same|Same)[A-Z]`)

// credentialProblems judges every non-test file of the compared packages, the marker
// names, and the mfa ticket.
func credentialProblems(fset *token.FileSet, files []file, fields map[string]bool) []string {
	var out []string
	add := func(pos token.Pos, path, msg string) {
		out = append(out, fmt.Sprintf("%s:%d: %s", path, fset.Position(pos).Line, msg))
	}
	for _, f := range files {
		if f.test {
			continue
		}
		// 1. the marker names.
		if !markerHome(f.path) && !strings.HasPrefix(f.path, "internal/lint/") {
			ast.Inspect(f.ast, func(n ast.Node) bool {
				if q := qualifiedName0(n); q != "" {
					if why, bad := markerOnly[q]; bad {
						add(n.Pos(), f.path, q+" is named outside internal/auth/marker: "+why)
					}
				}
				return true
			})
		}
		// 2. comparisons of credential fields.
		if inComparePackage(f.path) && !strings.HasPrefix(f.path, "internal/credgen/") {
			ast.Inspect(f.ast, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BinaryExpr:
					if x.Op != token.EQL && x.Op != token.NEQ {
						return true
					}
					lc := touchesCredential(x.X, fields) || presenceOfCredential(x.X, fields)
					rc := touchesCredential(x.Y, fields) || presenceOfCredential(x.Y, fields)
					if (lc && !isLiteral(x.Y)) || (rc && !isLiteral(x.X)) {
						add(x.Pos(), f.path, "a credential field is compared with another value; ask the credential generation (internal/credgen) instead")
					}
				case *ast.CallExpr:
					name := qualifiedName(x.Fun)
					equalish := equalityCallees[name]
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Equal" {
						equalish = equalish || touchesCredential(sel.X, fields)
					}
					if id, ok := x.Fun.(*ast.Ident); ok && sameHelper.MatchString(id.Name) {
						equalish = true
					}
					if equalish {
						for _, a := range x.Args {
							if touchesCredential(a, fields) {
								add(x.Pos(), f.path, "a credential field is passed to an equality helper; ask the credential generation (internal/credgen) instead")
								break
							}
						}
					}
				}
				return true
			})
		}
		// 3. the mfa ticket.
		if strings.HasPrefix(f.path, "internal/api/") || strings.HasPrefix(f.path, "internal/auth/") {
			for _, d := range f.ast.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				issued, spent, locked := false, false, false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CompositeLit:
						kind, hasCred := false, false
						for _, el := range x.Elts {
							kv, ok := el.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							k, _ := kv.Key.(*ast.Ident)
							if k == nil {
								continue
							}
							if k.Name == "Cred" {
								hasCred = true
							}
							if k.Name == "Kind" && isTicketMFA(kv.Value) {
								kind = true
							}
						}
						if kind {
							issued = true
							if !hasCred {
								add(x.Pos(), f.path, "an mfa ticket is made without Cred: it must carry the generation of the first factor it comes from")
							}
						}
					case *ast.CallExpr:
						if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
							switch sel.Sel.Name {
							case "UserLockFor":
								locked = true
							case "Take", "Peek", "TicketTake", "TicketPeek":
								for _, a := range x.Args {
									if isTicketMFA(a) {
										spent = true
									}
								}
							}
						}
					}
					return true
				})
				_ = issued
				if spent && !locked {
					add(fd.Pos(), f.path, fd.Name.Name+" reads an mfa ticket and never calls UserLockFor: the ticket is worth what the credentials were when it was made")
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func isTicketMFA(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "TicketMFA"
}

// qualifiedName0 is pkg.Name for a selector node, or "".
func qualifiedName0(n ast.Node) string {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name + "." + sel.Sel.Name
}

func TestCredentialGenerationRule(t *testing.T) {
	fields := credentialFields(t)
	fset, files := parseRepo(t)
	for _, p := range credentialProblems(fset, files, fields) {
		t.Error(p)
	}
}

// TestCredentialGenerationRuleCanFail plants code that breaks each part of the rule
// and expects the lint to say so. A lint that cannot fail proves nothing.
func TestCredentialGenerationRuleCanFail(t *testing.T) {
	fields := map[string]bool{}
	for _, c := range []string{"password_hash", "password_changed_at", "password_expires_at", "must_reset", "must_change_password", "totp_secret_ct", "totp_enabled_at", "disabled_at"} {
		fields[goFieldName(c)] = true
	}
	for want, got := range map[string]string{
		"PasswordExpiresAt": goFieldName("password_expires_at"), "TOTPSecretCT": goFieldName("totp_secret_ct"),
		"MustChangePassword": goFieldName("must_change_password"),
	} {
		if want != got {
			t.Fatalf("goFieldName gave %s, want %s", got, want)
		}
	}
	const header = "package p\n"
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"sameLock style: a nullable time against another", "internal/auth/login/x.go",
			"func f(l, u T) bool { return l.PasswordChangedAt == u.PasswordChangedAt }", 1},
		{"a flag against a flag", "internal/api/x.go",
			"func f(a, b T) bool { return a.MustChangePassword != b.MustChangePassword }", 1},
		{"hash revealed and compared", "internal/adminapi/x.go",
			"func f(a, b T) bool { return a.PasswordHash.Reveal() == b.PasswordHash.Reveal() }", 1},
		{"bytes.Equal on the seed", "internal/adminapi/x.go",
			"func f(a, b T) bool { return bytes.Equal(a.TOTPSecretCT, b.TOTPSecretCT) }", 1},
		{"a time Equal on an expiry", "internal/store/x.go",
			"func f(a, b *T) bool { return a.PasswordExpiresAt.Equal(*b.PasswordExpiresAt) }", 1},
		{"a same* helper over credential fields", "internal/auth/login/x.go",
			"func f(a, b T) bool { return sameTime(a.PasswordExpiresAt, b.PasswordExpiresAt) }", 1},
		{"presence of a factor against a flag", "internal/adminapi/x.go",
			"func f(a T, enrolled bool) bool { return (a.TOTPEnabledAt != nil) == enrolled }", 1},
		{"is it set is fine", "internal/api/x.go",
			"func f(a T) bool { return a.TOTPEnabledAt != nil && a.DisabledAt == nil && !a.MustReset }", 0},
		{"reading a flag is fine", "internal/api/x.go",
			"func f(a T) T2 { return T2{Restricted: a.MustReset, Hash: a.PasswordHash} }", 0},
		{"the helper itself may compare", "internal/credgen/x.go",
			"func f(a, b T) bool { return a.PasswordChangedAt == b.PasswordChangedAt }", 0},
		{"a comparison in a test is not judged", "internal/api/x_test.go",
			"func f(a, b T) bool { return a.PasswordChangedAt == b.PasswordChangedAt }", 0},
		{"another package is outside this rule", "internal/worker/x.go",
			"func f(a, b T) bool { return a.PasswordChangedAt == b.PasswordChangedAt }", 0},
		{"the generation is the thing to compare", "internal/api/x.go",
			"func f(a, b T) bool { return a.CredentialGen == b.CredentialGen }", 0},
		{"the label outside the marker", "internal/api/x.go",
			"func f() string { return keyring.LabelDevice }", 1},
		{"the admin label outside the marker", "internal/adminapi/x.go",
			"func f() string { return keyring.LabelAdminDevice }", 1},
		{"a cookie constructor outside the marker", "internal/auth/otp/x.go",
			"func f() any { return session.DeviceCookie(\"x\") }", 1},
		{"the label inside the marker", "internal/auth/marker/x.go",
			"func f() string { return keyring.LabelDevice }", 0},
		{"an mfa ticket without the generation", "internal/auth/login/x.go",
			"func f() any { return ticket.Issue{Kind: store.TicketMFA, User: u} }", 1},
		{"an mfa ticket with the generation", "internal/auth/login/x.go",
			"func f() any { return ticket.Issue{Kind: store.TicketMFA, User: u, Cred: c} }", 0},
		{"an mfa ticket read without the lock check", "internal/api/x.go",
			"func f() { s.tickets.Take(ctx, tok, store.TicketMFA) }", 1},
		{"an mfa ticket read with the lock check", "internal/api/x.go",
			"func f() { s.tickets.Peek(ctx, tok, store.TicketMFA); tx.UserLockFor(u, c) }", 0},
		{"a reset ticket is another kind", "internal/api/x.go",
			"func f() { s.tickets.Take(ctx, tok, store.TicketReset) }", 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := credentialProblems(fset, []file{{path: c.path, test: strings.HasSuffix(c.path, "_test.go"), ast: af}}, fields)
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
