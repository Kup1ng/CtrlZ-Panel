package lint_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// Rule one-primitive-per-key, fourth half (review round 12, primitives-r12-3; typed in round 13,
// primitives-r13-2 and -5). The keyring refuses an empty context at run time, but a context that is
// a constant or a bare tenant id binds a ciphertext to nothing the row owns, and the refusal cannot
// tell. A sealed column's context is what keeps a copy of the ciphertext in another tenant's row
// from opening, so this lint reads every non-test use of Seal, Open, SealLabeled and OpenLabeled
// through the type checker (keyringuse_test.go) and asks that the context argument is the result of
// an AAD function that builds a keyring.Context from every parameter, directly or through a
// variable that is assigned nothing else and is never written after. A new sealed column adds its
// own AAD function in its own package, which a reviewer reads, and not a nil, a literal or a
// function that returns a fixed value.

func sealOps() map[string]bool {
	return map[string]bool{"Seal": true, "Open": true, "SealLabeled": true, "OpenLabeled": true}
}

// keyringContextProblems judges the four operations that carry a context.
func keyringContextProblems(w *keyringWorld) []string {
	out := w.shapeProblems(sealOps())
	for _, u := range w.uses {
		idx, ok := contextIndex(u.name)
		if !ok || u.call == nil {
			continue
		}
		if len(u.call.Args) <= idx {
			out = append(out, w.at(u.call)+": "+u.name+" is called with too few arguments to read its context")
			continue
		}
		arg := u.call.Args[idx]
		why := w.aadCall(arg)
		if why != "" {
			if o := w.objOf(arg); o != nil && w.aadVars[o] {
				why = ""
			}
		}
		if why != "" {
			out = append(out, w.at(u.call)+": "+u.name+" takes a context that is not the result of a well-formed AAD function ("+why+"); bind a sealed value to its row with one")
		}
	}
	sort.Strings(out)
	return out
}

func TestEverySealBindsAnAADFunction(t *testing.T) {
	fset, files := parseRepo(t)
	w, ok := newKeyringWorld(fset, files)
	if !ok {
		t.Fatal("type information unavailable")
	}
	if got := keyringContextProblems(w); len(got) > 0 {
		t.Errorf("%d uses seal or open without an AAD function:\n%s", len(got), strings.Join(got, "\n"))
	}
	// The scan found the calls it is about: a lint that read nothing would pass for free.
	seals := 0
	for _, u := range w.uses {
		if _, ok := contextIndex(u.name); ok {
			seals++
		}
	}
	if seals < 8 {
		t.Errorf("the lint saw only %d seal or open calls; the type information is incomplete", seals)
	}
}

// plantedKeyring is the package the planted sources call: the real Ring's seven methods with the real
// signatures reduced to bytes, and the real Domain and Label constants (so a planted call under a
// pair the registry does not list is judged against the registry itself).
func plantedKeyring(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("package keyring\nimport \"github.com/google/uuid\"\ntype Ring struct{}\ntype Context struct{ b []byte }\n")
	b.WriteString("func RowContext(ids []uuid.UUID, parts ...string) Context { return Context{} }\n")
	b.WriteString("func DigestContext(digest []byte, parts ...string) Context { return Context{} }\n")
	b.WriteString("func (r *Ring) Seal(domain string, context Context, plain []byte) ([]byte, error) { return nil, nil }\n")
	b.WriteString("func (r *Ring) Open(domain string, context Context, ct []byte) ([]byte, error) { return nil, nil }\n")
	b.WriteString("func (r *Ring) SealLabeled(domain, label string, context Context, plain []byte) ([]byte, error) { return nil, nil }\n")
	b.WriteString("func (r *Ring) OpenLabeled(domain, label string, context Context, ct []byte) ([]byte, error) { return nil, nil }\n")
	b.WriteString("func (r *Ring) MAC(domain, label string, parts ...[]byte) []byte { return nil }\n")
	b.WriteString("func (r *Ring) VerifyMAC(domain, label string, tag []byte, parts ...[]byte) bool { return false }\n")
	b.WriteString("func (r *Ring) Sign(domain, label string, msg []byte) (uint16, []byte, error) { return 0, nil, nil }\n")
	consts := keyringConstants(t)
	names := make([]string, 0, len(consts))
	for n := range consts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "const %s = %q\n", n, consts[n])
	}
	return b.String()
}

// plantedWorld type-checks one planted source next to the planted keyring.
func plantedWorld(t *testing.T, name, path, src string) *keyringWorld {
	t.Helper()
	fset := token.NewFileSet()
	var files []file
	for p, s := range map[string]string{"internal/keyring/ring.go": plantedKeyring(t), path: src} {
		af, err := parser.ParseFile(fset, p, s, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		files = append(files, file{path: p, test: strings.HasSuffix(p, "_test.go"), ast: af})
	}
	w, ok := newKeyringWorld(fset, files)
	if !ok {
		t.Fatalf("%s: no type information", name)
	}
	return w
}

const plantHeader = "package x\nimport (\n\t\"fmt\"\n\t\"strings\"\n\t\"github.com/google/uuid\"\n\t\"" + keyringPkg + "\"\n)\n"

// plantedAAD are the AAD functions the planted calls use: two right ones, the listed exception, and
// the five shapes the rule refuses.
const plantedAAD = `
func userAAD(id uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{id}) }
func rowAAD(tenant, row uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{tenant, row}) }
func partAAD(id uuid.UUID, kind string) keyring.Context { return keyring.RowContext([]uuid.UUID{id}, kind) }
func constPartAAD(id uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{id}, "cred") }
func otpAAD(phone, purpose string, h []byte) keyring.Context { return keyring.DigestContext(h, phone, purpose) }
func ignoreAAD(id, other uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{id}) }
func blankAAD(id uuid.UUID, _ string) keyring.Context { return keyring.RowContext([]uuid.UUID{id}) }
func literalAAD(id uuid.UUID) keyring.Context { return keyring.Context{} }
func localAAD(id uuid.UUID) keyring.Context { c := keyring.RowContext([]uuid.UUID{id}); return c }
func compareAAD(id uuid.UUID) keyring.Context { if id == uuid.Nil { return keyring.Context{} }; return keyring.RowContext([]uuid.UUID{id}) }
func nilIDAAD(id uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{id, uuid.Nil}) }
func callIDAAD(id uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{uuid.New()}) }
func callPartAAD(id uuid.UUID, p fmt.Stringer) keyring.Context { return keyring.RowContext([]uuid.UUID{id}, p.String()) }
func exprPartAAD(id uuid.UUID, p string) keyring.Context { return keyring.RowContext([]uuid.UUID{id}, p+"x") }
func idPartAAD(id uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{id}, id.String()) }
func noIDAAD(p string) keyring.Context { return keyring.RowContext(nil, p) }
func digestNoPartAAD(h []byte) keyring.Context { return keyring.DigestContext(h) }
func constDigestAAD(p string) keyring.Context { return keyring.DigestContext([]byte("0123456789abcdef"), p) }
func otherCtorAAD(id uuid.UUID) keyring.Context { return build(id) }
func build(id uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{id}) }
func wideAAD(id uuid.UUID) string { return id.String() }
func noParamAAD() keyring.Context { return keyring.RowContext(nil) }
func fixedAAD() keyring.Context { return keyring.RowContext([]uuid.UUID{uuid.New()}, "x") }
func spreadAAD(ids []uuid.UUID) keyring.Context { return keyring.RowContext(ids) }
`

// TestSealContextLintCanFail plants the shapes the rule is about.
func TestSealContextLintCanFail(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"an AAD function", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { k.Seal("d", userAAD(id), nil) }`, 0},
		{"an AAD function of two ids", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID) { k.Open("d", rowAAD(a, b), nil) }`, 0},
		{"a variable assigned an AAD call", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); k.Seal("d", aad, nil) }`, 0},
		{"a variable used inside a func literal", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); _ = func() { k.Seal("d", aad, nil) } }`, 0},
		{"a variable assigned something else too", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); aad = nil; k.Seal("d", aad, nil) }`, 1},
		{"a variable whose address is taken", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); p := &aad; _ = p; k.Seal("d", aad, nil) }`, 1},
		{"a variable declared with no value", "internal/api/x.go", `func f(k *keyring.Ring) { var aad []byte; k.Seal("d", aad, nil) }`, 1},
		{"a shadowing variable is its own", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); { aad := []byte("x"); k.Seal("d", aad, nil) }; _ = aad }`, 1},
		{"an AAD function of the OTP digest", "internal/api/x.go", `func f(k *keyring.Ring, p, q string, h []byte) { k.Open("d", otpAAD(p, q, h), nil) }`, 0},
		{"an AAD function with a part", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID, kind string) { k.Seal("d", partAAD(id, kind), nil) }`, 0},
		{"an AAD function with a constant part", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { k.Seal("d", constPartAAD(id), nil) }`, 0},
		// Round 18 (primitives-r18-13): the bytes are made by the constructors, and the lint reads what
		// is left, that the function builds its context from what it is given.
		{"an AAD function that ignores a parameter", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID) { k.Seal("d", ignoreAAD(a, b), nil) }`, 1},
		{"an AAD function with a blank parameter", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", blankAAD(a, "x"), nil) }`, 1},
		{"an AAD function that returns the zero Context", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", literalAAD(a), nil) }`, 1},
		{"an AAD function that builds in a local", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", localAAD(a), nil) }`, 1},
		{"an AAD function with a branch", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", compareAAD(a), nil) }`, 1},
		{"an AAD function with a fixed id next to its own", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", nilIDAAD(a), nil) }`, 1},
		{"an AAD function whose id is a call", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", callIDAAD(a), nil) }`, 1},
		{"an AAD function whose part is a call", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID, p fmt.Stringer) { k.Seal("d", callPartAAD(a, p), nil) }`, 1},
		{"an AAD function whose part is an expression", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", exprPartAAD(a, "p"), nil) }`, 1},
		{"an AAD function that spells its id as a part", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", idPartAAD(a), nil) }`, 1},
		{"an AAD function with no id", "internal/api/x.go", `func f(k *keyring.Ring) { k.Seal("d", noIDAAD("p"), nil) }`, 1},
		{"an AAD function of a digest and no part", "internal/api/x.go", `func f(k *keyring.Ring, h []byte) { k.Seal("d", digestNoPartAAD(h), nil) }`, 1},
		{"an AAD function of a constant digest", "internal/api/x.go", `func f(k *keyring.Ring) { k.Seal("d", constDigestAAD("p"), nil) }`, 1},
		{"an AAD function that calls another builder", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", otherCtorAAD(a), nil) }`, 1},
		{"an AAD function that returns a string", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", wideAAD(a), nil) }`, 1},
		{"an AAD function with no parameter", "internal/api/x.go", `func f(k *keyring.Ring) { k.Seal("d", noParamAAD(), nil) }`, 1},
		{"an AAD function that spreads its ids", "internal/api/x.go", `func f(k *keyring.Ring, ids []uuid.UUID) { k.Seal("d", spreadAAD(ids), nil) }`, 1},
		{"a variable assigned the zero Context after", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); aad = keyring.Context{}; k.Seal("d", aad, nil) }`, 1},
		{"a variable handed to a helper", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); use(aad); k.Seal("d", aad, nil) }`, 1},
		{"a nil context", "internal/api/x.go", `func f(k *keyring.Ring) { k.Seal("d", nil, nil) }`, 1},
		{"a literal context", "internal/api/x.go", `func f(k *keyring.Ring) { k.Open("d", []byte("x"), nil) }`, 1},
		{"a tenant id as the context", "internal/api/x.go", `func f(k *keyring.Ring, id [16]byte) { k.Seal("d", id[:], nil) }`, 1},
		{"a parameter", "internal/api/x.go", `func f(k *keyring.Ring, ctx []byte) { k.Seal("d", ctx, nil) }`, 1},
		{"a variable from a call that is not AAD", "internal/api/x.go", `func other() []byte { return nil }
func f(k *keyring.Ring) { aad := other(); k.Open("d", aad, nil) }`, 1},
		{"a constant AAD function", "internal/api/x.go", `func f(k *keyring.Ring) { k.Seal("d", fixedAAD(), nil) }`, 1},
		{"an AAD function of a tenant id that is not a uuid", "internal/api/x.go", `func f(k *keyring.Ring, id [16]byte) { k.Seal("d", tenantAAD(id), nil) }`, 1},
		{"an AAD function that ignores a parameter", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID) { k.Seal("d", ignoreAAD(a, b), nil) }`, 1},
		{"an AAD function that returns a string", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { k.Seal("d", []byte(wideAAD(id)), nil) }`, 1},
		{"an AAD function of strings that is not listed", "internal/api/x.go", `func f(k *keyring.Ring, p string) { k.Seal("d", phoneAAD(p), nil) }`, 1},
		{"an AAD function called with the nil uuid", "internal/api/x.go", `func f(k *keyring.Ring) { k.Seal("d", userAAD(uuid.Nil), nil) }`, 1},
		{"an AAD function called with literals only", "internal/api/x.go", `func f(k *keyring.Ring) { k.Seal("d", otpAAD("a", "b"), nil) }`, 1},
		// Round 16 (primitives-r16-7): each argument is judged, whatever the others are. Every one of
		// the first six passed the rule "refuse only when all arguments are fixed".
		{"one fixed uuid next to a real one", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", rowAAD(a, uuid.Nil), nil) }`, 1},
		{"a zero uuid literal next to a real one", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", rowAAD(a, uuid.UUID{}), nil) }`, 1},
		{"a parsed constant next to a real one", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", rowAAD(a, uuid.MustParse("11111111-2222-3333-4444-555555555555")), nil) }`, 1},
		{"a package-level value next to a real one", "internal/api/x.go", `var fixedRow = uuid.New()
func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", rowAAD(a, fixedRow), nil) }`, 1},
		{"a package-level constant array as the id", "internal/api/x.go", `var maxID = uuid.UUID{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
func f(k *keyring.Ring, a uuid.UUID) { k.Open("d", rowAAD(maxID, a), nil) }`, 1},
		{"the same id twice", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", rowAAD(a, a), nil) }`, 1},
		{"the same method result twice", "internal/api/x.go", `type tx struct{}
func (tx) TenantID() uuid.UUID { return uuid.UUID{} }
func f(k *keyring.Ring, v tx) { k.Seal("d", rowAAD(v.TenantID(), v.TenantID()), nil) }`, 1},
		{"a fixed string next to a real one is only a label", "internal/api/x.go", `func f(k *keyring.Ring, p string) { k.Seal("d", otpAAD(p, "login"), nil) }`, 0},
		{"a fixed id converted from a local copy of a constant", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { k.Seal("d", rowAAD(a, uuid.UUID([16]byte{})), nil) }`, 1},
		{"two ids taken from fields of one value", "internal/api/x.go", `type row struct{ Tenant, ID uuid.UUID }
func f(k *keyring.Ring, r row) { k.Seal("d", rowAAD(r.Tenant, r.ID), nil) }`, 0},
		{"two ids from methods of one value", "internal/api/x.go", `type tx struct{ t uuid.UUID }
func (v tx) TenantID() uuid.UUID { return v.t }
func f(k *keyring.Ring, v tx, id uuid.UUID) { k.Seal("d", rowAAD(v.TenantID(), id), nil) }`, 0},
		{"an id read through a pointer", "internal/api/x.go", `func f(k *keyring.Ring, a, b *uuid.UUID) { k.Seal("d", rowAAD(*a, *b), nil) }`, 0},
		{"an id element of a slice of rows", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID, rows []uuid.UUID) { for i := range rows { k.Seal("d", rowAAD(a, rows[i]), nil) } }`, 0},
		{"a closure variable", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID) { g := func() { k.Seal("d", rowAAD(a, b), nil) }; g() }`, 0},
		// Round 16 fix gate (primitives-r16-17): a local or a parameter is judged by what it is given, so
		// a fixed identity put in a variable first, or handed to a wrapper by one of its callers, is as
		// fixed as when written in the call.
		{"a local assigned the nil uuid", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { fixed := uuid.Nil; k.Seal("d", rowAAD(a, fixed), nil) }`, 1},
		{"a local declared with a fixed value", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { var fixed uuid.UUID = uuid.UUID{}; k.Seal("d", rowAAD(a, fixed), nil) }`, 1},
		{"a local that is a real id on one path and a constant on another", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID, c bool) { id := b; if c { id = uuid.Nil }; k.Seal("d", rowAAD(a, id), nil) }`, 1},
		{"a local through a second local", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { x := uuid.MustParse("11111111-2222-3333-4444-555555555555"); y := x; k.Seal("d", rowAAD(a, y), nil) }`, 1},
		{"a range variable over fixed values", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { for _, id := range []uuid.UUID{uuid.Nil} { k.Seal("d", rowAAD(a, id), nil) } }`, 1},
		{"a local filled by a call that takes a row's id", "internal/api/x.go", `func load(a uuid.UUID) (uuid.UUID, error) { return a, nil }
func f(k *keyring.Ring, a uuid.UUID) { id, _ := load(a); k.Seal("d", rowAAD(a, id), nil) }`, 0},
		{"a local filled through a pointer", "internal/api/x.go", `func scan(p *uuid.UUID) {}
func f(k *keyring.Ring, a uuid.UUID) { var id uuid.UUID; scan(&id); k.Seal("d", rowAAD(a, id), nil) }`, 0},
		{"a fresh id made before the insert", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { id, _ := uuid.NewV7(); k.Seal("d", rowAAD(a, id), nil) }`, 0},
		{"a fresh id wrapped in Must", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { id := uuid.Must(uuid.NewV7()); k.Seal("d", rowAAD(a, id), nil) }`, 0},
		{"Must of a parsed constant", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { id := uuid.Must(uuid.Parse("11111111-2222-3333-4444-555555555555")); k.Seal("d", rowAAD(a, id), nil) }`, 1},
		{"a wrapper called with the nil uuid", "internal/api/x.go", `func seal(k *keyring.Ring, a, id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }
func g(k *keyring.Ring, a uuid.UUID) { seal(k, a, uuid.Nil) }`, 1},
		{"a wrapper called with real ids only", "internal/api/x.go", `func seal(k *keyring.Ring, a, id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }
func g(k *keyring.Ring, a, b uuid.UUID) { seal(k, a, b) }`, 0},
		{"a wrapper called with a real id by one caller and a fixed one by another", "internal/api/x.go", `func seal(k *keyring.Ring, a, id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }
func g(k *keyring.Ring, a, b uuid.UUID) { seal(k, a, b) }
func h(k *keyring.Ring, a uuid.UUID) { seal(k, a, uuid.UUID{}) }`, 1},
		{"a wrapper two calls deep", "internal/api/x.go", `func seal(k *keyring.Ring, a, id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }
func mid(k *keyring.Ring, a, id uuid.UUID) { seal(k, a, id) }
func g(k *keyring.Ring, a uuid.UUID) { mid(k, a, uuid.Nil) }`, 1},
		{"a wrapper that calls itself", "internal/api/x.go", `func seal(k *keyring.Ring, a, id uuid.UUID, n int) { if n > 0 { seal(k, a, id, n-1) }; k.Seal("d", rowAAD(a, id), nil) }
func g(k *keyring.Ring, a, b uuid.UUID) { seal(k, a, b, 3) }`, 0},
		{"a wrapper method called through an interface with a fixed id", "internal/api/x.go", `type sealer interface{ Do(k *keyring.Ring, a, id uuid.UUID) }
type impl struct{}
func (impl) Do(k *keyring.Ring, a, id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }
func g(s sealer, k *keyring.Ring, a uuid.UUID) { s.Do(k, a, uuid.Nil) }`, 1},
		{"a wrapper called through a func value with a fixed id", "internal/api/x.go", `func seal(k *keyring.Ring, a, id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }
func g(k *keyring.Ring, a uuid.UUID) { do := seal; do(k, a, uuid.Nil) }`, 1},
		{"a wrapper handed a struct that holds a fixed id", "internal/api/x.go", `type row struct{ Tenant, ID uuid.UUID }
func seal(k *keyring.Ring, r row) { k.Seal("d", rowAAD(r.Tenant, r.ID), nil) }
func g(k *keyring.Ring) { seal(k, row{Tenant: uuid.Nil, ID: uuid.Nil}) }`, 1},
		{"a wrapper handed a struct built from variables", "internal/api/x.go", `type row struct{ Tenant, ID uuid.UUID }
func seal(k *keyring.Ring, r row) { k.Seal("d", rowAAD(r.Tenant, r.ID), nil) }
func g(k *keyring.Ring, a, b uuid.UUID) { seal(k, row{Tenant: a, ID: b}) }`, 0},
		// The two limits the doc comment of argIsRowBound named in round 16 are closed in the fix gate: a
		// copy of an id under another name, and a method of a variable that returns a constant.
		{"a copy of an id under another name", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { t := a; k.Seal("d", rowAAD(t, a), nil) }`, 1},
		{"a copy of a copy", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { t := a; u := t; k.Seal("d", rowAAD(u, a), nil) }`, 1},
		{"a copy of a field", "internal/api/x.go", `type row struct{ Tenant uuid.UUID }
func f(k *keyring.Ring, r row) { t := r.Tenant; k.Seal("d", rowAAD(t, r.Tenant), nil) }`, 1},
		{"two variables of one value read from different rows", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID) { t := a; u := b; k.Seal("d", rowAAD(t, u), nil) }`, 0},
		{"a method of a variable that returns a constant", "internal/api/x.go", `type tx struct{}
func (tx) TenantID() uuid.UUID { return uuid.UUID{} }
func f(k *keyring.Ring, v tx, id uuid.UUID) { k.Seal("d", rowAAD(v.TenantID(), id), nil) }`, 1},
		{"a method that returns the nil uuid on one path", "internal/api/x.go", `type tx struct{ t uuid.UUID; ok bool }
func (v tx) TenantID() uuid.UUID { if !v.ok { return uuid.Nil }; return v.t }
func f(k *keyring.Ring, v tx, id uuid.UUID) { k.Seal("d", rowAAD(v.TenantID(), id), nil) }`, 1},
		{"a function that returns a constant in its first result", "internal/api/x.go", `func fixed() (uuid.UUID, error) { return uuid.Nil, nil }
func f(k *keyring.Ring, a uuid.UUID) { id, _ := fixed(); k.Seal("d", rowAAD(a, id), nil) }`, 1},
		{"a method that returns a field of its receiver", "internal/api/x.go", `type tx struct{ t uuid.UUID }
func (v tx) TenantID() uuid.UUID { return v.t }
func f(k *keyring.Ring, v tx, id uuid.UUID) { k.Seal("d", rowAAD(v.TenantID(), id), nil) }`, 0},
		{"a method that returns another method of a parent", "internal/api/x.go", `type tx struct{ parent *tx; t uuid.UUID }
func (v *tx) TenantID() uuid.UUID { if v.parent != nil { return v.parent.TenantID() }; return v.t }
func f(k *keyring.Ring, v *tx, id uuid.UUID) { k.Seal("d", rowAAD(v.TenantID(), id), nil) }`, 0},
		// Round 17 (primitives-r17-7): ways to reach a seal bound to the zero id that the allow list took
		// as read from a row. The keyring refuses the zero id at run time as well (keyring
		// TestAContextOfTheZeroRowBindsNothingAndIsRefused); these are found before it gets there.
		{"a local declared and never filled", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { var id uuid.UUID; k.Seal("d", rowAAD(a, id), nil) }`, 1},
		{"a zero struct whose field is read", "internal/api/x.go", `type row struct{ Tenant, ID uuid.UUID }
func f(k *keyring.Ring, a uuid.UUID) { var r row; k.Seal("d", rowAAD(a, r.ID), nil) }`, 1},
		{"a local declared and filled by a pointer method", "internal/api/x.go", `type holder struct{ id uuid.UUID }
func (h *holder) fill() {}
func f(k *keyring.Ring, a uuid.UUID) { var h holder; h.fill(); k.Seal("d", rowAAD(a, h.id), nil) }`, 0},
		{"a local declared and then assigned a real id", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID) { var id uuid.UUID; id = b; k.Seal("d", rowAAD(a, id), nil) }`, 0},
		{"a func literal called with the nil uuid", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { apply := func(id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }; apply(uuid.Nil) }`, 1},
		{"a func literal called where it is written", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { func(id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }(uuid.Nil) }`, 1},
		{"a func literal called with real ids", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID) { apply := func(id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }; apply(b) }`, 0},
		{"a func literal called with a real id and with a fixed one", "internal/api/x.go", `func f(k *keyring.Ring, a, b uuid.UUID) { apply := func(id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }; apply(b); apply(uuid.UUID{}) }`, 1},
		// Round 17 fix gate (primitives-r17-11): one plant for each way the flow facts are read, so each
		// clause of buildFlow and varBound has a case that fails without it (and a mutant, mutants.yaml).
		{"a local filled through the address of its field", "internal/api/x.go", `type row struct{ Tenant, ID uuid.UUID }
func scan(p *uuid.UUID) {}
func f(k *keyring.Ring, a uuid.UUID) { var r row; scan(&r.ID); k.Seal("d", rowAAD(a, r.ID), nil) }`, 0},
		{"a local filled through the address of an element", "internal/api/x.go", `func scan(p *uuid.UUID) {}
func f(k *keyring.Ring, a uuid.UUID) { var ids [2]uuid.UUID; scan(&ids[0]); k.Seal("d", rowAAD(a, ids[1]), nil) }`, 0},
		{"the address of another local fills nothing", "internal/api/x.go", `func scan(p *uuid.UUID) {}
func f(k *keyring.Ring, a uuid.UUID) { var id, other uuid.UUID; scan(&other); k.Seal("d", rowAAD(a, id), nil) }`, 1},
		{"a variadic func literal called with no argument", "internal/api/x.go", `func f(k *keyring.Ring, a uuid.UUID) { apply := func(ids ...uuid.UUID) { k.Seal("d", userAAD(ids[0]), nil) }; apply() }`, 1},
		{"a func literal called with the results of one call", "internal/api/x.go", `func pair(a uuid.UUID) (uuid.UUID, uuid.UUID) { return a, a }
func f(k *keyring.Ring, a uuid.UUID) { apply := func(x, y uuid.UUID) { k.Seal("d", userAAD(x), nil) }; apply(pair(a)) }`, 1},
		{"a variadic function called with no argument", "internal/api/x.go", `func sealN(k *keyring.Ring, ids ...uuid.UUID) { k.Seal("d", userAAD(ids[0]), nil) }
func f(k *keyring.Ring) { sealN(k) }`, 1},
		{"a variadic function called with no argument at all", "internal/api/x.go", `func sealV(ids ...uuid.UUID) { var k *keyring.Ring; k.Seal("d", userAAD(ids[0]), nil) }
func f() { sealV() }`, 1},
		{"a function called with the results of one call", "internal/api/x.go", `func pair(a uuid.UUID) (uuid.UUID, uuid.UUID) { return a, a }
func seal2(x, y uuid.UUID) { var k *keyring.Ring; k.Seal("d", userAAD(x), nil) }
func f(a uuid.UUID) { seal2(pair(a)) }`, 1},
		{"a func literal handed to another function", "internal/api/x.go", `func run(fn func(uuid.UUID)) {}
func f(k *keyring.Ring, a uuid.UUID) { run(func(id uuid.UUID) { k.Seal("d", rowAAD(a, id), nil) }) }`, 0},
		{"a labelled seal with a nil context", "internal/api/x.go", `func f(k *keyring.Ring) { k.SealLabeled("d", "l", nil, nil) }`, 1},
		{"a labelled open with an AAD function", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { k.OpenLabeled("d", "l", userAAD(id), nil) }`, 0},
		{"a func literal inside", "internal/api/x.go", `func f(k *keyring.Ring) { _ = func() { k.Seal("d", nil, nil) } }`, 1},
		{"a method value with a literal context", "internal/api/x.go", `func f(k *keyring.Ring) { seal := k.Seal; _, _ = seal("d", []byte("doh"), nil) }`, 1},
		{"a method value of a struct field", "internal/api/x.go", `type s struct{ keys *keyring.Ring }
func (v s) f() { seal := v.keys.Seal; _, _ = seal("d", []byte("doh"), nil) }`, 1},
		{"a method handed on as a function value", "internal/api/x.go", `func rekey(open func(string, []byte, []byte) ([]byte, error)) { _, _ = open("d", []byte("doh"), nil) }
func f(k *keyring.Ring) { rekey(k.Open) }`, 1},
		{"a method expression", "internal/api/x.go", `func f(k *keyring.Ring) { _, _ = (*keyring.Ring).Seal(k, "d", []byte("x"), nil) }`, 1},
		{"a parenthesised call is still a call", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { _, _ = (k.Seal)("d", userAAD(id), nil) }`, 0},
		{"a ring embedded in a struct", "internal/api/x.go", `type s struct{ *keyring.Ring }
func f(v s) { _, _ = v.Seal("d", nil, nil) }`, 1},
		{"a ring behind an interface", "internal/api/x.go", `type sealer interface{ Seal(domain string, context keyring.Context, plain []byte) ([]byte, error) }
func f(s sealer) { _, _ = s.Seal("d", []byte("x"), nil) }`, 1},
		{"a value whose type cannot be resolved", "internal/api/x.go", `func f(k Missing) { _, _ = k.Seal("d", []byte("x"), nil) }`, 1},
		{"a method of another arity", "internal/api/x.go", `type M struct{}
func (M) Open(kind, cookie string) {}
func f(m *M) { m.Open("kind", "cookie") }`, 0},
		{"a test file is not judged", "internal/api/x_test.go", `func f(k *keyring.Ring) { k.Seal("d", nil, nil) }`, 0},
		{"the keyring itself is not judged", "internal/keyring/x.go", `func f(k *Ring) { k.Seal("d", nil, nil) }`, 0},
		// Round 14 (primitives-r14-2, -4, -5): the declaration is judged by what the parameters
		// reach, a variable by every use of it, an interface by its method set wherever it is written.
		// Round 15 (primitives-r15-2): the expression is judged by an allow list, so a shape the rule
		// never saw fails. Each of the first four read as "the parameter reaches the result" under the
		// deny list and bound every row to one context.
		{"a variable that is read", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); _ = len(aad); k.Seal("d", aad, nil) }`, 1},
		{"a variable used by two seals", "internal/api/x.go", `func f(k *keyring.Ring, id uuid.UUID) { aad := userAAD(id); k.Seal("d", aad, nil); k.Open("d", aad, nil) }`, 0},
		{"a ring behind an interface literal parameter", "internal/api/x.go", `func f(s interface{ Seal(domain string, context keyring.Context, plain []byte) ([]byte, error) }) { _, _ = s.Seal("d", []byte("x"), nil) }`, 1},
		{"a ring behind an alias of an interface literal", "internal/api/x.go", `type sealer = interface{ Open(domain string, context keyring.Context, ct []byte) ([]byte, error) }
func f(s sealer) { _, _ = s.Open("d", []byte("x"), nil) }`, 1},
		{"a ring behind a type assertion to a literal", "internal/api/x.go", `func f(v any) { _, _ = v.(interface{ SealLabeled(domain, label string, context keyring.Context, plain []byte) ([]byte, error) }).SealLabeled("d", "l", []byte("x"), nil) }`, 1},
		{"a ring behind an interface variable", "internal/api/x.go", `var s interface{ Seal(domain string, context keyring.Context, plain []byte) ([]byte, error) }`, 1},
		{"an interface with another signature is not the ring", "internal/api/x.go", `type t interface{ Seal(kind string) }
func f(s interface{ Open(a, b string) }, v t) {}`, 0},
	}
	for _, c := range cases {
		src := plantHeader + c.src + plantedAAD
		if c.path == "internal/keyring/x.go" {
			src = "package keyring\n" + c.src
		}
		w := plantedWorld(t, c.name, c.path, src)
		if got := keyringContextProblems(w); len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
