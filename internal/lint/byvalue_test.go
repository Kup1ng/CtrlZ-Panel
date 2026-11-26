package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Rule closed-values-in-logs, round 18 (primitives-r18-9). The image sets GOTRACEBACK=none so that a
// crash prints no frame (round 17), and that setting does not hold for every crash: in Go 1.27 the
// runtime raises the level to 2 and prints every goroutine for a runtime THROW (a stack overflow, the
// Go allocator running out of memory, a consistency failure of the runtime itself), whatever the
// environment says; only fatal errors that are raised by the library and unrecovered panics respect
// "none". A frame prints the arguments of its function, up to ten words, and an array passed by value is
// printed as its words, so the ten bytes of a recovery code or a 16-byte key held by value in a frame
// reached the container log, its backups and any log shipper, and the setting could not stop it.
//
// The class is removed by construction and the setting stays as a second wall: no function of the
// module or of shared/ takes, receives or returns a value that holds an ARRAY by value (an array, or a
// struct with an array field, through any depth of named types), outside a closed list with a reason. A
// slice, a pointer, a map or a secret.Bytes is printed as an address, a length and a capacity, which
// tell a reader nothing of what it holds. Code that needs a fixed-size buffer keeps it inside a function
// body, where it is a local and not an argument, and hands the rest of the program a slice.
//
// What it judges and what it does not: the declared signatures of every function declaration and
// function literal of every non-test file, read through the type checker with the standard library
// type-checked from source. A type of a third-party package is a stub there and is not seen (a
// uuid.UUID is an array of sixteen bytes, and a row id is not a secret). A method value or an interface
// method is judged where the method is declared. A zero-length array holds no byte and is not judged. A value that is an array inside a struct that a function
// takes by pointer is not by value and is not judged. A generic is judged where it is instantiated, through
// the type checker's instances (primitives-r18-21): `func show[T any](v T)` holds a type parameter, and the
// frame of show[[16]byte] prints the array, so the substituted signature of each use (and the substituted
// methods of each named use of a generic type) is read, and a use inside another generic is judged where
// that one is instantiated. A generic that is never instantiated in the module prints nothing.

// byValueSites are the declarations outside shared/ that may hold an array by value, each with why it is no
// secret. A key is a declaration, "file::Func" or "file::Type.Method" (sites_test.go), never a file or a
// directory (primitives-r18-23).
var byValueSites = map[string]string{
	"internal/auth/credstate/credstate.go::all":  "the table of credential states: arrays of bools that say which transitions exist; no byte of a secret",
	"internal/auth/credstate/credstate.go::edge": "the edge of the credential-state table: arrays of bools; no byte of a secret",
}

// byValueSharedReasons say what each directory of shared/ holds in the fixed-size values its declarations
// pass by value. The data plane of the DNS node keeps rule ids, country codes, address blocks and content
// hashes that way all through its packages. The declarations themselves are listed one by one in
// testdata/byvalue-shared.golden: a new function of shared/ that takes or returns an
// array fails until its line is added in a diff a reviewer reads, and a line that excuses nothing fails
// (primitives-r18-23: the directory used to excuse every function in it, so a new function of
// shared/identity or shared/wire could hold a secret with no review although this reason says none is
// held there). A credential is never held by value in any of them: a token is a string, and what these
// packages keep of one is its hash.
var byValueSharedReasons = map[string]string{
	"shared/appleprofile/": "the Apple DNS profile: the SHA-256 of the profile parameters and the fixed UUID namespace of its identifiers, both public",
	"shared/blob/":         "the compiled policy blob: rule ids, country codes, address blocks and content hashes of public profile data",
	"shared/gtable/":       "the global table: the 16-byte key of a public service name",
	"shared/identity/":     "the identity hashes of the data plane (a resolver id, a client label, a DoH path token): one-way hashes, never the value they are of",
	"shared/locations/":    "endpoint ids and pair references of the location tables",
	"shared/names/":        "DNS names in wire form and the fixed SipHash key of profile blobs (the ASCII text ctrlz-profile-v1)",
	"shared/policy/":       "policy decisions: rule ids, endpoint ids and country codes",
	"shared/quarantine/":   "content hashes of profile blobs",
	"shared/rules/":        "rule patterns: country codes",
	"shared/vectors/":      "the golden test vectors of the shared contract: ids and hashes",
	"shared/wire/":         "the hash chain of the wire format: SHA-256 values of public content",
	// P4: the failover zone shared by the Panel's hub and the nodes. Its fixed-size values are the 16-byte
	// ids of nodes and pairs, which are public identifiers (they are in the pair table every node holds and
	// in the activity feed), never a credential: a node's secret is its mTLS key, which no code of this
	// package sees.
	"shared/zone/":                 "the failover zone: 16-byte node ids and pair ids, public identifiers of the pair table",
	"shared/internal/failovergen/": "the generator of the zone-failover vectors: the same node ids, as test data",
}

// byValueSharedGolden is the list of declarations of shared/ that may hold an array by value.
func byValueSharedGolden(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "lint", "testdata", "byvalue-shared.golden"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// byValueAllowed is every declaration that may hold an array by value, with its reason: the sites of
// byValueSites and the golden list of shared/, each under the reason of its directory. A listed site of a
// directory with no reason is an error of the list and is reported by name.
func byValueAllowed(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for k, v := range byValueSites {
		out[k] = v
	}
	for _, site := range byValueSharedGolden(t) {
		path, _, _ := strings.Cut(site, "::")
		reason := ""
		for dir, r := range byValueSharedReasons {
			if strings.HasPrefix(path, dir) {
				reason = r
			}
		}
		if reason == "" {
			t.Errorf("testdata/byvalue-shared.golden lists %s, whose directory has no reason in byValueSharedReasons", site)
			continue
		}
		out[site] = reason
	}
	return out
}

// byValueAllowedFor says which entry of the list excuses a site, "" when none does.
func byValueAllowedFor(allowed map[string]string, site string) string {
	if _, ok := allowed[site]; ok {
		return site
	}
	return ""
}

// mentionsTypeParam says whether an instantiation is made with a type parameter of an enclosing generic
// (`G[T]` in the receiver of a method of G, `show[T]` in another generic): the instance is the generic itself
// or one that is judged where that generic is instantiated.
func mentionsTypeParam(args *types.TypeList) bool {
	var has func(t types.Type) bool
	has = func(t types.Type) bool {
		switch u := types.Unalias(t).(type) {
		case *types.TypeParam:
			return true
		case *types.Pointer:
			return has(u.Elem())
		case *types.Slice:
			return has(u.Elem())
		case *types.Array:
			return has(u.Elem())
		case *types.Chan:
			return has(u.Elem())
		case *types.Map:
			return has(u.Key()) || has(u.Elem())
		case *types.Named:
			for i := range u.TypeArgs().Len() {
				if has(u.TypeArgs().At(i)) {
					return true
				}
			}
		}
		return false
	}
	for i := range args.Len() {
		if has(args.At(i)) {
			return true
		}
	}
	return false
}

// holdsArray says whether a value of type t holds an array by value, and which.
func holdsArray(t types.Type, seen map[types.Type]bool) (string, bool) {
	if t == nil || seen[t] {
		return "", false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Array:
		// A zero-length array holds no byte (slog.Value carries one to keep itself uncomparable).
		if u.Len() == 0 {
			return "", false
		}
		return t.String(), true
	case *types.Struct:
		for i := range u.NumFields() {
			if s, ok := holdsArray(u.Field(i).Type(), seen); ok {
				return t.String() + " (field " + u.Field(i).Name() + ": " + s + ")", true
			}
		}
	}
	return "", false
}

// byValueProblems judges every function signature of the non-test files.
func byValueProblems(fset *token.FileSet, files []file, info *types.Info, allowed map[string]string) (problems []string, used map[string]bool) {
	used = map[string]bool{}
	judge := func(path, site string, pos token.Pos, name string, sig *types.Signature) {
		if site == "" {
			site = path + "::" // a declaration that is not a function (an interface type)
		}
		check := func(kind string, v *types.Var) {
			s, ok := holdsArray(v.Type(), map[types.Type]bool{})
			if !ok {
				return
			}
			if key := byValueAllowedFor(allowed, site); key != "" {
				used[key] = true
				return
			}
			problems = append(problems, fmt.Sprintf("%s: %s of %s [site %s] holds an array by value (%s): a crash that the runtime reports as a throw prints the words of every argument whatever GOTRACEBACK says; take a slice or a pointer, or list the declaration in byValueSites (outside shared/) or add its line to testdata/byvalue-shared.golden (in shared/) with the reason it holds no secret", fset.Position(pos), kind, name, site, s))
		}
		if r := sig.Recv(); r != nil {
			check("the receiver", r)
		}
		for i := range sig.Params().Len() {
			check("parameter "+sig.Params().At(i).Name(), sig.Params().At(i))
		}
		for i := range sig.Results().Len() {
			check("a result", sig.Results().At(i))
		}
	}
	for _, f := range files {
		if f.test {
			continue
		}
		walkSites(f.path, f.ast, func(site string, n ast.Node) {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if fn, ok := info.Defs[x.Name].(*types.Func); ok {
					if sig, ok := fn.Type().(*types.Signature); ok {
						judge(f.path, totpSite(f.path, x), x.Pos(), x.Name.Name, sig)
					}
				}
			case *ast.FuncLit:
				if sig, ok := info.TypeOf(x).(*types.Signature); ok {
					judge(f.path, site, x.Pos(), "a function literal in "+site, sig)
				}
			case *ast.Ident:
				// A generic is judged where it is instantiated (primitives-r18-21): the frame of f[[16]byte] prints
				// the words of the array, and the declaration holds only a type parameter. The instance carries the
				// substituted signature of a function, or the substituted methods of a type; a use inside another
				// generic still names a type parameter, which holds no array here and is judged where that generic
				// is instantiated.
				inst, ok := info.Instances[x]
				if !ok || mentionsTypeParam(inst.TypeArgs) {
					return
				}
				switch it := inst.Type.(type) {
				case *types.Signature:
					judge(f.path, site, x.Pos(), "the instantiation "+x.Name, it)
				case *types.Named:
					for i := range it.NumMethods() {
						if sig, ok := it.Method(i).Type().(*types.Signature); ok {
							judge(f.path, site, x.Pos(), "the method "+it.Method(i).Name()+" of the instantiated type "+x.Name, sig)
						}
					}
				}
			case *ast.InterfaceType:
				// An interface method is declared here and called anywhere: its signature is judged too.
				tv, ok := info.Types[x]
				if !ok || tv.Type == nil {
					return
				}
				if it, ok := tv.Type.Underlying().(*types.Interface); ok {
					for i := range it.NumExplicitMethods() {
						m := it.ExplicitMethod(i)
						if sig, ok := m.Type().(*types.Signature); ok {
							judge(f.path, site, x.Pos(), "the interface method "+m.Name(), sig)
						}
					}
				}
			}
		})
	}
	sort.Strings(problems)
	return problems, used
}

func TestNoFunctionTakesAnArrayByValue(t *testing.T) {
	fset, files := clockFiles(t)
	info, ok := typeInfo(fset, files)
	if !ok {
		t.Fatal("type information unavailable")
	}
	allowed := byValueAllowed(t)
	problems, used := byValueProblems(fset, files, info, allowed)
	for _, p := range problems {
		t.Error(p)
	}
	for site, why := range allowed {
		if !used[site] {
			t.Errorf("%s (%s) is listed in byValueSites or testdata/byvalue-shared.golden and holds no array by value any more: remove the entry", site, why)
		}
	}
}

// TestByValueLintCanFail plants every form Go allows for the construct: an array parameter, an array
// result, an array receiver, a struct with an array field, a named array type, an array behind two
// named types, a function literal, an interface method, a method of a generic type, an array inside a
// pointer or a slice (clean), a slice (clean) and a test file (clean).
func TestByValueLintCanFail(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"an array parameter", "internal/auth/x.go", "func f(b [10]byte) {}", 1},
		{"an array result", "internal/auth/x.go", "func f() [10]byte { return [10]byte{} }", 1},
		{"an array receiver", "internal/auth/x.go", "type T [4]byte\nfunc (t T) f() {}", 1},
		{"a pointer to an array", "internal/auth/x.go", "func f(b *[10]byte) {}", 0},
		{"a slice", "internal/auth/x.go", "func f(b []byte) {}", 0},
		{"a struct with an array field", "internal/auth/x.go", "type S struct{ k [32]byte }\nfunc f(s S) {}", 1},
		{"a struct with an array two levels down", "internal/auth/x.go", "type In struct{ k [32]byte }\ntype Out struct{ in In }\nfunc f(o Out) {}", 1},
		{"a named array type", "internal/auth/x.go", "type Key [16]byte\nfunc f(k Key) {}", 1},
		{"an alias of an array", "internal/auth/x.go", "type Key = [16]byte\nfunc f(k Key) {}", 1},
		{"a struct that holds a pointer to one", "internal/auth/x.go", "type S struct{ k *[32]byte }\nfunc f(s S) {}", 0},
		{"a function literal", "internal/auth/x.go", "var g = func(b [4]byte) {}", 1},
		{"a function literal in a function", "internal/auth/x.go", "func f() { h := func(b [4]byte) {}; _ = h }", 1},
		{"an interface method", "internal/auth/x.go", "type I interface{ Do(b [8]byte) }", 1},
		{"a type parameter method", "internal/auth/x.go", "type G[T any] struct{}\nfunc (G[T]) f(b [3]byte) {}", 1},
		{"a variadic of arrays", "internal/auth/x.go", "func f(b ...[2]byte) {}", 0},
		{"a map of arrays", "internal/auth/x.go", "func f(m map[string][2]byte) {}", 0},
		{"a local array", "internal/auth/x.go", "func f() { var b [10]byte; _ = b }", 0},
		{"an integer", "internal/auth/x.go", "func f(n uint64) {}", 0},
		{"a test file", "internal/auth/x_test.go", "func f(b [10]byte) {}", 0},
		{"a file of shared/", "shared/names/x.go", "func f(b [10]byte) {}", 1},
		// primitives-r18-21: a generic is judged where it is instantiated, with the substituted signature.
		{"a generic function declared and never instantiated", "internal/auth/x.go", "func show[T any](v T) {}", 0},
		{"a generic function instantiated with an array", "internal/auth/x.go", "func show[T any](v T) {}\nfunc f(k *[16]byte) { show(*k) }", 1},
		{"a generic function instantiated explicitly with an array", "internal/auth/x.go", "func show[T any](v T) {}\nfunc f() { show[[4]byte]([4]byte{}) }", 1},
		{"a generic function returning an array through a slice", "internal/auth/x.go", "func pick[T any](v []T) T { return v[0] }\nfunc f(v [][16]byte) { _ = pick(v) }", 1},
		{"a generic function instantiated with a struct that holds an array", "internal/auth/x.go", "type S struct{ k [8]byte }\nfunc show[T any](v T) {}\nfunc f(s *S) { show(*s) }", 1},
		{"a generic function instantiated with an integer", "internal/auth/x.go", "func show[T any](v T) {}\nfunc f(n int) { show(n) }", 0},
		{"a generic function instantiated with a string and a pointer to an array", "internal/auth/x.go", "func show[T any](v T) {}\nfunc f(s string, p *[16]byte) { show(s); show(p) }", 0},
		{"a generic type instantiated with an array", "internal/auth/x.go", "type Box[T any] struct{ v T }\nfunc (b Box[T]) Get() T { return b.v }\nfunc f(b *Box[[16]byte]) {}", 2},
		{"a generic type instantiated with an integer", "internal/auth/x.go", "type Box[T any] struct{ v T }\nfunc (b Box[T]) Get() T { return b.v }\nfunc f(b *Box[int]) {}", 0},
		{"a generic type declared and never instantiated", "internal/auth/x.go", "type Box[T any] struct{ v T }\nfunc (b Box[T]) Get() T { return b.v }", 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		dir := c.path[:strings.LastIndex(c.path, "/")]
		src := "package " + dir[strings.LastIndex(dir, "/")+1:] + "\n" + c.src
		af, err := parser.ParseFile(fset, c.path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fs := []file{{path: c.path, test: strings.HasSuffix(c.path, "_test.go"), ast: af}}
		info, ok := typeInfo(fset, fs)
		if !ok {
			if c.want == 0 && strings.HasSuffix(c.path, "_test.go") {
				continue // a file of tests only has no package the checker reads: nothing is judged
			}
			t.Fatalf("%s: no type information", c.name)
		}
		got, _ := byValueProblems(fset, fs, info, nil)
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
	// A listed declaration is excused, and an entry that excuses nothing is stale.
	fset := token.NewFileSet()
	af, _ := parser.ParseFile(fset, "internal/auth/x.go", "package auth\nfunc f(b [10]byte) {}", 0)
	fs := []file{{path: "internal/auth/x.go", ast: af}}
	info, _ := typeInfo(fset, fs)
	got, used := byValueProblems(fset, fs, info, map[string]string{"internal/auth/x.go::f": "an id"})
	if len(got) != 0 || !used["internal/auth/x.go::f"] {
		t.Errorf("a listed declaration: %v %v", got, used)
	}
	// A declaration of shared/ is excused by its own entry, and a neighbour in the same file is not
	// (primitives-r18-23).
	af2, _ := parser.ParseFile(fset, "shared/names/x.go", "package names\nfunc f(b [10]byte) {}\nfunc g(b [10]byte) {}", 0)
	fs2 := []file{{path: "shared/names/x.go", ast: af2}}
	info2, _ := typeInfo(fset, fs2)
	if got, _ := byValueProblems(fset, fs2, info2, map[string]string{"shared/names/x.go::f": "a name"}); len(got) != 1 || !strings.Contains(got[0], "shared/names/x.go::g") {
		t.Errorf("a neighbour of a listed declaration of shared/: %v", got)
	}
}

// TestByValueAllowListEntriesAreKnown holds the shape of the lists: a key is a declaration of a file that
// exists, and a directory reason names a directory of shared/ that exists and is used by at least one line
// of the golden list, so an entry cannot name a place that is gone.
func TestByValueAllowListEntriesAreKnown(t *testing.T) {
	root := repoRoot(t)
	golden := byValueSharedGolden(t)
	if len(golden) < 50 {
		t.Fatalf("testdata/byvalue-shared.golden lists %d declarations: the list was emptied, or the file moved", len(golden))
	}
	for k := range byValueAllowed(t) {
		file, _, ok := strings.Cut(k, "::")
		if !ok {
			t.Errorf("%s is not file::Func", k)
			continue
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(file))); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	for site := range byValueSites {
		if strings.HasPrefix(site, "shared/") {
			t.Errorf("%s is a declaration of shared/ in byValueSites: it belongs in testdata/byvalue-shared.golden", site)
		}
	}
	for _, site := range golden {
		if !strings.HasPrefix(site, "shared/") {
			t.Errorf("%s is in testdata/byvalue-shared.golden and is not a declaration of shared/", site)
		}
	}
	for dir := range byValueSharedReasons {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(dir, "/")))); err != nil {
			t.Errorf("%s: %v", dir, err)
		}
		used := false
		for _, site := range golden {
			used = used || strings.HasPrefix(site, dir)
		}
		if !used {
			t.Errorf("byValueSharedReasons has %s and no declaration of the golden list is in it: remove the reason", dir)
		}
	}
}
