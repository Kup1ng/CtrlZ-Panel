package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The import allow list (P1 auth review round 11, primitives-r11-2 and -3; rule one-primitive-per-key and
// spec 6.3). The RFC 6238 lint used to be a block list of path elements (totp, hotp, otp, gotp) and of two
// imports (crypto/hmac, crypto/sha1). A library under another name (dgoogauth, twofactor, go-otp) passed, and
// so did HMAC-SHA1 built as hkdf.Extract(crypto.SHA1.New, msg, key). Two rounds had widened the name list
// each time, which is the shape of a rule that fails open. The rule is an allow list now: internal/lint/
// imports.yaml names every package non-test code may import from outside the standard library and this
// module, and the few packages that can compute an HMAC with the only directories that may import them. An
// import nobody reviewed fails the build until a reviewer adds it, with the reason.

// importPolicy is imports.yaml.
type importPolicy struct {
	CodePrimitives map[string]struct {
		Why  string   `yaml:"why"`
		Only []string `yaml:"only"`
	} `yaml:"code_primitives"`
	ThirdParty []struct {
		Path string `yaml:"path"`
		Why  string `yaml:"why"`
	} `yaml:"third_party"`
	WithoutNonTestImport []struct {
		Module string `yaml:"module"`
		Why    string `yaml:"why"`
	} `yaml:"without_non_test_import"`

	// reach maps a package directory of the shared module ("shared/identity") to the code
	// primitives it imports, itself or through another shared package. It is read from the source of
	// shared/, not from imports.yaml (round 12, primitives-r12-4).
	reach map[string][]string
}

func loadImportPolicy(t *testing.T) importPolicy {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "lint", "imports.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var p importPolicy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("imports.yaml: %v", err)
	}
	return p
}

func (p importPolicy) listed() map[string]bool {
	m := map[string]bool{}
	for _, e := range p.ThirdParty {
		m[e.Path] = true
	}
	return m
}

// sharedModule is the shared contract module, reached through a replace directive. It is ours, but it is a
// second module with its own checks, and what its packages import reaches the Panel through them, so a Panel
// import of one is listed under third_party like any other module (round 12, primitives-r12-4: the module
// used to be waved through here, and shared/ itself was never read).
const sharedModule = "github.com/Kup1ng/CtrlZ-Shared"

// isOutside reports whether an import path is neither the standard library (no dot in the first element) nor
// this module.
func isOutside(p string) bool {
	first, _, _ := strings.Cut(p, "/")
	if !strings.Contains(first, ".") {
		return false
	}
	return p != module && !strings.HasPrefix(p, module+"/")
}

// sharedDir maps an import path of the shared module to its directory in this repository.
func sharedDir(p string) (string, bool) {
	switch {
	case p == sharedModule:
		return "shared", true
	case strings.HasPrefix(p, sharedModule+"/"):
		return "shared/" + strings.TrimPrefix(p, sharedModule+"/"), true
	}
	return "", false
}

func inSharedTree(dir string) bool { return dir == "shared" || strings.HasPrefix(dir, "shared/") }

// sharedReach computes, for every package directory of shared/, the code primitives of the policy that it
// imports directly or through another shared package. files are the non-test files of shared/.
func sharedReach(p importPolicy, files []file) map[string][]string {
	direct := map[string]map[string]bool{}
	edges := map[string]map[string]bool{}
	for _, f := range files {
		dir := filepath.ToSlash(filepath.Dir(f.path))
		if direct[dir] == nil {
			direct[dir], edges[dir] = map[string]bool{}, map[string]bool{}
		}
		for _, imp := range f.ast.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if _, ok := p.CodePrimitives[path]; ok {
				direct[dir][path] = true
			}
			if d, ok := sharedDir(path); ok {
				edges[dir][d] = true
			}
		}
	}
	out := map[string][]string{}
	for dir := range direct {
		seen := map[string]bool{}
		got := map[string]bool{}
		var walk func(d string)
		walk = func(d string) {
			if seen[d] {
				return
			}
			seen[d] = true
			for prim := range direct[d] {
				got[prim] = true
			}
			for e := range edges[d] {
				walk(e)
			}
		}
		walk(dir)
		for prim := range got {
			out[dir] = append(out[dir], prim)
		}
		sort.Strings(out[dir])
	}
	return out
}

// importViolations is the allow list applied to one non-test file in dir.
func importViolations(p importPolicy, dir, name string, f *ast.File) []string {
	var out []string
	listed := p.listed()
	shared := inSharedTree(dir)
	allowedFor := func(path string) bool {
		for _, d := range p.CodePrimitives[path].Only {
			if d == dir {
				return true
			}
		}
		return false
	}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if prim, ok := p.CodePrimitives[path]; ok {
			if !allowedFor(path) {
				out = append(out, name+" imports "+path+", which can compute an HMAC or a one-time code; only "+strings.Join(prim.Only, ", ")+" may (internal/lint/imports.yaml). MACs belong in internal/keyring and codes in internal/auth/totp")
			}
			continue
		}
		if shared {
			// shared/ is a module of its own with its own hygiene test: only the primitives above are
			// judged here, so a code library cannot hide in the module the Panel imports.
			continue
		}
		// A package of the shared module carries the primitives it imports to whoever imports it: a Panel
		// directory that may not compute an HMAC may not import a shared package that does.
		if sd, ok := sharedDir(path); ok {
			for _, prim := range p.reach[sd] {
				if !allowedFor(prim) {
					out = append(out, name+" imports "+path+", which reaches "+prim+" and can compute an HMAC or a one-time code; only "+strings.Join(p.CodePrimitives[prim].Only, ", ")+" may import it, directly or through shared (internal/lint/imports.yaml)")
				}
			}
		}
		// A module that imports.yaml says non-test code does not use cannot be used by a quiet commit:
		// the excuse is removed, and the packages listed, in the diff that first imports it.
		excused := false
		for _, e := range p.WithoutNonTestImport {
			if underModule(path, e.Module) {
				excused = true
				out = append(out, name+" imports "+path+", of module "+e.Module+", which imports.yaml says non-test code does not import; remove it from without_non_test_import and list the package under third_party with the reason")
			}
		}
		if excused {
			continue
		}
		if isOutside(path) && !listed[path] {
			out = append(out, name+" imports "+path+", which internal/lint/imports.yaml does not list; a reviewer adds a package there with the reason, and a one-time-code library is verified by internal/auth/totp Check, which throttles first")
		}
	}
	return out
}

// directRequires reads the direct requirements of go.mod (the lines of a require block that do not end in
// "// indirect"), so the allow list can be compared with the module file and not with itself.
func directRequires(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	in := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "require ("):
			in = true
		case line == ")":
			in = false
		case in && line != "" && !strings.HasPrefix(line, "//") && !strings.HasSuffix(line, "// indirect"):
			out = append(out, strings.Fields(line)[0])
		case strings.HasPrefix(line, "require ") && !strings.HasSuffix(line, "// indirect") && !strings.Contains(line, "("):
			out = append(out, strings.Fields(line)[1])
		}
	}
	return out
}

func underModule(path, mod string) bool { return path == mod || strings.HasPrefix(path, mod+"/") }

// parseSharedTree reads the non-test Go files of shared/ for the import rule. Paths are relative to the
// repository ("shared/identity/identity.go"), so the allow list names a shared package the way it names a
// Panel one. Test files are left out like everywhere else. The generated code of shared/gen is read too:
// it imports the protobuf runtime on purpose and no primitive, and a primitive there would be as reachable.
func parseSharedTree(t *testing.T) []file { return parseSharedTreeMode(t, parser.ImportsOnly) }

// parseSharedTreeMode is parseSharedTree with the parser mode the caller needs: the import rule reads
// imports only, the guard rule (primitives-r13-3) reads the declarations and the bodies.
func parseSharedTreeMode(t *testing.T, mode parser.Mode) []file {
	t.Helper()
	return parseSharedTreeInto(t, token.NewFileSet(), mode)
}

// parseSharedTreeInto reads shared/ into a file set the caller owns, so a rule that reports positions
// can judge these files together with the files of parseRepo.
func parseSharedTreeInto(t *testing.T, fset *token.FileSet, mode parser.Mode) []file {
	t.Helper()
	root := repoRoot(t)
	out, err := parseModuleFiles(fset, root, filepath.Join(root, "shared"), mode, false)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestEveryImportIsReviewed runs the allow list on every non-test file of the module and compares the list
// with the source and with go.mod, so that neither a new import nor a stale entry passes.
func TestEveryImportIsReviewed(t *testing.T) {
	pol := loadImportPolicy(t)
	_, files := parseRepo(t)
	// shared/ is read as well (round 12, primitives-r12-4): parseRepo leaves it out because it is a module
	// with its own rules, but the code primitives it imports reach the Panel through the packages the Panel
	// imports, and shared/identity already computes an HMAC.
	shared := parseSharedTree(t)
	if len(shared) < 20 {
		t.Fatalf("only %d non-test files read under shared/; the walk is wrong", len(shared))
	}
	pol.reach = sharedReach(pol, shared)
	files = append(files, shared...)
	imported := map[string]bool{}      // every outside path non-test code imports
	importers := map[string][]string{} // primitive path -> dirs that import it
	for _, f := range files {
		if f.test {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(f.path))
		for _, v := range importViolations(pol, dir, filepath.ToSlash(f.path), f.ast) {
			t.Error(v)
		}
		for _, imp := range f.ast.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if isOutside(path) && !inSharedTree(dir) {
				imported[path] = true
			}
			if _, ok := pol.CodePrimitives[path]; ok {
				importers[path] = append(importers[path], dir)
			}
			// A directory that imports a shared package imports what it reaches.
			if sd, ok := sharedDir(path); ok && !inSharedTree(dir) {
				for _, prim := range pol.reach[sd] {
					importers[prim] = append(importers[prim], dir)
				}
			}
		}
	}

	// Stale entries: a list that names what nobody imports protects nothing and hides the next addition.
	for _, e := range pol.ThirdParty {
		if !imported[e.Path] {
			t.Errorf("imports.yaml lists %s and no non-test file imports it; remove the entry", e.Path)
		}
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("imports.yaml lists %s with no reason", e.Path)
		}
	}
	for path, prim := range pol.CodePrimitives {
		if strings.TrimSpace(prim.Why) == "" {
			t.Errorf("imports.yaml lists the primitive %s with no reason", path)
		}
		have := map[string]bool{}
		for _, d := range importers[path] {
			have[d] = true
		}
		for _, d := range prim.Only {
			if !have[d] {
				t.Errorf("imports.yaml lets %s import %s and it does not; remove %s from the entry", d, path, d)
			}
		}
	}

	// The two lists against go.mod.
	direct := directRequires(t)
	if len(direct) < 5 {
		t.Fatalf("go.mod: only %d direct requirements read", len(direct))
	}
	sort.Strings(direct)
	covers := map[string]bool{}
	for _, e := range pol.ThirdParty {
		hit := false
		for _, mod := range direct {
			if underModule(e.Path, mod) {
				hit, covers[mod] = true, true
			}
		}
		if !hit {
			t.Errorf("imports.yaml lists %s, which no direct requirement of go.mod provides", e.Path)
		}
	}
	excused := map[string]bool{}
	for _, e := range pol.WithoutNonTestImport {
		excused[e.Module] = true
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("imports.yaml excuses %s with no reason", e.Module)
		}
		if covers[e.Module] {
			t.Errorf("imports.yaml excuses %s as unused by non-test code and also lists a path of it", e.Module)
		}
	}
	for _, mod := range direct {
		if !covers[mod] && !excused[mod] {
			t.Errorf("go.mod requires %s directly and imports.yaml has no path of it: list the packages non-test code imports, or put it under without_non_test_import with the reason", mod)
		}
	}
	for m := range excused {
		found := false
		for _, mod := range direct {
			if mod == m {
				found = true
			}
		}
		if !found {
			t.Errorf("imports.yaml excuses %s, which go.mod does not require directly", m)
		}
	}
}

// TestImportAllowListCanFail plants what the rule exists to stop: a library under a name no list
// foresaw, HMAC-SHA1 built from HKDF and the bare crypto package, the same through x/crypto and PBKDF2, a
// listed package in a directory that may not use it, and the cases that must stay quiet.
func TestImportAllowListCanFail(t *testing.T) {
	base := loadImportPolicy(t)
	// The shared packages the planted sources reach: identity imports hmac itself and wrapper through
	// identity, as the real tree does for identity alone.
	base.reach = map[string][]string{"shared/identity": {"crypto/hmac"}, "shared/wrapper": {"crypto/hmac"}}
	for name, tc := range map[string]struct {
		dir, src string
		want     int
	}{
		"a library with an unrelated name": {"internal/api", `package x
import "github.com/dgryski/dgoogauth"
func f() { _ = dgoogauth.Authenticate }`, 1},
		"another library with an unrelated name": {"internal/adminapi", `package x
import "github.com/sec51/twofactor"
func f() { _ = twofactor.Validate }`, 1},
		"a library named totp": {"internal/adminapi", `package x
import "github.com/pquerna/otp/totp"
func f() { _ = totp.Validate }`, 1},
		"a library at a major version path": {"internal/api", `package x
import "example.com/hotp/v2"
func f() { _ = hotp.Validate }`, 1},
		"HMAC-SHA1 from hkdf.Extract": {"internal/api", `package x
import ("crypto"; "crypto/hkdf")
func f() { _, _ = hkdf.Extract(crypto.SHA1.New, nil, nil) }`, 2},
		"HMAC-SHA1 from x/crypto hkdf": {"internal/api", `package x
import "golang.org/x/crypto/hkdf"
func f() { _ = hkdf.New }`, 1},
		"HMAC-SHA1 from pbkdf2": {"internal/api", `package x
import "crypto/pbkdf2"
func f() { _ = pbkdf2.Key }`, 1},
		"hmac outside": {"internal/api", `package x
import "crypto/hmac"
func f() { _ = hmac.New }`, 1},
		"sha1 outside": {"internal/api", `package x
import "crypto/sha1"
func f() { _ = sha1.New }`, 1},
		"hmac in keyring": {"internal/keyring", `package x
import "crypto/hmac"
func f() { _ = hmac.New }`, 0},
		"hkdf in keyring": {"internal/keyring", `package x
import "crypto/hkdf"
func f() { _ = hkdf.Extract }`, 0},
		"hkdf in the totp package": {"internal/auth/totp", `package x
import "crypto/hkdf"
func f() { _ = hkdf.Extract }`, 1},
		"hmac and sha1 in the totp package": {"internal/auth/totp", `package x
import ("crypto/hmac"; "crypto/sha1")
func f() { _, _ = hmac.New, sha1.New }`, 0},
		"sha1 in ratelimit": {"internal/ratelimit", `package x
import "crypto/sha1"
func f() { _ = sha1.New }`, 0},
		"hmac in ratelimit": {"internal/ratelimit", `package x
import "crypto/hmac"
func f() { _ = hmac.New }`, 1},
		"a listed library": {"internal/api", `package x
import "github.com/google/uuid"
func f() { _ = uuid.New }`, 0},
		"the standard library and this module": {"internal/api", `package x
import ("crypto/sha256"; "net/http"; "github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp")
func f() { _, _ = sha256.New, http.StatusOK }`, 0},
		"the shared module while the excuse stands": {"internal/api", `package x
import "github.com/Kup1ng/CtrlZ-Shared/blob"
func f() { _ = blob.X }`, 1},
		"a listed shared package once the excuse is gone": {"internal/api", `package x
import "github.com/Kup1ng/CtrlZ-Shared/blob"
func f() { _ = blob.X }`, 0},
		"an unlisted shared package once the excuse is gone": {"internal/api", `package x
import "github.com/Kup1ng/CtrlZ-Shared/policy"
func f() { _ = policy.X }`, 1},
		"a shared package that reaches hmac, imported where hmac may not be, once the excuse is gone": {"internal/api", `package x
import "github.com/Kup1ng/CtrlZ-Shared/identity"
func f() { _ = identity.ProofCode }`, 1},
		"a shared package that reaches hmac, imported where hmac may be, once the excuse is gone": {"internal/keyring", `package x
import "github.com/Kup1ng/CtrlZ-Shared/identity"
func f() { _ = identity.ProofCode }`, 0},
		"a shared package that reaches hmac through another, once the excuse is gone": {"internal/api", `package x
import "github.com/Kup1ng/CtrlZ-Shared/wrapper"
func f() { _ = wrapper.X }`, 1},
		"sha1 planted in a shared package": {"shared/policy", `package x
import "crypto/sha1"
func f() { _ = sha1.New }`, 1},
		"hkdf planted in a shared package": {"shared/policy", `package x
import "crypto/hkdf"
func f() { _ = hkdf.Extract }`, 1},
		"hmac in the listed shared package": {"shared/identity", `package x
import "crypto/hmac"
func f() { _ = hmac.New }`, 0},
		"hmac in another shared package": {"shared/wire", `package x
import "crypto/hmac"
func f() { _ = hmac.New }`, 1},
		"a protobuf import in shared is not judged here": {"shared/gen", `package x
import "google.golang.org/protobuf/proto"
func f() { _ = proto.Marshal }`, 0},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pol := base
		if strings.Contains(name, "once the excuse is gone") || strings.Contains(name, "while the excuse stands") {
			// The state after the first Panel import of the shared module: the packages listed, and
			// the excuse removed unless the case is about the excuse itself. The package is listed
			// in both, so the excuse alone is what the first case can fail on.
			// The Panel imports the shared module now (P2), so imports.yaml no longer carries the excuse. The
			// case about the excuse puts it back and must still fail, which is what proves the mechanism.
			pol.WithoutNonTestImport = nil
			if strings.Contains(name, "while the excuse stands") {
				pol.WithoutNonTestImport = []struct {
					Module string `yaml:"module"`
					Why    string `yaml:"why"`
				}{{Module: sharedModule, Why: "planted"}}
			}
			pol.ThirdParty = append([]struct {
				Path string `yaml:"path"`
				Why  string `yaml:"why"`
			}(nil), pol.ThirdParty...)
			for _, p := range []string{"blob", "identity", "wrapper"} {
				pol.ThirdParty = append(pol.ThirdParty, struct {
					Path string `yaml:"path"`
					Why  string `yaml:"why"`
				}{Path: sharedModule + "/" + p, Why: "planted"})
			}
		}
		if got := importViolations(pol, tc.dir, "x.go", f); len(got) != tc.want {
			t.Errorf("%s: %d violations %v, want %d", name, len(got), got, tc.want)
		}
	}
}
