package lint_test

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The capability guard (P1 auth review round 16, sms-r16-21, sms-r16-22): who in the module may reach
// memory or a process that the type system keeps from them.
//
// Rounds 15 and 16 closed these doors one package at a time, and only for the directories a gateway
// call is known to reach (smsScope). The worker and the admin routes hold the BUILT sender and are
// not reached by one, so an `unsafe` cast of the sender to a copy of its layout, an os/exec, a
// syscall, a plugin, cgo, a go:linkname or an assembly file in them stayed green. The same defect
// as in round 15 with reflect: a guard scoped to the packages somebody had in mind.
//
// Now every non-test file of the module is judged by CLOSED lists, and anything not listed fails:
//
//   - a standard package is imported only if it is in moduleStdSafe (it gives no reach outside the
//     type system) or the directory has it in stdCapabilities (with the reason). `unsafe`, `plugin`,
//     `C` and every package added to the standard library later are in neither, so they start
//     refused: the list names what is allowed, never what is forbidden.
//   - os is judged by the member a selector names (osMembers): it starts a process and opens
//     /proc/self/mem with no other import, so a directory may use only the members listed for it.
//   - reflect is judged by reflectImporters (testonly_test.go).
//   - no function has no body (assembly, linkname), no comment is a go:linkname, and no package
//     holds a file the Go toolchain builds in besides Go source (C, assembly, objects, SWIG), asked
//     of `go list` and not of a list of extensions.
//
// What it does not judge: third-party packages (imports.yaml), shared/ (another module with its own
// checks) and test files, which may import anything.

// moduleStdSafe are the standard packages any directory may import: none of them gives a way to
// read or write memory the type system hid, start a process or load code.
var moduleStdSafe = map[string]string{
	"bufio":           "buffered I/O",
	"bytes":           "bytes",
	"container/list":  "a list",
	"context":         "deadlines and cancellation",
	"crypto/aes":      "AES for the key ring",
	"crypto/cipher":   "GCM for the key ring",
	"crypto/ecdsa":    "keys of the dev certificate tools",
	"crypto/elliptic": "curves of the dev certificate tools",
	"crypto/hkdf":     "subkeys of the key ring",
	"crypto/hmac":     "MACs",
	"crypto/rand":     "random bytes",
	"crypto/sha1":     "the HIBP style k-anonymity prefix and the TOTP algorithm named by RFC 6238",
	"crypto/sha256":   "digests",
	"crypto/subtle":   "constant time comparison",
	"crypto/tls":      "TLS configuration of the servers; an HTTP client of a gateway is judged by the SMS scope",
	"crypto/x509":     "certificates and pools",
	"database/sql":    "the type of a NULL column",
	"embed":           "files compiled in",
	"encoding/base32": "TOTP seeds",
	"encoding/base64": "text forms",
	"encoding/binary": "framing",
	"encoding/hex":    "text forms",
	"encoding/json":   "JSON",
	"encoding/xml":    "the Melipayamak reply",
	"errors":          "errors",
	"flag":            "command line flags",
	"fmt":             "formatting",
	"go/format":       "the generator of the layout tables",
	"hash/maphash":    "a seeded hash for sharding",
	"io":              "readers and writers",
	"io/fs":           "file system types",
	"log":             "the standard logger of a tool",
	"log/slog":        "logging",
	"math":            "arithmetic",
	"math/big":        "arithmetic",
	"math/rand/v2":    "non-security randomness, judged by the randsource lint",
	"net":             "addresses and listeners of the servers; a gateway call is judged by the SMS scope",
	"net/http":        "the servers and requests; a gateway client is judged by the SMS scope",
	"net/netip":       "addresses",
	"net/url":         "URLs",
	"path":            "slash paths",
	"path/filepath":   "file paths",
	"regexp":          "regular expressions",
	"slices":          "slices",
	"sort":            "ordering",
	"strconv":         "numbers",
	"strings":         "strings",
	"sync":            "locks",
	"sync/atomic":     "counters",
	"text/template":   "the generator of the layout tables",
	"time":            "time",
	"time/tzdata":     "the zone database compiled in, so no host file is needed",
	"unicode":         "character classes",
	"unicode/utf16":   "the UTF-16 dress of a provider reply",
	"unicode/utf8":    "lengths",
}

// stdCapabilities are the packages that do reach outside the type system or the process, with the
// directories that may import each and why. Each entry must be matched by an import (a stale one is
// a free pass kept for later).
var stdCapabilities = map[string]map[string]string{
	"os/signal": {
		"cmd/ctrlz":     "the service's graceful stop",
		"tools/mutants": "the mutation tool restores the tree when interrupted",
	},
	"os/exec": {
		"internal/mutant": "the mutation tool runs go test in a scratch copy of the tree",
	},
	"syscall": {
		"cmd/ctrlz": "the stop signals",
	},
	"runtime": {
		"internal/logattr":         "logattr.Stack reads the function names, files and lines of the call stack (runtime.Callers), never a value a frame holds",
		"internal/auth/pwstrength": "reads the number of CPUs to size the check pool",
	},
	"testing": {
		"internal/authtest":           "a harness",
		"internal/authtest/isolation": "a harness",
		"internal/authtest/oracle":    "a harness",
		"internal/testpg":             "a harness",
		"internal/testvalkey":         "a harness",
	},
	"net/http/httptest": {
		"internal/authtest/boundary": "a harness",
		"internal/authtest/oracle":   "a harness",
		"internal/testtls":           "a harness",
	},
}

// osMembers are the members of os a directory may use, per directory. os is the one package that
// opens a file or starts a process with no import of anything else (os.StartProcess, os.OpenFile on
// /proc/self/mem), so it is judged by the object a selector names, whatever the import is called,
// and a directory that is not listed may not import it at all.
var osMembers = map[string][]string{
	"internal/sms/noop": {"OpenFile", "O_APPEND", "O_CREATE", "O_WRONLY"}, // the development driver appends to one configured file
	"internal/secret":   {"ReadFile", "PathError"},                        // a secret read from a file, an error type
	"internal/keyring":  {"ErrNotExist"},                                  // a missing key file is not an error of the ring

	"cmd/ctrlz":                            {"Args", "Exit", "Interrupt", "Stderr"},                                                                                                          // the command line, the exit status and the stop signal of the service
	"internal/app":                         {"Getenv", "Stdout"},                                                                                                                             // the roles read their environment and log to stdout
	"internal/admincli":                    {"ErrExist", "ErrNotExist", "FileMode", "Getenv", "O_CREATE", "O_EXCL", "O_WRONLY", "OpenFile", "Remove", "Rename", "Stderr", "Stdin", "Stdout"}, // the console writes secret files exclusively and prints to the terminal
	"internal/testpg":                      {"ReadFile", "Stderr"},                                                                                                                           // a harness: the wiring test reads the Compose scripts it copies in
	"deploy":                               {"Getenv"},                                                                                                                                       // the image reference a developer may override, and only with a pinned one
	"internal/testvalkey":                  {"Stderr"},                                                                                                                                       // a harness
	"internal/mutant":                      {"Environ", "MkdirAll", "MkdirTemp", "ReadDir", "ReadFile", "RemoveAll", "Stat", "WriteFile"},                                                    // the mutation tool works in a scratch copy of the tree
	"tools/mutants":                        {"Exit", "Getwd", "Interrupt", "Stat", "Stderr", "Stdout"},                                                                                       // the mutation tool's command
	"tools/genmig":                         {"Exit", "Stderr"},                                                                                                                               // the migration generator's command
	"internal/migrategen":                  {"Open", "ReadDir", "ReadFile", "WriteFile"},                                                                                                     // the migration generator reads the SQL and writes the generated files
	"internal/auth/pwstrength/layouts/gen": {"Args", "Exit", "Stderr", "WriteFile"},                                                                                                          // the generator of the layout tables
}

// capabilityProblems judges the files by the lists above. With stale it also says which entry of a
// list no file uses.
func capabilityProblems(fset *token.FileSet, files []file, info *types.Info, stale bool) []string {
	var out []string
	usedCap := map[string]map[string]bool{}
	usedOS := map[string]map[string]bool{}
	usedSafe := map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		dir := dirOf(f.path)
		for _, im := range f.ast.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			if !isStdPath(p) || p == reflectPkg {
				continue
			}
			if p == "os" {
				if _, ok := osMembers[dir]; !ok {
					out = append(out, fmt.Sprintf("%s: %s imports os, which starts a process (os.StartProcess) or opens any file (/proc/self/mem) with no other import; only the directories of osMembers may, and each only for the members listed", fset.Position(im.Pos()), dir))
				}
				if im.Name != nil && im.Name.Name == "." {
					out = append(out, fmt.Sprintf("%s: a dot import of os hides which member is used", fset.Position(im.Pos())))
				}
				continue
			}
			if _, ok := moduleStdSafe[p]; ok {
				usedSafe[p] = true
				continue
			}
			if _, ok := stdCapabilities[p][dir]; ok {
				if usedCap[p] == nil {
					usedCap[p] = map[string]bool{}
				}
				usedCap[p][dir] = true
				continue
			}
			out = append(out, fmt.Sprintf("%s: %s imports %s, which is not in moduleStdSafe and is not a listed capability of this directory (stdCapabilities); unsafe, plugin, cgo, syscall, os/exec and any package nobody reviewed reach memory or a process the type system hides (sms-r16-21)", fset.Position(im.Pos()), dir, p))
		}
		for _, cg := range f.ast.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "//go:linkname") {
					out = append(out, fmt.Sprintf("%s: go:linkname reaches what the type system hides", fset.Position(c.Pos())))
				}
			}
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if fd, ok := n.(*ast.FuncDecl); ok && fd.Body == nil {
				out = append(out, fmt.Sprintf("%s: a function with no body is implemented in assembly or by linkname, code no lint reads", fset.Position(fd.Pos())))
			}
			sx, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			xid, ok := sx.X.(*ast.Ident)
			if !ok {
				return true
			}
			pn, ok := info.Uses[xid].(*types.PkgName)
			if !ok || pn.Imported().Path() != "os" {
				return true
			}
			for _, m := range osMembers[dir] {
				if m == sx.Sel.Name {
					if usedOS[dir] == nil {
						usedOS[dir] = map[string]bool{}
					}
					usedOS[dir][m] = true
					return true
				}
			}
			out = append(out, fmt.Sprintf("%s: %s uses os.%s, which is not a member of osMembers for the directory", fset.Position(sx.Pos()), dir, sx.Sel.Name))
			return true
		})
	}
	if stale {
		for p, dirs := range stdCapabilities {
			for d := range dirs {
				if !usedCap[p][d] {
					out = append(out, fmt.Sprintf("stdCapabilities lists %s for %s, which does not import it: remove the entry", p, d))
				}
			}
		}
		for dir, ms := range osMembers {
			for _, m := range ms {
				if !usedOS[dir][m] {
					out = append(out, fmt.Sprintf("osMembers lists os.%s for %s, which does not use it: remove the entry", m, dir))
				}
			}
		}
		for p := range moduleStdSafe {
			if !usedSafe[p] && !strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
				out = append(out, "moduleStdSafe lists "+p+", which no non-test file imports: remove the entry")
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func TestNoDirectoryReachesMemoryOrAProcessUnlisted(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, "os")
	if !ok {
		t.Fatal("type information unavailable")
	}
	for _, p := range capabilityProblems(fset, files, info, true) {
		t.Error(p)
	}
}

// buildFileProblems reports every package whose directory holds a file the Go toolchain builds in
// besides Go source. The toolchain's own classification (go list) is the source of truth, so a new
// extension it learns is covered, and a file the lint never parses (C, assembly, an object) cannot
// ride along in a package that looks clean.
func buildFileProblems(root string) []string {
	cmd := exec.Command("go", "list", "-find", "-e", "-f",
		"{{.Dir}}|{{join .CgoFiles \",\"}}|{{join .CFiles \",\"}}|{{join .CXXFiles \",\"}}|{{join .MFiles \",\"}}|{{join .HFiles \",\"}}|{{join .FFiles \",\"}}|{{join .SFiles \",\"}}|{{join .SwigFiles \",\"}}|{{join .SwigCXXFiles \",\"}}|{{join .SysoFiles \",\"}}", "./...")
	cmd.Dir = root
	// With cgo off a file that imports "C" is left out of the package and is listed under no kind at
	// all; the question is what the toolchain WOULD build in, so it is asked with cgo on, whatever the
	// host has set.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	b, err := cmd.Output()
	if err != nil {
		return []string{"go list failed: " + err.Error()}
	}
	return foreignFromList(root, string(b))
}

// foreignFromList reads the lines of the go list template of buildFileProblems.
func foreignFromList(root, listing string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(listing), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) < 2 {
			continue
		}
		for _, p := range parts[1:] {
			if p != "" {
				rel, err := filepath.Rel(root, parts[0])
				if err != nil {
					rel = parts[0]
				}
				out = append(out, filepath.ToSlash(rel)+": builds "+p+", a file that is not Go source; C, assembly and objects are compiled into the package and no lint reads them (sms-r16-21)")
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestNoPackageBuildsAFileThatIsNotGoSource(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	for _, p := range buildFileProblems(repoRoot(t)) {
		t.Error(p)
	}
}

// TestBuildFileListingCanFail feeds the reader of the go list template a line for each kind of file
// the toolchain builds in, and a clean one.
func TestBuildFileListingCanFail(t *testing.T) {
	root := filepath.Join(os.TempDir(), "r")
	dir := filepath.Join(root, "internal", "x")
	for i, name := range []string{"cgo", "c", "cxx", "m", "h", "f", "s", "swig", "swigcxx", "syso"} {
		cols := make([]string, 10)
		cols[i] = name + ".file"
		line := dir + "|" + strings.Join(cols, "|")
		if got := foreignFromList(root, line); len(got) != 1 {
			t.Errorf("a %s file in the listing was reported %d times: %v", name, len(got), got)
		}
	}
	if got := foreignFromList(root, dir+"|||||||||||"); len(got) != 0 {
		t.Errorf("a clean package has problems: %v", got)
	}
}

// harnessImportsOf and the production list: see packageClassProblems.

// packageClassProblems makes every directory with non-test Go source one of two things: a
// production package (listed in testdata/packages.golden) or a test harness (harnessPackages, with
// its reason). A directory that is neither fails, whatever it is called (sms-r16-22): the earlier
// check flagged a package whose directory began or ended with "test", and a harness called mocks,
// fakegw or fixtures that shipped its own certificate authority was in neither list and was not
// named like one. Now a new directory starts refused until somebody says which it is, and the
// import ban (testOnlyProblems) applies to the declared harnesses.
func packageClassProblems(dirs map[string]bool, production map[string]bool) []string {
	var out []string
	for dir := range dirs {
		if strings.Contains("/"+dir+"/", "/testdata/") {
			continue
		}
		_, harness := underAny(dir, harnessPackages)
		switch {
		case harness && production[dir]:
			out = append(out, dir+": listed as a production package and declared a harness; it is one or the other")
		case !harness && !production[dir]:
			out = append(out, dir+": a directory with Go source that is neither in testdata/packages.golden nor in harnessPackages; decide which it is (a harness that production code must not import is declared in harnessPackages with its reason)")
		}
	}
	for dir := range production {
		if !dirs[dir] {
			out = append(out, "testdata/packages.golden lists "+dir+", which has no non-test Go source: remove the line")
		}
	}
	sort.Strings(out)
	return out
}

func readProductionGolden(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "lint", "testdata", "packages.golden"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out[l] = true
		}
	}
	return out
}

func TestEveryPackageIsProductionOrADeclaredHarness(t *testing.T) {
	_, files := parseRepo(t)
	dirs := map[string]bool{}
	for _, f := range files {
		if !f.test {
			dirs[dirOf(f.path)] = true
		}
	}
	for _, p := range packageClassProblems(dirs, readProductionGolden(t)) {
		t.Error(p)
	}
}

func TestPackageClassLintCanFail(t *testing.T) {
	dirs := map[string]bool{"internal/a": true, "internal/testpg": true, "internal/fakegw": true}
	prod := map[string]bool{"internal/a": true}
	got := packageClassProblems(dirs, prod)
	if len(got) != 1 || !strings.Contains(got[0], "internal/fakegw") {
		t.Errorf("an undeclared package called fakegw: %v", got)
	}
	for _, name := range []string{"mocks", "stub", "fixtures", "smstest", "testfake"} {
		d := map[string]bool{"internal/a": true, "internal/testpg": true, "internal/" + name: true}
		if got := packageClassProblems(d, prod); len(got) != 1 {
			t.Errorf("an undeclared package called %s: %v", name, got)
		}
	}
	if got := packageClassProblems(map[string]bool{"internal/a": true, "internal/testpg": true}, prod); len(got) != 0 {
		t.Errorf("a classified tree has problems: %v", got)
	}
	if got := packageClassProblems(map[string]bool{"internal/testpg": true}, prod); len(got) != 1 {
		t.Errorf("a golden line with no source: %v", got)
	}
	both := map[string]bool{"internal/a": true, "internal/testpg": true}
	if got := packageClassProblems(both, map[string]bool{"internal/a": true, "internal/testpg": true}); len(got) != 1 {
		t.Errorf("a package that is production and harness: %v", got)
	}
	if got := packageClassProblems(map[string]bool{"internal/a": true, "internal/a/testdata": true, "internal/testpg": true}, prod); len(got) != 0 {
		t.Errorf("a testdata directory is data: %v", got)
	}
}

// TestCapabilityLintCanFail plants every way a file of ANY directory reaches memory or a process the
// type system hides, and the clean uses, so the guard is shown to fail and to pass. The directories
// are the worker and the admin routes on purpose: the places that hold the built sender.
func TestCapabilityLintCanFail(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"unsafe in the worker", "internal/worker/smssend/x.go", `import "unsafe"
var _ unsafe.Pointer`, 1},
		{"unsafe imported blank", "internal/adminapi/x.go", `import _ "unsafe"`, 1},
		{"unsafe imported under an alias", "internal/app/x.go", `import u "unsafe"
var _ u.Pointer`, 1},
		{"syscall in the api", "internal/api/x.go", `import _ "syscall"`, 1},
		{"os/exec in the admin console", "internal/admincli/x.go", `import _ "os/exec"`, 1},
		{"plugin", "internal/store/x.go", `import _ "plugin"`, 1},
		{"cgo", "internal/httpx/x.go", `import "C"`, 1},
		{"a package nobody listed", "internal/api/x.go", `import _ "archive/zip"`, 1},
		{"io/ioutil", "internal/api/x.go", `import _ "io/ioutil"`, 1},
		{"runtime in a directory not listed", "internal/api/x.go", `import _ "runtime"`, 1},
		{"os/signal in a directory not listed", "internal/api/x.go", `import _ "os/signal"`, 1},
		{"testing in production", "internal/api/x.go", `import _ "testing"`, 1},
		{"httptest in production", "internal/api/x.go", `import _ "net/http/httptest"`, 1},
		{"os in a directory not listed", "internal/api/x.go", `import "os"
func f() { os.Exit(1) }`, 2},
		{"os imported with a dot", "internal/sms/noop/x.go", `import . "os"
func f() { OpenFile("x", O_APPEND, 0) }`, 1},
		{"os.StartProcess in a listed directory", "internal/sms/noop/x.go", `import "os"
func f() { os.StartProcess("x", nil, nil) }`, 1},
		{"os through an alias, another member", "internal/secret/x.go", `import o "os"
func f() { o.OpenFile("/proc/self/mem", 2, 0) }`, 1},
		{"a function with no body", "internal/worker/smssend/x.go", `func raw(x int) int`, 1},
		{"go:linkname", "internal/worker/smssend/x.go", "//go:linkname x y\nvar x int", 1},

		{"os/signal in its directory", "cmd/ctrlz/x.go", `import _ "os/signal"
import _ "syscall"`, 0},
		{"os/exec in the mutation tool", "internal/mutant/x.go", `import _ "os/exec"`, 0},
		{"a listed os member", "internal/secret/x.go", `import "os"
func f() { os.ReadFile("x") }`, 0},
		{"the safe standard packages", "internal/api/x.go", `import (_ "net/http"; _ "encoding/json"; _ "context"; _ "time")`, 0},
		{"reflect is judged by its own list", "internal/api/x.go", `import _ "reflect"`, 0},
		{"a test file may import anything", "internal/api/x_test.go", `import _ "unsafe"
import _ "os/exec"`, 0},
		{"a third party library is another list", "internal/api/x.go", `import _ "github.com/google/uuid"`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		fs := parsePlanted(t, fset, []planted{{c.path, c.src}})
		if strings.HasSuffix(c.path, "_test.go") {
			fs = append(fs, parsePlanted(t, fset, []planted{{"internal/zz/z.go", `var Z int`}})...)
		}
		info, ok := typeInfoReal(fset, fs)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got := capabilityProblems(fset, fs, info, false)
		if (c.want == 0) != (len(got) == 0) {
			t.Errorf("%s: %d problems, want %d or more: %v", c.name, len(got), c.want, got)
		}
	}
	// A stale entry fails: with no importer of runtime/debug anywhere the entry is a free pass.
	fset := token.NewFileSet()
	fs := parsePlanted(t, fset, []planted{{"internal/api/x.go", `var X int`}})
	info, _ := typeInfoReal(fset, fs)
	stale := 0
	for _, p := range capabilityProblems(fset, fs, info, true) {
		if strings.Contains(p, "which does not") || strings.Contains(p, "which no non-test file imports") {
			stale++
		}
	}
	if stale == 0 {
		t.Error("stale entries of the capability lists were not reported")
	}
}

// The scoped list of the gateway packages is stricter than the module-wide one, and a member the
// first allows must be allowed by the second too, or one of the two lists is stale.
func TestScopedOSMembersAreMembersOfTheModuleList(t *testing.T) {
	for dir, ms := range smsOSMembers {
		for _, m := range ms {
			found := false
			for _, x := range osMembers[dir] {
				found = found || x == m
			}
			if !found {
				t.Errorf("smsOSMembers allows os.%s for %s and osMembers does not", m, dir)
			}
		}
	}
}

// TestBuildFileCheckSeesEveryFileTheToolchainBuildsIn runs the real go list over a scratch module that
// holds one package for each kind of file besides Go source, so the template of buildFileProblems is
// shown to name them (a column dropped from it would let that kind through), and a package of Go
// files alone is clean.
func TestBuildFileCheckSeesEveryFileTheToolchainBuildsIn(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module scratch\n\ngo 1.22\n")
	for _, d := range []string{"clean", "asm", "hdr", "obj", "cgo"} {
		write(d+"/a.go", "package "+d+"\n")
	}
	write("asm/a.s", "// assembly\n")
	write("hdr/a.h", "/* header */\n")
	write("obj/a.syso", "x")
	write("cgo/a.go", "package cgo\n\n// int f(void) { return 0; }\nimport \"C\"\n")
	got := buildFileProblems(root)
	for _, want := range []string{"asm: builds a.s", "hdr: builds a.h", "obj: builds a.syso", "cgo: builds a.go"} {
		found := false
		for _, g := range got {
			found = found || strings.Contains(g, want)
		}
		if !found {
			t.Errorf("no problem for %q in %v", want, got)
		}
	}
	for _, g := range got {
		if strings.Contains(g, "clean:") {
			t.Errorf("a package of Go files alone was reported: %s", g)
		}
	}
}
