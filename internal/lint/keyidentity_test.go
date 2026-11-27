package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Rule key-identity (P1 auth review round 5, rules.md topic 23, spec 8.3 to 8.5):
// no key tool decides which key it has from a key number or from a file being there or
// missing. The scenario matrix in internal/admincli (keyidentity_test.go) runs every
// key command over generated key histories and compares it with the ground truth.
// This lint closes what a matrix cannot enumerate: a new code path that reaches for
// the shortcuts again.
//
//  1. scripts/gen-secrets.sh names no kek_ file but kek_root in a command. Which
//     files belong to the root is `ctrlz keys derive`'s answer.
//  2. The key tools (internal/admincli, internal/keyring/file.go) do not stat a file.
//     They read it, and what they read is proved against the root.
//  3. A function of internal/admincli that reads the key number off a ciphertext
//     (keyring.KeyNumber) also opens a value or takes the answer of an open as its
//     input. A number is a claim; only opening proves it.

func TestKeyToolsDecideNothingFromANumberOrAFile(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "scripts", "gen-secrets.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range scriptKeyFileUses(string(src)) {
		t.Errorf("scripts/gen-secrets.sh: %s", v)
	}
	_, files := parseRepo(t)
	seen := 0
	for _, f := range files {
		if f.test || !(strings.HasPrefix(f.path, "internal/admincli/") || f.path == "internal/keyring/file.go") {
			continue
		}
		seen++
		for _, v := range keyToolViolations(f.ast) {
			t.Errorf("%s: %s", f.path, v)
		}
	}
	if seen < 4 {
		t.Fatalf("the lint saw %d key tool files; the paths moved", seen)
	}
}

// scriptKeyFileUses reports every line of a shell script that acts on a kek_ file other
// than kek_root. Comments and the words of a message do not count.
func scriptKeyFileUses(src string) []string {
	var out []string
	for i, ln := range strings.Split(src, "\n") {
		code := strings.TrimSpace(ln)
		if code == "" || strings.HasPrefix(code, "#") || strings.HasPrefix(code, "echo ") {
			continue
		}
		for rest := code; ; {
			j := strings.Index(rest, "kek_")
			if j < 0 {
				break
			}
			rest = rest[j+len("kek_"):]
			if !strings.HasPrefix(rest, "root") {
				out = append(out, "line "+strconv.Itoa(i+1)+" acts on a kek_ file ("+code+"); whether key files belong to the root is the derive's proof, not a test of a name")
				break
			}
		}
	}
	return out
}

// keyToolViolations applies rules 2 and 3 to one file.
func keyToolViolations(f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		hasKeyNumber, proves := false, false
		for _, p := range fd.Type.Params.List {
			for _, n := range p.Names {
				if n.Name == "opens" || n.Name == "open" {
					proves = true // the answer of an open, or the open itself, is an input
				}
			}
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok && x.Name == "os" && (fn.Sel.Name == "Stat" || fn.Sel.Name == "Lstat") {
					out = append(out, fd.Name.Name+" calls os."+fn.Sel.Name+"; a key tool reads the file and proves what it read, it does not decide from the file being there")
				}
				switch fn.Sel.Name {
				case "KeyNumber":
					hasKeyNumber = true
				case "Open", "OpenCredentials", "Identify":
					proves = true
				}
			case *ast.Ident:
				switch fn.Name {
				case "opensWith", "open":
					proves = true
				}
			}
			return true
		})
		if hasKeyNumber && !proves {
			out = append(out, fd.Name.Name+" reads a key number off a ciphertext and never opens a value; the number is a claim, only opening proves it")
		}
	}
	return out
}

// TestKeyIdentityLintCanFail plants each shortcut and requires the lint to see it.
func TestKeyIdentityLintCanFail(t *testing.T) {
	scripts := []struct {
		name, src string
		bad       bool
	}{
		{"the shipped idiom, a glob over key files", "for f in \"$dir\"/kek_*; do\n  if [ -e \"$f\" ]; then exit 1; fi\ndone\n", true},
		{"a size test of one key file", "[ -s \"$dir/kek_$d\" ] || need=1\n", true},
		{"a named key file", "[ -e \"$dir/kek_user_totp\" ]\n", true},
		{"the root itself", "root=\"$dir/kek_root\"\n[ -e \"$root\" ]\n", false},
		{"a message and a comment", "# kek_ files\necho \"secrets: kek_user_totp missing\" >&2\n", false},
	}
	for _, tc := range scripts {
		if got := len(scriptKeyFileUses(tc.src)) > 0; got != tc.bad {
			t.Errorf("script %q: flagged = %v, want %v", tc.name, got, tc.bad)
		}
	}
	funcs := []struct {
		name, src string
		bad       bool
	}{
		{"a refusal by number alone", `package p
func refuses(r *Ring, ct []byte, want int) bool {
	n, _ := keyring.KeyNumber(ct)
	return int(n) == want && r.Has("x")
}`, true},
		{"a stat of a key file", `package p
func exists(p string) bool { _, err := os.Stat(p); return err == nil }`, true},
		{"a lstat", `package p
func exists(p string) bool { _, err := os.Lstat(p); return err == nil }`, true},
		{"the number then an open", `package p
func ok(r *Ring, ct []byte) bool {
	if n, ok := keyring.KeyNumber(ct); ok && n == 1 {
		_, err := r.Open("d", nil, ct)
		return err == nil
	}
	return false
}`, false},
		{"the number with the answer of an open as input", `package p
func add(ct []byte, opens bool) { n, _ := keyring.KeyNumber(ct); _ = n; _ = opens }`, false},
	}
	for _, tc := range funcs {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(keyToolViolations(f)) > 0; got != tc.bad {
			t.Errorf("func %q: flagged = %v, want %v", tc.name, got, tc.bad)
		}
	}
}
