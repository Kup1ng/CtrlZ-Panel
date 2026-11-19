package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The argon2-memory-budget rule (P1 auth review round 5, rules.md topic 22, spec
// 4.1). Argon2 memory was allocated outside any budget three times: a stored hash
// that asked for 256 MiB, an environment pair below OWASP's minimum, and the
// console tool's eager full-cost dummy hash inside the admin container's cgroup.
// The structure that removes the class is one function, Gate.derive in
// internal/auth/password/gate.go: it refuses a run larger than one slot of the
// budget, waits for a slot, and only then calls argon2.IDKey. This file keeps that
// true:
//
//   - TestArgon2OnlyInTheGate: the argon2 package is imported only by the password
//     package, and no function but Gate.derive calls anything of it. Test files are
//     covered too: a test that hashes on the side is a run outside the budget in CI.
//   - TestArgon2HasherOnlyFromSettings: a service gets its Hasher from
//     password.Settings, which owns the floor and the budget, never from the bare
//     constructor that tests use.
//   - TestComposeGivesEveryHashingServiceItsShare: the budget the code enforces is
//     the one the container's memory limit allows.
//
// The behaviour half (nothing is allocated before first use, every run waits for
// the gate) is internal/auth/password TestHasherAllocatesNothingBeforeFirstUse and
// TestEveryRunWaitsForTheGate, and internal/app TestNoEntryPointAllocatesArgon2.

const (
	argon2Import  = "golang.org/x/crypto/argon2"
	passwordDir   = "internal/auth/password/"
	argon2GateFn  = "internal/auth/password/gate.go"
	argon2PHCFile = "internal/auth/password/password.go"
)

// argon2Problems reports every use of the argon2 package in one file that the rule
// does not allow. path is repository relative with forward slashes.
func argon2Problems(path string, f *ast.File) []string {
	var out []string
	local := ""
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p != argon2Import {
			continue
		}
		local = "argon2"
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if !strings.HasPrefix(path, passwordDir) {
			out = append(out, path+" imports "+argon2Import+"; only internal/auth/password may, behind its gate")
		}
		if local == "." || local == "_" {
			out = append(out, path+" imports the argon2 package as "+local+", which hides its calls from this lint")
		}
	}
	if local == "" || local == "." || local == "_" {
		return out
	}
	for _, d := range f.Decls {
		fd, isFn := d.(*ast.FuncDecl)
		inDerive := isFn && path == argon2GateFn && fd.Name.Name == "derive" && recvIs(fd, "Gate")
		ast.Inspect(d, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != local || x.Obj != nil {
				return true
			}
			switch {
			case sel.Sel.Name == "Version" && path == argon2PHCFile:
				// The PHC string names the version; a constant allocates nothing.
			case inDerive:
			default:
				where := "package level"
				if isFn {
					where = "func " + fd.Name.Name
				}
				out = append(out, path+": "+local+"."+sel.Sel.Name+" in "+where+"; Argon2 runs only in (*Gate).derive, which keeps the budget")
			}
			return true
		})
	}
	return out
}

func recvIs(fd *ast.FuncDecl, typ string) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	id, ok := t.(*ast.Ident)
	return ok && id.Name == typ
}

func TestArgon2OnlyInTheGate(t *testing.T) {
	_, files := parseRepo(t)
	seen := false
	for _, f := range files {
		for _, imp := range f.ast.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == argon2Import {
				seen = true
			}
		}
		for _, p := range argon2Problems(f.path, f.ast) {
			t.Error(p)
		}
	}
	if !seen {
		t.Error("no file imports the argon2 package: the lint looks at the wrong files, or the import path changed")
	}
	// derive must exist and call IDKey, or the rule has no place to stand.
	for _, f := range files {
		if f.path != argon2GateFn {
			continue
		}
		found := false
		for _, d := range f.ast.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "derive" && recvIs(fd, "Gate") {
				ast.Inspect(fd, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "IDKey" {
						found = true
					}
					return true
				})
			}
		}
		if !found {
			t.Errorf("%s has no (*Gate).derive that calls IDKey", argon2GateFn)
		}
	}
}

func parseOne(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestArgon2LintCanFail plants each way the rule can be broken, and the clean shapes
// that must stay clean, so the lint is itself shown to fail.
func TestArgon2LintCanFail(t *testing.T) {
	const head = "package p\nimport \"golang.org/x/crypto/argon2\"\n"
	for name, c := range map[string]struct {
		path, src string
		bad       bool
	}{
		"the gate's own derive":             {argon2GateFn, head + "type Gate struct{}\nfunc (g *Gate) derive() { argon2.IDKey(nil, nil, 1, 8, 1, 32) }\n", false},
		"the PHC version":                   {argon2PHCFile, head + "func encode() int { return argon2.Version }\n", false},
		"another function of the gate file": {argon2GateFn, head + "type Gate struct{}\nfunc (g *Gate) other() { argon2.IDKey(nil, nil, 1, 8, 1, 32) }\n", true},
		"a function named derive elsewhere": {argon2GateFn, head + "func derive() { argon2.IDKey(nil, nil, 1, 8, 1, 32) }\n", true},
		"derive of another type":            {argon2GateFn, head + "type H struct{}\nfunc (h *H) derive() { argon2.IDKey(nil, nil, 1, 8, 1, 32) }\n", true},
		"derive in another file":            {passwordDir + "password.go", head + "type Gate struct{}\nfunc (g *Gate) derive() { argon2.IDKey(nil, nil, 1, 8, 1, 32) }\n", true},
		"NewHasher computing its dummy":     {argon2PHCFile, head + "func NewHasher() { _ = argon2.IDKey(nil, nil, 2, 47104, 1, 32) }\n", true},
		"the other key function":            {argon2GateFn, head + "type Gate struct{}\nfunc (g *Gate) other() { argon2.Key(nil, nil, 1, 8, 1, 32) }\n", true},
		"a package-level value":             {argon2PHCFile, head + "var x = argon2.IDKey\n", true},
		"the version outside password.go":   {argon2GateFn, head + "func f() int { return argon2.Version }\n", true},
		"another package imports it":        {"internal/store/x.go", head + "var _ = 1\n", true},
		"a test file in the package":        {passwordDir + "x_test.go", head + "func TestX() { argon2.IDKey(nil, nil, 1, 8, 1, 32) }\n", true},
		"a dot import":                      {argon2GateFn, "package p\nimport . \"golang.org/x/crypto/argon2\"\nvar _ = 1\n", true},
		"an alias":                          {argon2GateFn, "package p\nimport a2 \"golang.org/x/crypto/argon2\"\ntype Gate struct{}\nfunc (g *Gate) other() { a2.IDKey(nil, nil, 1, 8, 1, 32) }\n", true},
		"a local that shadows the package":  {argon2GateFn, head + "func f() { argon2 := struct{ IDKey func() }{}; argon2.IDKey() }\n", false},
	} {
		got := argon2Problems(c.path, parseOne(t, c.src))
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: problems %v, want bad=%v", name, got, c.bad)
		}
	}
}

// hasherFromSettingsProblems: outside the password package and the test support, no
// non-test file builds a Hasher with the bare constructor or writes a Settings
// literal. The bare constructor checks that the parameters fit the gate's budget,
// but the floor is Settings'; a service that skipped Settings could run below
// OWASP's minimum.
func hasherFromSettingsProblems(path string, f *ast.File) []string {
	if strings.HasPrefix(path, passwordDir) || strings.HasPrefix(path, "internal/authtest/") || strings.HasSuffix(path, "_test.go") {
		return nil
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "password" && x.Sel.Name == "NewHasher" {
				out = append(out, path+": password.NewHasher; build the Hasher with password.Settings.NewHasher, which owns the floor and the budget")
			}
		case *ast.CompositeLit:
			if sel, ok := x.Type.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "password" && sel.Sel.Name == "Settings" {
					out = append(out, path+": a password.Settings literal; read it with password.FromEnv, which validates it")
				}
			}
		}
		return true
	})
	return out
}

func TestArgon2HasherOnlyFromSettings(t *testing.T) {
	_, files := parseRepo(t)
	viaSettings := false
	for _, f := range files {
		for _, p := range hasherFromSettingsProblems(f.path, f.ast) {
			t.Error(p)
		}
		if f.path != "internal/app/runtime.go" {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewHasher" && len(call.Args) == 0 {
					viaSettings = true
				}
			}
			return true
		})
	}
	if !viaSettings {
		t.Error("internal/app/runtime.go no longer calls Settings.NewHasher: the services get their hasher some other way")
	}
}

func TestArgon2HasherLintCanFail(t *testing.T) {
	for name, c := range map[string]struct {
		path, src string
		bad       bool
	}{
		"the bare constructor in a service": {"internal/app/runtime.go", "package p\nvar _ = password.NewHasher(a, b)\n", true},
		"a Settings literal":                {"internal/app/config.go", "package p\nvar _ = password.Settings{}\n", true},
		"Settings.NewHasher":                {"internal/app/runtime.go", "package p\nvar _ = cfg.Argon2.NewHasher()\n", false},
		"a test":                            {"internal/api/x_test.go", "package p\nvar _ = password.NewHasher(a, b)\n", false},
		"the test support":                  {"internal/authtest/authtest.go", "package p\nvar _ = password.NewHasher(a, b)\n", false},
	} {
		got := hasherFromSettingsProblems(c.path, parseOne(t, c.src))
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: problems %v, want bad=%v", name, got, c.bad)
		}
	}
}

// composeShareProblems reads the Compose text of the services that run Argon2 and
// checks that each states a budget (CTRLZ_ARGON2_BUDGET_MIB) below its Go memory
// limit, and that the gate size times the default hash cost fits in it. The code
// refuses a setting that does not fit the budget; this keeps the budget itself
// honest about the container.
func composeShareProblems(compose string, profiles map[string]string) []string {
	var out []string
	block := func(name string) string {
		re := regexp.MustCompile(`(?m)^  ` + name + `:\n((?:    .*\n|\n)*)`)
		if m := re.FindStringSubmatch(compose); m != nil {
			return m[1]
		}
		return ""
	}
	num := func(re, s string) (int, bool) {
		m := regexp.MustCompile(re).FindStringSubmatch(s)
		if m == nil {
			return 0, false
		}
		n, _ := strconv.Atoi(m[1])
		return n, true
	}
	const hashMiB = 46 // the default cost, 47104 KiB
	for _, svc := range []struct{ name, memlimit string }{{"api", "GOMEMLIMIT"}, {"admin", "GOMEMLIMIT"}} {
		b := block(svc.name)
		budget, ok := num(`CTRLZ_ARGON2_BUDGET_MIB: (?:\$\{\w+:-)?(\d+)`, b)
		if !ok {
			out = append(out, "docker-compose.yml: service "+svc.name+" sets no CTRLZ_ARGON2_BUDGET_MIB; its share of the container's memory is the code default of 192 MiB")
			continue
		}
		limit, ok := num(`GOMEMLIMIT: \$\{\w+:-(\d+)MiB`, b)
		if !ok {
			out = append(out, "docker-compose.yml: service "+svc.name+" has no GOMEMLIMIT default")
			continue
		}
		conc, ok := num(`CTRLZ_ARGON2_CONCURRENCY: (?:\$\{\w+:-)?"?(\d+)`, b)
		if !ok {
			out = append(out, "docker-compose.yml: service "+svc.name+" has no CTRLZ_ARGON2_CONCURRENCY")
			continue
		}
		if budget >= limit {
			out = append(out, "docker-compose.yml: "+svc.name+" budget "+strconv.Itoa(budget)+" MiB is not below GOMEMLIMIT "+strconv.Itoa(limit)+" MiB")
		}
		if conc*hashMiB > budget {
			out = append(out, "docker-compose.yml: "+svc.name+" "+strconv.Itoa(conc)+" slots of 46 MiB do not fit its budget of "+strconv.Itoa(budget)+" MiB")
		}
	}
	for file, text := range profiles {
		budget, hasBudget := num(`(?m)^CTRLZ_API_ARGON2_BUDGET_MIB=(\d+)`, text)
		conc, _ := num(`(?m)^CTRLZ_API_ARGON2_CONCURRENCY=(\d+)`, text)
		limit, _ := num(`(?m)^GOMEMLIMIT_API=(\d+)MiB`, text)
		if !hasBudget {
			budget = 128 // the compose default of the api service
		}
		if budget >= limit || conc*hashMiB > budget {
			out = append(out, "profiles/"+file+": api budget "+strconv.Itoa(budget)+" MiB with "+strconv.Itoa(conc)+" slots and GOMEMLIMIT "+strconv.Itoa(limit)+" MiB do not fit")
		}
	}
	return out
}

func TestComposeGivesEveryHashingServiceItsShare(t *testing.T) {
	compose := readDeploy(t, "docker-compose.yml")
	profiles := map[string]string{}
	for _, n := range []string{"small.env", "standard.env"} {
		profiles[n] = readDeploy(t, "profiles", n)
	}
	for _, p := range composeShareProblems(compose, profiles) {
		t.Error(p)
	}
	// The bad shapes it exists for.
	bad := strings.ReplaceAll(compose, "CTRLZ_ARGON2_BUDGET_MIB: ${CTRLZ_ADMIN_ARGON2_BUDGET_MIB:-64}", "CTRLZ_ARGON2_BUDGET_MIB: ${CTRLZ_ADMIN_ARGON2_BUDGET_MIB:-192}")
	if bad == compose || len(composeShareProblems(bad, profiles)) == 0 {
		t.Error("a 192 MiB budget in the 96 MiB admin container passes the compose check")
	}
	if len(composeShareProblems(strings.ReplaceAll(compose, "CTRLZ_ARGON2_BUDGET_MIB", "CTRLZ_ARGON2_BUDGET_X"), profiles)) == 0 {
		t.Error("a service with no budget passes the compose check")
	}
}
