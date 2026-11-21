// Command plan computes the test and mutant matrices of the GitHub run from the
// tree that was checked out, and PROVES the partitions before anything runs.
//
//	go run ./.github/ci/plan plan  -out plan.json   compute the shards
//	go run ./.github/ci/plan prove -in  plan.json   recompute the universe and check the file against it
//	  [-outputs $GITHUB_OUTPUT]                     and read the matrices the jobs run back from the step outputs
//	go run ./.github/ci/plan local-mutants          the workspace mutant ids, comma separated
//
// Why it exists. The local CI runs one `go test ./...` and one `tools/mutants` over the
// whole tree. On GitHub the same work is cut into shards that run on separate machines, and
// a cut that loses a package, a test or a mutant fails nothing by itself: the missing piece
// simply never runs, and the run is green. So the cut is computed from the tree (it adapts
// to any commit) and `prove` checks it a second time from the tree, not from the planner's
// own variables: every package of `go list ./...` is in exactly one test shard, every test
// of internal/api is selected by exactly one shard (judged with the shards' own -run and
// -skip patterns, so a typo in a name cannot pass), and every mutant of mutants.yaml is in
// exactly one shard or is named as left to the local run.
//
// The directory starts with a dot, so `./...` skips it: neither the test partition nor the
// vet of ci.sh ever sees these helpers.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Plan is the file `plan` writes and `prove` reads.
type Plan struct {
	Version      int           `json:"version"`
	Module       string        `json:"module"`
	Packages     []string      `json:"packages"` // every package of go list ./..., relative to the module root
	API          APIPlan       `json:"api"`
	TestShards   []TestShard   `json:"test_shards"`
	MutantShards []MutantShard `json:"mutant_shards"`
	AllMutants   []string      `json:"all_mutants"`
	LocalMutants []string      `json:"local_mutants"` // workspace mutants: they need documents that are not in this repository
}

// APIPlan records how internal/api was cut and why, so a reader of the summary can see it.
type APIPlan struct {
	Package   string   `json:"package"`
	List      []string `json:"list"`        // go test -list of the package, default build tags
	Split     []string `json:"split"`       // tests that get a machine of their own
	SplitWhy  []string `json:"split_why"`   // the reason of each, same order
	NotInList []string `json:"not_in_list"` // detected as oracle or timing tests but not built here (a build tag): not run by ci.sh either
	RestSkip  string   `json:"rest_skip"`
	RestTests []string `json:"rest_tests"`
}

// TestShard is one `go test` invocation on one machine.
type TestShard struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"` // packages | api-split | api-rest
	Packages       []string `json:"packages"`
	Run            string   `json:"run,omitempty"`
	Skip           string   `json:"skip,omitempty"`
	Tests          []string `json:"tests,omitempty"` // top-level tests that must each have run and passed (api shards)
	NeedsImage     bool     `json:"needs_image"`     // a package of the shard inspects ctrlz/panel:dev
	Parallel       int      `json:"parallel"`        // go test -p
	TimeoutMinutes int      `json:"timeout_minutes"`
	Weight         int      `json:"weight_seconds"` // estimate, for ordering and balance only
}

// MutantShard is one `tools/mutants -only` invocation on one machine.
type MutantShard struct {
	ID             string   `json:"id"`
	IDs            []string `json:"ids"`
	Groups         int      `json:"groups"`
	Jobs           int      `json:"jobs"`
	TimeoutMinutes int      `json:"timeout_minutes"`
	Weight         int      `json:"weight_seconds"`
}

// Weights is the optional .github/ci/weights.json: estimates in seconds, refreshed by hand
// from the shard table of a run. A wrong estimate only unbalances the shards.
type Weights struct {
	TestPackages  map[string]int `json:"test_packages"`
	DefaultPlain  int            `json:"default_plain_package"`
	DefaultDocker int            `json:"default_container_package"`
	Mutant        struct {
		PlainBaseline  int `json:"plain_baseline"`
		PlainRun       int `json:"plain_run"`
		DockerBaseline int `json:"docker_baseline"`
		DockerRun      int `json:"docker_run"`
	} `json:"mutant"`
	// MutantSeconds is the measured cost of one mutant (all of its must_fail runs, as if run alone), for the few
	// whose cost is far from the class default: a Valkey or Postgres start-up that the test waits for makes one mutant
	// worth ten (CI review round 13, ci-r13-7). An id that no longer exists is ignored.
	MutantSeconds    map[string]int `json:"mutant_seconds"`
	APIRestSeconds   int            `json:"api_rest"`
	APISplitSeconds  int            `json:"api_split"`
	PackageShardSecs int            `json:"package_shard_target"`
	MutantShardSecs  int            `json:"mutant_shard_target"`
	MaxPackageShards int            `json:"max_package_shards"`
	MaxMutantShards  int            `json:"max_mutant_shards"`
}

func defaultWeights() Weights {
	w := Weights{DefaultPlain: 15, DefaultDocker: 90, APIRestSeconds: 3300, APISplitSeconds: 150,
		PackageShardSecs: 900, MutantShardSecs: 1500, MaxPackageShards: 6, MaxMutantShards: 6}
	w.Mutant.PlainBaseline, w.Mutant.PlainRun, w.Mutant.DockerBaseline, w.Mutant.DockerRun = 20, 12, 70, 45
	return w
}

func loadWeights(root string) Weights {
	w := defaultWeights()
	b, err := os.ReadFile(filepath.Join(root, ".github", "ci", "weights.json"))
	if err != nil {
		return w
	}
	var f Weights
	if err := json.Unmarshal(b, &f); err != nil {
		fatalf("weights.json: %v", err)
	}
	// Only the keys the file sets replace the defaults.
	if f.TestPackages != nil {
		w.TestPackages = f.TestPackages
	}
	if f.MutantSeconds != nil {
		w.MutantSeconds = f.MutantSeconds
	}
	set := func(dst *int, v int) {
		if v > 0 {
			*dst = v
		}
	}
	set(&w.DefaultPlain, f.DefaultPlain)
	set(&w.DefaultDocker, f.DefaultDocker)
	set(&w.Mutant.PlainBaseline, f.Mutant.PlainBaseline)
	set(&w.Mutant.PlainRun, f.Mutant.PlainRun)
	set(&w.Mutant.DockerBaseline, f.Mutant.DockerBaseline)
	set(&w.Mutant.DockerRun, f.Mutant.DockerRun)
	set(&w.APIRestSeconds, f.APIRestSeconds)
	set(&w.APISplitSeconds, f.APISplitSeconds)
	set(&w.PackageShardSecs, f.PackageShardSecs)
	set(&w.MutantShardSecs, f.MutantShardSecs)
	set(&w.MaxPackageShards, f.MaxPackageShards)
	set(&w.MaxMutantShards, f.MaxMutantShards)
	return w
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: plan (plan|prove|local-mutants) [-out file | -in file [-outputs step-output-file]]")
	}
	cmd := os.Args[1]
	file := "plan.json"
	outputs := ""
	for i := 2; i+1 < len(os.Args); i++ {
		if os.Args[i] == "-out" || os.Args[i] == "-in" {
			file = os.Args[i+1]
		}
		if os.Args[i] == "-outputs" {
			outputs = os.Args[i+1]
		}
	}
	root, err := os.Getwd()
	if err != nil {
		fatalf("%v", err)
	}
	switch cmd {
	case "plan":
		p := buildPlan(root)
		b, _ := json.MarshalIndent(p, "", "  ")
		if err := os.WriteFile(file, append(b, '\n'), 0o644); err != nil {
			fatalf("%v", err)
		}
		emitOutputs(p)
		writeSummary(p)
		fmt.Printf("plan: %d packages, %d test shards, %d mutants in %d shards, %d left to the local run\n",
			len(p.Packages), len(p.TestShards), len(p.AllMutants)-len(p.LocalMutants), len(p.MutantShards), len(p.LocalMutants))
	case "local-mutants":
		// The ids of mutants.yaml that GitHub leaves to the local run, from the same parser
		// the plan uses, comma separated. The local run reads its list from here and not from
		// a text pattern over the YAML, so the two halves of the split cannot drift apart:
		//   go run <path>/.github/ci/plan/main.go local-mutants     (from the Panel root)
		var ids []string
		for _, m := range loadMutants(root) {
			if m.Workspace {
				ids = append(ids, m.ID)
			}
		}
		sort.Strings(ids)
		fmt.Println(strings.Join(ids, ","))
	case "prove":
		b, err := os.ReadFile(file)
		if err != nil {
			fatalf("%v", err)
		}
		var p Plan
		if err := json.Unmarshal(b, &p); err != nil {
			fatalf("%s: %v", file, err)
		}
		problems := prove(root, &p)
		// -outputs: the step-output file that `plan` wrote on the runner. The matrices the jobs
		// run are read back from it and compared with the plan (ci-r6-2).
		if outputs != "" {
			problems = append(problems, proveOutputs(&p, outputs)...)
		}
		if len(problems) > 0 {
			fmt.Fprintln(os.Stderr, "plan: the partition is NOT proven:")
			for _, s := range problems {
				fmt.Fprintln(os.Stderr, "  - "+s)
			}
			os.Exit(1)
		}
		fmt.Printf("prove: ok. %d packages and %d tests of %s and %d mutants, each in exactly one shard\n",
			len(p.Packages), len(p.API.List), p.API.Package, len(p.AllMutants)-len(p.LocalMutants))
	default:
		fatalf("unknown command %q", cmd)
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "plan: "+format+"\n", a...)
	os.Exit(1)
}

// ---- what the tree says ---------------------------------------------------------------

func run(root string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return out.String(), err
}

func goModule(root string) string {
	out, err := run(root, "list", "-m")
	if err != nil {
		fatalf("go list -m: %v", err)
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0])
}

type pkgInfo struct {
	Rel       string
	Container bool // its tests import a package that starts Postgres or Valkey
	NeedImage bool // its tests inspect the Panel image
}

// listPackages is `go list ./...` with what the planner needs to know about each.
func listPackages(root, module string) []pkgInfo {
	out, err := run(root, "list", "-f", `{{.ImportPath}}|{{.Dir}}|{{join .TestImports ","}},{{join .XTestImports ","}}`, "./...")
	if err != nil {
		fatalf("go list ./...: %v", err)
	}
	var pkgs []pkgInfo
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.SplitN(line, "|", 3)
		if len(f) != 3 {
			fatalf("unexpected go list line %q", line)
		}
		p := pkgInfo{Rel: rel(module, f[0])}
		for _, imp := range strings.Split(f[2], ",") {
			if strings.HasSuffix(imp, "/internal/testpg") || strings.HasSuffix(imp, "/internal/testvalkey") || strings.Contains(imp, "testcontainers") {
				p.Container = true
			}
		}
		p.NeedImage = dirMentionsImage(f[1])
		pkgs = append(pkgs, p)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Rel < pkgs[j].Rel })
	return pkgs
}

// ignoredTestFileReasons are the _test.go files that go leaves out on the runner and that are
// known and accepted, each with its reason. A test file that go leaves out (a _windows_test.go
// suffix on a Linux runner, or a build tag nobody sets) is in no package's test list, so no
// shard runs it, the planner cannot see it and shardrun cannot report on it: it is a test that
// silently never runs, which is what prove exists to catch (CI review round 3, ci-r3-1).
// A function, not a var: internal/lint forbids package-level mutable state in every .go file.
func ignoredTestFileReasons() map[string]string {
	return map[string]string{
		"internal/api/timing_test.go": "build tag timing: opt-in duration probes, not run by scripts/ci.sh either",
	}
}

// unbuiltTestFiles lists the _test.go files of the tree that no package of `go list ./...` builds
// on this machine, as paths relative to the module root. The list of what exists comes from the
// file system and the list of what is built from go's TestGoFiles and XTestGoFiles, so a test file
// is refused for whatever reason go leaves it out: a GOOS suffix, a build tag, a name that starts
// with "_" or "." (go drops such a file without reporting it in IgnoredGoFiles), or a directory go
// does not list. An earlier version read IgnoredGoFiles and so missed the silent cases (CI review
// round 9, ci-r9-4). The walk skips only what go never reads and nothing else: testdata, vendor,
// node_modules, .git, and the directory of a module of its own (strayModules refuses every one
// but shared/, which has its own run). Directories that start with "." or "_" are searched, so a
// test file there is refused too: go never runs it.
func unbuiltTestFiles(root, module string) []string {
	out, err := run(root, "list", "-f", `{{.ImportPath}}|{{join .TestGoFiles ","}},{{join .XTestGoFiles ","}}`, "./...")
	if err != nil {
		fatalf("go list ./... (test files): %v", err)
	}
	built := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		ip, names, ok := strings.Cut(strings.TrimSpace(line), "|")
		if !ok {
			continue
		}
		dir := rel(module, ip)
		for _, f := range strings.Split(names, ",") {
			switch {
			case f == "":
			case dir == ".":
				built[f] = true
			default:
				built[dir+"/"+f] = true
			}
		}
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		r, _ := filepath.Rel(root, path)
		r = filepath.ToSlash(r)
		if d.IsDir() {
			if r == "." {
				return nil
			}
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules":
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), "_test.go") && !built[r] {
			files = append(files, r)
		}
		return nil
	})
	if err != nil {
		fatalf("walking the tree for test files: %v", err)
	}
	sort.Strings(files)
	return files
}

// unlistedGoDirs walks the tree for directories that hold a .go file and that `go list ./...`
// does not list. go list drops a package with no buildable file on this runner (every file is
// _windows.go, or every file sits behind a build tag) without a word, and its IgnoredGoFiles
// never shows it either, because that field belongs to a package that is listed. Such a
// directory is in no shard and in no proof, and its tests never run (CI review round 4,
// ci-r4-1). A directory is accepted only when every one of its .go files is named in `known`.
// The walk skips what `./...` itself skips (testdata, names starting with "." or "_", vendor), a
// directory of a module of its own (its own go.mod: `./...` stops there too; strayModules refuses
// every one but shared/), and node_modules (JS packages carry
// no Go that this module builds).
func unlistedGoDirs(root string, listed map[string]bool, known map[string]string) ([]string, error) {
	files := map[string][]string{} // directory relative to the root -> its .go files
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		r, _ := filepath.Rel(root, path)
		r = filepath.ToSlash(r)
		if d.IsDir() {
			if r == "." {
				return nil
			}
			n := d.Name()
			if n == "testdata" || n == "vendor" || n == "node_modules" || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") {
			dir := filepath.ToSlash(filepath.Dir(r))
			files[dir] = append(files[dir], r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var bad []string
	for dir, fs := range files {
		if listed[dir] {
			continue
		}
		allKnown := true
		for _, f := range fs {
			if _, ok := known[f]; !ok {
				allKnown = false
			}
		}
		if !allKnown {
			bad = append(bad, dir)
		}
	}
	sort.Strings(bad)
	return bad, nil
}

// strayModules lists the go.mod files of the tree that are not the root module's or shared/'s.
// A fail-closed list and not a skip (CI review round 8, ci-r8-2): a module of its own is not in
// `go list ./...` of the root or of shared, so its tests are in no shard and in no job, and the
// walks above that skipped it never saw it. A new module is a reviewed change that adds a job for
// it and then names it here, as in .github/ci/gofiles.sh, which holds the same list for the Node
// and for shared/. What go itself never reads (testdata, vendor, node_modules) and .git are not
// searched.
func strayModules(root string) ([]string, error) {
	var bad []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		r, _ := filepath.Rel(root, path)
		if r = filepath.ToSlash(r); r != "go.mod" && r != "shared/go.mod" {
			bad = append(bad, r)
		}
		return nil
	})
	sort.Strings(bad)
	return bad, err
}

func rel(module, importPath string) string {
	if importPath == module {
		return "."
	}
	return strings.TrimPrefix(importPath, module+"/")
}

// dirMentionsImage says whether a test file of the directory inspects the Panel image. Those
// tests skip when the image is not built (and TestImageSmoke fails on a stale one), so the
// shard that holds the package builds it first, as scripts/ci.sh does.
func dirMentionsImage(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil && (bytes.Contains(b, []byte("CTRLZ_IMAGE")) || bytes.Contains(b, []byte("ctrlz/panel:"))) {
			return true
		}
	}
	return false
}

var listedTest = regexp.MustCompile(`^(Test|Fuzz|Example)[A-Za-z0-9_]*$`)

// listTests is `go test -list` of one package. -short keeps TestMain from starting a
// Postgres container just to print names; the list is the same with and without it.
func listTests(root, pkg string) []string {
	out, err := run(root, "test", "-short", "-count=1", "-list", ".*", "./"+pkg)
	if err != nil {
		fatalf("go test -list %s: %v\n%s", pkg, err, out)
	}
	var names []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if listedTest.MatchString(l) {
			names = append(names, l)
		}
	}
	sort.Strings(names)
	return names
}

// isOracleEntry names the entry points of the tests that drive an oracle state: the world of
// the oracle and the one function that runs a state. A test that reaches either is one of
// the tests that compare durations, and two of them must never share a machine.
func isOracleEntry(name string) bool { return name == "runOracleState" || name == "newOracleWorld" }

// isDurationFile names the files that hold tests that measure time itself.
func isDurationFile(base string) bool { return base == "timing_test.go" }

// detectDurationTests parses every _test.go file of the package, build tags or not, and
// returns the top-level tests that reach an oracle entry point through calls inside the
// package, or that live in a file made to measure time. The reason of each is returned
// with it. Parsing instead of a name list is what makes a new oracle test split by itself.
func detectDurationTests(dir string) (map[string]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { return strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		return nil, err
	}
	type fn struct {
		file  string
		calls map[string]bool
	}
	funcs := map[string][]fn{} // by name: a method and a function may share one, both are followed
	var tests []string
	testFile := map[string]string{}
	for _, pk := range pkgs {
		for path, f := range pk.Files {
			base := filepath.Base(path)
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				calls := map[string]bool{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok {
						calls[id.Name] = true
					}
					return true
				})
				funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fn{base, calls})
				if fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Test") && listedTest.MatchString(fd.Name.Name) {
					tests = append(tests, fd.Name.Name)
					testFile[fd.Name.Name] = base
				}
			}
		}
	}
	reaches := func(start string) bool {
		seen := map[string]bool{}
		queue := []string{start}
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if seen[n] {
				continue
			}
			seen[n] = true
			if isOracleEntry(n) {
				return true
			}
			for _, f := range funcs[n] {
				for c := range f.calls {
					if isOracleEntry(c) || funcs[c] != nil {
						queue = append(queue, c)
					}
				}
			}
		}
		return false
	}
	out := map[string]string{}
	for _, t := range tests {
		switch {
		case isDurationFile(testFile[t]):
			out[t] = "measures time (" + testFile[t] + ")"
		case reaches(t):
			out[t] = "runs an oracle state (" + testFile[t] + ")"
		}
	}
	return out, nil
}

// ---- mutants.yaml ---------------------------------------------------------------------

type mutantEntry struct {
	ID        string `yaml:"id"`
	Docker    bool   `yaml:"docker"`
	Workspace bool   `yaml:"workspace"`
	MustFail  []struct {
		Pkg   string   `yaml:"pkg"`
		Tests []string `yaml:"tests"`
	} `yaml:"must_fail"`
}

// loadMutants reads only what the planner needs and is not strict about the rest: the
// strict decoding and the validation belong to tools/mutants, which every shard runs.
func loadMutants(root string) []mutantEntry {
	b, err := os.ReadFile(filepath.Join(root, "mutants.yaml"))
	if err != nil {
		fatalf("%v", err)
	}
	var f struct {
		Mutants []mutantEntry `yaml:"mutants"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		fatalf("mutants.yaml: %v", err)
	}
	return f.Mutants
}

func (m mutantEntry) keys() []string {
	var ks []string
	for _, ex := range m.MustFail {
		t := append([]string(nil), ex.Tests...)
		sort.Strings(t)
		ks = append(ks, ex.Pkg+" "+strings.Join(t, ","))
	}
	return ks
}

// ---- the plan -------------------------------------------------------------------------

func buildPlan(root string) *Plan {
	module := goModule(root)
	w := loadWeights(root)
	pkgs := listPackages(root, module)
	p := &Plan{Version: 1, Module: module}
	for _, k := range pkgs {
		p.Packages = append(p.Packages, k.Rel)
	}

	// internal/api: one shard per duration test, one for the rest.
	const apiPkg = "internal/api"
	apiDir := filepath.Join(root, filepath.FromSlash(apiPkg))
	if _, err := os.Stat(apiDir); err != nil || !contains(p.Packages, apiPkg) {
		fatalf("%s is not a package of this tree; the planner cuts it by name", apiPkg)
	}
	list := listTests(root, apiPkg)
	cands, err := detectDurationTests(apiDir)
	if err != nil {
		fatalf("parse %s: %v", apiPkg, err)
	}
	p.API.Package = apiPkg
	p.API.List = list
	var names []string
	for n := range cands {
		names = append(names, n)
	}
	sort.Strings(names)
	inList := toSet(list)
	for _, n := range names {
		if inList[n] {
			p.API.Split = append(p.API.Split, n)
			p.API.SplitWhy = append(p.API.SplitWhy, cands[n])
		} else {
			p.API.NotInList = append(p.API.NotInList, n)
		}
	}
	p.API.RestSkip = anchoredAlternation(p.API.Split)
	splitSet := toSet(p.API.Split)
	for _, n := range list {
		if !splitSet[n] {
			p.API.RestTests = append(p.API.RestTests, n)
		}
	}

	// Package shards: every package but internal/api, packed by estimated weight.
	var items []packItem
	needImage := map[string]bool{}
	for _, k := range pkgs {
		if k.Rel == apiPkg {
			continue
		}
		wt, ok := w.TestPackages[k.Rel]
		if !ok {
			wt = w.DefaultPlain
			if k.Container {
				wt = w.DefaultDocker
			}
		}
		items = append(items, packItem{Name: k.Rel, Weight: wt})
		needImage[k.Rel] = k.NeedImage
	}
	total := 0
	for _, it := range items {
		total += it.Weight
	}
	nb := clamp(int(math.Ceil(float64(total)/float64(w.PackageShardSecs))), 2, w.MaxPackageShards)
	for i, bin := range pack(items, nb) {
		if len(bin.Names) == 0 {
			continue
		}
		s := TestShard{ID: fmt.Sprintf("packages-%d", i+1), Kind: "packages", Parallel: 3, Weight: bin.Weight}
		for _, n := range bin.Names {
			s.Packages = append(s.Packages, "./"+n)
			if needImage[n] {
				s.NeedsImage = true
			}
		}
		s.TimeoutMinutes = clamp(bin.Weight/60*3+30, 45, 180)
		p.TestShards = append(p.TestShards, s)
	}
	// With every test split out there is no rest to run, and a rest shard with an empty list
	// would be a shard that judges nothing (shardrun refuses it).
	if len(p.API.RestTests) > 0 {
		p.TestShards = append(p.TestShards, TestShard{ID: "api-rest", Kind: "api-rest", Packages: []string{"./" + apiPkg}, Skip: p.API.RestSkip,
			Tests: p.API.RestTests, Parallel: 1, TimeoutMinutes: 150, Weight: w.APIRestSeconds, NeedsImage: dirMentionsImage(apiDir)})
	}
	for _, n := range p.API.Split {
		p.TestShards = append(p.TestShards, TestShard{ID: "api-" + strings.TrimPrefix(n, "Test"), Kind: "api-split",
			Packages: []string{"./" + apiPkg}, Run: "^" + regexp.QuoteMeta(n) + "$", Tests: []string{n},
			Parallel: 1, TimeoutMinutes: 45, Weight: w.APISplitSeconds, NeedsImage: dirMentionsImage(apiDir)})
	}
	// The longest first: a matrix starts its jobs in order, and max-parallel keeps the rest waiting.
	sort.SliceStable(p.TestShards, func(i, j int) bool { return p.TestShards[i].Weight > p.TestShards[j].Weight })

	// Mutants.
	all := loadMutants(root)
	var work []mutantEntry
	for _, m := range all {
		p.AllMutants = append(p.AllMutants, m.ID)
		if m.Workspace {
			p.LocalMutants = append(p.LocalMutants, m.ID)
		} else {
			work = append(work, m)
		}
	}
	sort.Strings(p.AllMutants)
	sort.Strings(p.LocalMutants)
	p.MutantShards = planMutants(work, w)
	return p
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func toSet(s []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range s {
		m[x] = true
	}
	return m
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// anchoredAlternation is the pattern that matches exactly the given top-level names, and
// matches nothing at all for an empty list (a bare "^()$" would match the empty name only).
func anchoredAlternation(names []string) string {
	if len(names) == 0 {
		return ""
	}
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	sort.Strings(q)
	return "^(" + strings.Join(q, "|") + ")$"
}

// ---- packing --------------------------------------------------------------------------

type packItem struct {
	Name    string
	Weight  int
	Members []string // for a mutant group: its ids
}

type bin struct {
	Names  []string
	Items  []packItem
	Weight int
}

// pack is longest-processing-time first: sort by weight, put each item in the lightest bin.
// Ties break by name so the same tree always gives the same plan.
func pack(items []packItem, n int) []bin {
	if n < 1 {
		n = 1
	}
	sorted := append([]packItem(nil), items...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Weight != sorted[j].Weight {
			return sorted[i].Weight > sorted[j].Weight
		}
		return sorted[i].Name < sorted[j].Name
	})
	bins := make([]bin, n)
	for _, it := range sorted {
		lo := 0
		for i := range bins {
			if bins[i].Weight < bins[lo].Weight {
				lo = i
			}
		}
		bins[lo].Names = append(bins[lo].Names, it.Name)
		bins[lo].Items = append(bins[lo].Items, it)
		bins[lo].Weight += it.Weight
	}
	for i := range bins {
		sort.Strings(bins[i].Names)
	}
	return bins
}

// planMutants groups the mutants that share a baseline and packs the groups.
//
// internal/mutant checks that the named tests pass on the unchanged tree once per package
// and test set and per run, so two mutants that name the same set of tests share that
// cost when they sit in the same shard and pay it twice when they do not. A group is
// therefore the set of mutants linked by a shared (package, tests) key. A group that is
// heavier than a fair shard is split by its first key, then by mutant: a split wastes a
// baseline, which is cheaper than one shard that decides the length of the whole run.
func planMutants(work []mutantEntry, w Weights) []MutantShard {
	if len(work) == 0 {
		return nil
	}
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] == "" {
			parent[x] = x
		}
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(a, b string) { parent[find(a)] = find(b) }
	for _, m := range work {
		ks := m.keys()
		for _, k := range ks {
			find(k)
		}
		for _, k := range ks[1:] {
			union(ks[0], k)
		}
	}
	cost := func(m mutantEntry) (run int) {
		if v := w.MutantSeconds[m.ID]; v > 0 {
			return v
		}
		for range m.MustFail {
			if m.Docker {
				run += w.Mutant.DockerRun
			} else {
				run += w.Mutant.PlainRun
			}
		}
		return run
	}
	baseline := func(ms []mutantEntry) int {
		seen := map[string]bool{}
		c := 0
		for _, m := range ms {
			for _, k := range m.keys() {
				if !seen[k] {
					seen[k] = true
					if m.Docker {
						c += w.Mutant.DockerBaseline
					} else {
						c += w.Mutant.PlainBaseline
					}
				}
			}
		}
		return c
	}
	weight := func(ms []mutantEntry) int {
		t := baseline(ms)
		for _, m := range ms {
			t += cost(m)
		}
		return t
	}
	byRoot := map[string][]mutantEntry{}
	var roots []string
	for _, m := range work {
		r := find(m.keys()[0])
		if _, ok := byRoot[r]; !ok {
			roots = append(roots, r)
		}
		byRoot[r] = append(byRoot[r], m)
	}
	total := weight(work)
	nShards := clamp(int(math.Ceil(float64(total)/float64(w.MutantShardSecs))), 1, w.MaxMutantShards)
	cap := total / nShards * 11 / 10 // a group above 110% of a fair share is split

	var groups [][]mutantEntry
	for _, r := range roots {
		g := byRoot[r]
		if weight(g) <= cap {
			groups = append(groups, g)
			continue
		}
		byKey := map[string][]mutantEntry{}
		var order []string
		for _, m := range g {
			k := m.keys()[0]
			if _, ok := byKey[k]; !ok {
				order = append(order, k)
			}
			byKey[k] = append(byKey[k], m)
		}
		for _, k := range order {
			sub := byKey[k]
			if weight(sub) <= cap {
				groups = append(groups, sub)
				continue
			}
			for _, m := range sub {
				groups = append(groups, []mutantEntry{m})
			}
		}
	}

	items := make([]packItem, len(groups))
	for i, g := range groups {
		ids := make([]string, len(g))
		for j, m := range g {
			ids[j] = m.ID
		}
		sort.Strings(ids)
		items[i] = packItem{Name: ids[0], Weight: weight(g), Members: ids}
	}
	var shards []MutantShard
	bins := pack(items, nShards)
	sort.SliceStable(bins, func(i, j int) bool { return bins[i].Weight > bins[j].Weight })
	for _, b := range bins {
		if len(b.Items) == 0 {
			continue
		}
		s := MutantShard{Groups: len(b.Items), Jobs: 2, Weight: b.Weight, TimeoutMinutes: clamp(b.Weight/60*3+30, 45, 240)}
		for _, it := range b.Items {
			s.IDs = append(s.IDs, it.Members...)
		}
		sort.Strings(s.IDs)
		s.ID = fmt.Sprintf("mutants-%d", len(shards)+1)
		shards = append(shards, s)
	}
	return shards
}

// ---- the proof ------------------------------------------------------------------------

// prove recomputes the universe from the tree and checks the plan against it. It never
// reads a variable of the planner: a bug there must not be able to vouch for itself.
func prove(root string, p *Plan) []string {
	var bad []string
	add := func(f string, a ...any) { bad = append(bad, fmt.Sprintf(f, a...)) }

	module := goModule(root)
	if p.Module != module {
		add("the plan is for module %q, this tree is %q", p.Module, module)
	}

	// 0. A test file that go leaves out on this runner is a test no shard runs. Only the ones
	// named in ignoredTestFileReasons, with a reason, are accepted.
	known := ignoredTestFileReasons()
	for _, f := range unbuiltTestFiles(root, module) {
		if _, ok := known[f]; !ok {
			add("%s is a test file that go does not build on this runner (a GOOS suffix such as _windows_test.go, a build tag, a name or a directory that starts with _ or ., or a directory go does not list), so no shard runs it: rename it, or name it with a reason in ignoredTestFileReasons", f)
		}
	}

	universe := listPackages(root, module)
	listed := map[string]bool{}
	for _, k := range universe {
		listed[k.Rel] = true
	}
	// A directory with Go files that go list leaves out altogether (no buildable file on this
	// runner) is invisible to the check above, which only reads the packages that are listed.
	dirs, err := unlistedGoDirs(root, listed, known)
	if err != nil {
		add("walking the tree for Go directories: %v", err)
	}
	for _, d := range dirs {
		add("%s holds Go files but is not a package of go list ./... on this runner (every file is excluded by a GOOS suffix or a build tag), so no shard runs its tests: rename the files, or name each with a reason in ignoredTestFileReasons", d)
	}
	// A module of its own is in no `go list ./...`, so the walk above skips its directory and
	// no shard runs it: only the root and shared/ are modules of this repository (ci-r8-2).
	mods, err := strayModules(root)
	if err != nil {
		add("walking the tree for go.mod files: %v", err)
	}
	for _, m := range mods {
		add("%s is a Go module that no job runs (the root and shared/ are the only ones): add a job for it, and then name it in strayModules and in .github/ci/gofiles.sh", m)
	}

	// 1. Packages. Every package of go list ./... is in exactly one shard, except the one
	// package that is cut by test, which is in the api shards only. A shard is one of the three
	// kinds the planner makes: a kind nobody reads would be in no count below, and a packages
	// shard with a -run, a -skip or a list of tests would run fewer tests than its packages hold
	// and still be "in exactly one shard" (CI review round 8, ci-r8-1). shardrun refuses the same
	// shapes (shapeProblem), as the second lock.
	seen := map[string]int{}
	for _, s := range p.TestShards {
		switch s.Kind {
		case "packages":
			if s.Run != "" || s.Skip != "" || len(s.Tests) > 0 {
				add("shard %s is a packages shard and carries a -run, a -skip or a list of tests (run %q, skip %q, %d tests), so it would run fewer tests than its packages hold", s.ID, s.Run, s.Skip, len(s.Tests))
			}
		case "api-split", "api-rest":
		default:
			add("shard %s has the unknown kind %q: no check below reads it", s.ID, s.Kind)
		}
		if s.Kind != "packages" {
			continue
		}
		dup := map[string]bool{}
		for _, pk := range s.Packages {
			if dup[pk] {
				add("package %s is listed twice in shard %s", pk, s.ID)
			}
			dup[pk] = true
			seen[strings.TrimPrefix(pk, "./")]++
		}
	}
	apiPkg := p.API.Package
	for _, k := range universe {
		switch {
		case k.Rel == apiPkg:
			if seen[k.Rel] != 0 {
				add("package %s is cut by test, but it is also in a package shard", k.Rel)
			}
		case seen[k.Rel] == 0:
			add("package %s is in no test shard", k.Rel)
		case seen[k.Rel] > 1:
			add("package %s is in %d test shards", k.Rel, seen[k.Rel])
		}
	}
	inUniverse := map[string]bool{}
	for _, k := range universe {
		inUniverse[k.Rel] = true
	}
	for pk := range seen {
		if !inUniverse[pk] {
			add("shard package %s is not a package of go list ./...", pk)
		}
	}
	if !inUniverse[apiPkg] {
		add("the cut package %s is not a package of this tree", apiPkg)
	}

	// 2. The tests of the cut package, judged by the shards' own patterns.
	list := listTests(root, apiPkg)
	if !equalSets(list, p.API.List) {
		add("the plan lists %d tests for %s, go test -list says %d", len(p.API.List), apiPkg, len(list))
	}
	type sel struct {
		re   *regexp.Regexp
		skip bool
		id   string
	}
	var sels []sel
	for _, s := range p.TestShards {
		if s.Kind != "api-split" && s.Kind != "api-rest" {
			continue
		}
		if len(s.Packages) != 1 || s.Packages[0] != "./"+apiPkg {
			add("shard %s must hold exactly ./%s, it holds %v", s.ID, apiPkg, s.Packages)
			continue
		}
		switch {
		case s.Kind == "api-split" && s.Run != "" && s.Skip == "":
			re, err := regexp.Compile(s.Run)
			if err != nil {
				add("shard %s: -run %q: %v", s.ID, s.Run, err)
				continue
			}
			sels = append(sels, sel{re, false, s.ID})
		case s.Kind == "api-rest" && s.Skip != "" && s.Run == "":
			re, err := regexp.Compile(s.Skip)
			if err != nil {
				add("shard %s: -skip %q: %v", s.ID, s.Skip, err)
				continue
			}
			sels = append(sels, sel{re, true, s.ID})
		case s.Kind == "api-rest" && s.Skip == "" && s.Run == "" && len(p.API.Split) == 0:
			sels = append(sels, sel{nil, true, s.ID}) // nothing split: the rest is everything
		default:
			add("shard %s has an unexpected -run/-skip combination (run %q, skip %q)", s.ID, s.Run, s.Skip)
		}
	}
	for _, name := range list {
		var by []string
		for _, s := range sels {
			selected := false
			switch {
			case s.re == nil:
				selected = true
			case s.skip:
				selected = !s.re.MatchString(name)
			default:
				selected = s.re.MatchString(name)
			}
			if selected {
				by = append(by, s.id)
			}
		}
		switch len(by) {
		case 0:
			add("test %s of %s is selected by no shard", name, apiPkg)
		case 1:
		default:
			add("test %s of %s is selected by %d shards (%s)", name, apiPkg, len(by), strings.Join(by, ", "))
		}
	}
	// A pattern that selects a name that is not a test is a typo that happens to be harmless
	// today, and the split shard it belongs to would fail at run time with "no tests to run".
	listSet := toSet(list)
	for _, n := range p.API.Split {
		if !listSet[n] {
			add("split test %s is not in go test -list of %s (a misspelt name)", n, apiPkg)
		}
	}
	for _, s := range p.TestShards {
		for _, n := range s.Tests {
			if !listSet[n] {
				add("shard %s expects test %s, which is not in go test -list of %s", s.ID, n, apiPkg)
			}
		}
		if s.Kind == "api-split" {
			if len(s.Tests) != 1 || s.Run != "^"+regexp.QuoteMeta(firstOr(s.Tests, ""))+"$" {
				add("shard %s: -run %q does not name exactly its test %v", s.ID, s.Run, s.Tests)
			}
		}
	}
	// The tests a shard names are what shardrun judges the run by: it fails a test that did
	// not run, did not pass, or ran without being named. An emptied or shortened list would
	// switch that judging off or blind it, so the list of the rest shard must be exactly the
	// whole list minus the split tests, computed here from go test -list and not from the plan.
	var wantRest []string
	splitNames := toSet(p.API.Split)
	for _, n := range list {
		if !splitNames[n] {
			wantRest = append(wantRest, n)
		}
	}
	rests := 0
	for _, s := range p.TestShards {
		if s.Kind != "api-rest" {
			continue
		}
		rests++
		if len(s.Tests) == 0 || len(s.Tests) != len(wantRest) || !equalSets(s.Tests, wantRest) {
			add("shard %s names %d tests, the tests of %s outside the split are %d: shardrun would not judge what the shard ran", s.ID, len(s.Tests), apiPkg, len(wantRest))
		}
	}
	switch {
	case rests > 1:
		add("%d rest shards for %s, there must be one", rests, apiPkg)
	case rests == 0 && len(wantRest) > 0:
		add("%d tests of %s are outside the split and no rest shard runs them", len(wantRest), apiPkg)
	}
	if want := anchoredAlternation(p.API.Split); want != p.API.RestSkip {
		add("the -skip pattern of the rest shard is %q, the split tests make %q", p.API.RestSkip, want)
	}
	// The union of the split tests and the rest is the whole list, with no overlap.
	var union []string
	union = append(union, p.API.Split...)
	union = append(union, p.API.RestTests...)
	if !equalSets(union, list) || len(union) != len(list) {
		add("split tests (%d) and rest tests (%d) are not a partition of the %d tests of %s", len(p.API.Split), len(p.API.RestTests), len(list), apiPkg)
	}
	// The detection is read again from the source: a duration test that the plan left in
	// the rest shard would run beside the others and spoil the comparison.
	cands, err := detectDurationTests(filepath.Join(root, filepath.FromSlash(apiPkg)))
	if err != nil {
		add("parse %s: %v", apiPkg, err)
	}
	for n := range cands {
		if listSet[n] && !contains(p.API.Split, n) {
			add("%s (%s) is in the rest shard of %s, it must have a machine of its own", n, cands[n], apiPkg)
		}
	}

	// 3. Mutants.
	muts := loadMutants(root)
	var want, local []string
	wantSet := map[string]bool{}
	for _, m := range muts {
		if wantSet[m.ID] {
			add("mutant id %s is used twice in mutants.yaml", m.ID)
		}
		wantSet[m.ID] = true
		if m.Workspace {
			local = append(local, m.ID)
		} else {
			want = append(want, m.ID)
		}
	}
	if !equalSets(local, p.LocalMutants) {
		add("the plan leaves %d mutants to the local run, mutants.yaml marks %d as workspace", len(p.LocalMutants), len(local))
	}
	inShard := map[string]int{}
	for _, s := range p.MutantShards {
		if len(s.IDs) == 0 {
			add("mutant shard %s is empty", s.ID)
		}
		for _, id := range s.IDs {
			inShard[id]++
			if !wantSet[id] {
				add("mutant shard %s names %s, which is not in mutants.yaml", s.ID, id)
			}
		}
	}
	localSet := toSet(local)
	for _, id := range want {
		switch inShard[id] {
		case 0:
			add("mutant %s is in no shard", id)
		case 1:
		default:
			add("mutant %s is in %d shards", id, inShard[id])
		}
	}
	for id := range inShard {
		if localSet[id] {
			add("workspace mutant %s is in a shard; it cannot run without the workspace documents", id)
		}
	}
	if !equalSets(p.AllMutants, keysOf(wantSet)) {
		add("the plan knows %d mutants, mutants.yaml has %d", len(p.AllMutants), len(wantSet))
	}
	sort.Strings(bad)
	return bad
}

func firstOr(s []string, d string) string {
	if len(s) > 0 {
		return s[0]
	}
	return d
}

func keysOf(m map[string]bool) []string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	return s
}

// equalSets compares as sets, ignoring order and duplicates.
func equalSets(a, b []string) bool {
	as, bs := toSet(a), toSet(b)
	if len(as) != len(bs) {
		return false
	}
	for k := range as {
		if !bs[k] {
			return false
		}
	}
	return true
}

// ---- outputs --------------------------------------------------------------------------

// proveOutputs checks the file that emitOutputs wrote, which is what the workflow really runs
// (the jobs read the matrices from it, not from plan.json). prove() judges plan.json only, so
// without this a dropped entry, a shard attached to the wrong id or a placeholder used while
// shards exist in the one hop between the plan and the matrices would leave a shard out of the run
// with the proof saying ok (CI review round 6, ci-r6-2). It shares no code with emitOutputs: it
// reads the lines back and compares them with the plan, which prove has already judged against the
// tree. GitHub keeps the last value when a name repeats, so a name that appears twice is refused
// rather than guessed at.
func proveOutputs(p *Plan, file string) []string {
	b, err := os.ReadFile(file)
	if err != nil {
		return []string{fmt.Sprintf("the step outputs %s cannot be read: %v", file, err)}
	}
	vals := map[string][]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if ok {
			vals[k] = append(vals[k], v)
		}
	}
	var bad []string
	add := func(f string, a ...any) { bad = append(bad, fmt.Sprintf(f, a...)) }
	one := func(name string) (string, bool) {
		v := vals[name]
		if len(v) != 1 {
			add("the step outputs hold %d lines named %s, there must be exactly one", len(v), name)
			return "", false
		}
		return v[0], true
	}
	count := func(name string, want int) {
		if v, ok := one(name); ok && v != fmt.Sprint(want) {
			add("output %s is %q, the plan has %d", name, v, want)
		}
	}
	count("test_shards", len(p.TestShards))
	count("mutant_shards", len(p.MutantShards))
	count("local_mutants", len(p.LocalMutants))

	type entry struct {
		ID      string          `json:"id"`
		Timeout int             `json:"timeout"`
		Shard   json.RawMessage `json:"shard"`
	}
	// matrix compares one output with the shards of the plan: want[i] is the id, timeout and
	// canonical JSON of shard i, and the empty list must come out as the single placeholder.
	matrix := func(name string, want []entry) {
		line, ok := one(name)
		if !ok {
			return
		}
		var m struct {
			Include []entry `json:"include"`
		}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			add("output %s is not a matrix: %v", name, err)
			return
		}
		if len(want) == 0 {
			if len(m.Include) != 1 || m.Include[0].ID != "none" {
				add("output %s must be the single placeholder \"none\" when the plan has no shard, it has %d entries", name, len(m.Include))
			}
			return
		}
		if len(m.Include) != len(want) {
			add("output %s has %d entries, the plan has %d shards", name, len(m.Include), len(want))
			return
		}
		for i, w := range want {
			g := m.Include[i]
			if g.ID != w.ID || g.Timeout != w.Timeout {
				add("output %s entry %d is %q (timeout %d), the plan's shard is %q (timeout %d)", name, i, g.ID, g.Timeout, w.ID, w.Timeout)
				continue
			}
			var shard any
			if err := json.Unmarshal(g.Shard, &shard); err != nil {
				add("output %s entry %s: shard is not JSON: %v", name, g.ID, err)
				continue
			}
			canon, _ := json.Marshal(shard)
			var planShard any
			_ = json.Unmarshal(w.Shard, &planShard)
			wantCanon, _ := json.Marshal(planShard)
			if !bytes.Equal(canon, wantCanon) {
				add("output %s entry %s carries a shard that differs from the plan's shard of that id", name, g.ID)
			}
		}
	}
	var tw, mw []entry
	for _, s := range p.TestShards {
		sb, _ := json.Marshal(s)
		tw = append(tw, entry{s.ID, s.TimeoutMinutes, sb})
	}
	for _, s := range p.MutantShards {
		sb, _ := json.Marshal(s)
		mw = append(mw, entry{s.ID, s.TimeoutMinutes, sb})
	}
	matrix("test_matrix", tw)
	matrix("mutant_matrix", mw)
	return bad
}

type matrixEntry struct {
	ID      string `json:"id"`
	Timeout int    `json:"timeout"`
	Shard   any    `json:"shard"`
}

// emitOutputs writes the step outputs of the plan job when it runs on GitHub. Each value is
// one line of compact JSON, which a workflow reads with fromJSON.
func emitOutputs(p *Plan) {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return
	}
	tm := []matrixEntry{}
	mm := []matrixEntry{}
	for _, s := range p.TestShards {
		tm = append(tm, matrixEntry{s.ID, s.TimeoutMinutes, s})
	}
	for _, s := range p.MutantShards {
		mm = append(mm, matrixEntry{s.ID, s.TimeoutMinutes, s})
	}
	// GitHub rejects a matrix with no entries and fails the whole workflow before any job
	// is judged. A tree with no mutant to run (all of them workspace ones) is legal, so the
	// matrix then holds one placeholder and the job is skipped by its "if" on the shard count.
	if len(tm) == 0 {
		tm = append(tm, matrixEntry{"none", 1, map[string]any{}})
	}
	if len(mm) == 0 {
		mm = append(mm, matrixEntry{"none", 1, map[string]any{}})
	}
	tj, _ := json.Marshal(map[string]any{"include": tm})
	mj, _ := json.Marshal(map[string]any{"include": mm})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		fatalf("%v", err)
	}
	defer f.Close()
	fmt.Fprintf(f, "test_matrix=%s\n", tj)
	fmt.Fprintf(f, "mutant_matrix=%s\n", mj)
	fmt.Fprintf(f, "test_shards=%d\n", len(p.TestShards))
	fmt.Fprintf(f, "mutant_shards=%d\n", len(p.MutantShards))
	fmt.Fprintf(f, "local_mutants=%d\n", len(p.LocalMutants))
}

// writeSummary tells a reader how the tree was cut.
func writeSummary(p *Plan) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "### Plan\n\n%d packages, %d tests in %s, %d mutants.\n\n", len(p.Packages), len(p.API.List), p.API.Package, len(p.AllMutants))
	b.WriteString("| test shard | kind | packages | estimate (s) |\n|---|---|---|---|\n")
	for _, s := range p.TestShards {
		pk := fmt.Sprintf("%d", len(s.Packages))
		if s.Kind != "packages" {
			pk = "internal/api (" + map[string]string{"api-split": s.Run, "api-rest": fmt.Sprintf("the other %d tests", len(s.Tests))}[s.Kind] + ")"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d |\n", s.ID, s.Kind, pk, s.Weight)
	}
	b.WriteString("\n| mutant shard | mutants | groups | estimate (s, as if run one at a time; -j 2 shortens the wall time) |\n|---|---|---|---|\n")
	for _, s := range p.MutantShards {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", s.ID, len(s.IDs), s.Groups, s.Weight)
	}
	if len(p.API.Split) > 0 {
		b.WriteString("\nSplit out of internal/api because each one compares durations and must not share a machine:\n\n")
		for i, n := range p.API.Split {
			fmt.Fprintf(&b, "- `%s` (%s)\n", n, p.API.SplitWhy[i])
		}
	}
	if len(p.API.NotInList) > 0 {
		fmt.Fprintf(&b, "\nDuration tests behind a build tag, not run by scripts/ci.sh either: %s\n", strings.Join(p.API.NotInList, ", "))
	}
	if len(p.LocalMutants) > 0 {
		fmt.Fprintf(&b, "\nLeft to the local run (they need the workspace documents): %s\n", strings.Join(p.LocalMutants, ", "))
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err == nil {
		defer f.Close()
		f.WriteString(b.String())
	}
}
