// Command shardrun runs one shard of the GitHub CI and judges the result.
//
//	SHARD_JSON='{...}' go run ./.github/ci/shardrun tests
//	SHARD_JSON='{...}' go run ./.github/ci/shardrun mutants
//	                   go run ./.github/ci/shardrun module <dir>
//
// Why it is not just `go test`. A shard is a slice of the work that the local CI does in
// one piece, and the usual ways for a slice to go wrong are silent: a -run or -skip pattern
// with a typo prints "no tests to run" and exits 0, a package that was handed to the shard
// reports nothing, a test that skips for want of something on the runner looks like a
// pass, and `tools/mutants -only` quietly ignores an id it does not know. So the command
// reads what the tool actually reported and fails the shard unless everything it was given
// has a result of the right kind. What was skipped, and why, goes to the job summary so
// the local run knows what it still owes.
//
// `module <dir>` is the same judging for a whole Go module (`go test ./...` in <dir>): the
// shared module in the static job, and the Node's own module. Every package of the module
// must report, and a skip that is not on the expected list fails. The Node repository carries
// a byte-identical copy of this file, because both repositories judge their tests alike.
//
// Nothing here prints test output that the test itself did not print, and no environment
// variable is echoed.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Shard is the part of the planner's shard objects this command reads. Unknown keys are
// ignored on purpose: the planner may carry more than a runner needs.
type Shard struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Packages       []string `json:"packages"`
	Run            string   `json:"run"`
	Skip           string   `json:"skip"`
	Tests          []string `json:"tests"`
	Parallel       int      `json:"parallel"`
	TimeoutMinutes int      `json:"timeout_minutes"`
	IDs            []string `json:"ids"`
	Jobs           int      `json:"jobs"`
	// Dir is the directory `go test` runs in, relative to the working directory. Empty
	// means the working directory. Only the `module` command sets it.
	Dir string `json:"dir"`
}

// expectedSkips are the reasons for which a skip is part of the design and not a defect.
// Every other skip fails the shard. They are patterns over the output of the test.
//
//   - The workspace documents (spec and rules.md of the owner's workspace) are not in a
//     repository checked out alone. The local run, which has them, owes these tests.
//   - a test in internal/netpool skips when two addresses land on the same shared
//     place by chance of the per-process seed, which the test itself calls by design.
//   - TestOpenCatalogGolden of internal/store/catalogtest does nothing without -update: it
//     is the switch that rewrites its golden file, and a run that does not rewrite goldens
//     is the normal run.
//   - the corpus and vector writers of the shared module (CTRLZ_WRITE_CORPUS and
//     CTRLZ_WRITE_VECTORS) are regeneration switches of the same kind, off in a CI run.
//
// What is NOT on the list, on purpose: the "host is too slow to measure" skip of
// TestRotatedCookieSession... in internal/api, which fails a shard on a loaded runner so
// that the slow host is looked at (see the README); and the noise skip of the linear-time
// guard in shared/quarantine, which has its own rule (noiseSkips).
func expectedSkips() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`no workspace around this repository`),
		regexp.MustCompile(`the two /64s meet in this process's seed`),
		regexp.MustCompile(`run with -update to rewrite testdata/pg_catalog_open\.golden`),
		regexp.MustCompile(`set CTRLZ_WRITE_CORPUS=1 to regenerate seed corpus`),
		regexp.MustCompile(`set CTRLZ_WRITE_VECTORS=1 to regenerate blob\.json and gtable\.json`),
	}
}

// noiseSkips are skips of a guard that measures time and gives up when the host is too
// noisy to measure. Such a test proves nothing on that run, and it is the guard that keeps a
// hostile config entry from costing a node quadratic time, so a quiet skip is not accepted:
// the test is run again, up to noiseAttempts times in all, and the shard fails when it never
// manages to measure. A pass on a later attempt is reported in the summary.
var noiseSkips = []*regexp.Regexp{
	regexp.MustCompile(`so the timing is noise here and proves nothing`),
}

const noiseAttempts = 3

type event struct {
	Action     string
	Package    string
	Test       string
	Output     string
	ImportPath string // build-output events carry this and no Package
	Elapsed    float64
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fatalf("usage: shardrun (tests|mutants|module <dir>)")
	}
	var sh Shard
	if os.Args[1] == "module" {
		if len(os.Args) != 3 {
			fatalf("usage: shardrun module <dir>")
		}
		sh = Shard{ID: "module-" + strings.NewReplacer("/", "-", ".", "root").Replace(os.Args[2]), Kind: "module", Dir: os.Args[2]}
	} else {
		if len(os.Args) != 2 {
			fatalf("usage: shardrun (tests|mutants|module <dir>)")
		}
		if err := json.Unmarshal([]byte(os.Getenv("SHARD_JSON")), &sh); err != nil || sh.ID == "" {
			fatalf("SHARD_JSON is not a shard object: %v", err)
		}
	}
	var problems []string
	switch os.Args[1] {
	case "tests", "module":
		problems = runTests(sh)
	case "mutants":
		problems = runMutants(sh)
	default:
		fatalf("unknown command %q", os.Args[1])
	}
	if len(problems) > 0 {
		fmt.Fprintln(os.Stderr, "\nshardrun: this shard FAILED:")
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  - "+p)
		}
		appendSummary("\n**FAILED**\n\n" + bullets(problems) + "\n")
		os.Exit(1)
	}
	fmt.Println("\nshardrun: shard ok")
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "shardrun: "+f+"\n", a...)
	os.Exit(1)
}

func bullets(s []string) string {
	var b strings.Builder
	for _, x := range s {
		b.WriteString("- " + strings.ReplaceAll(x, "\n", " ") + "\n")
	}
	return b.String()
}

func appendSummary(s string) {
	p := os.Getenv("GITHUB_STEP_SUMMARY")
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	io.WriteString(f, s)
}

// ---- tests ----------------------------------------------------------------------------

type skipped struct {
	pkg, test, reason string
	expected          bool
	noise             bool
}

// goOut runs a go command in dir (empty: here) and returns what it printed on stdout.
func goOut(dir string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	b, err := cmd.Output()
	return string(b), err
}

// want is a package the shard was given: the argument of go test and the import path its
// events carry. The two are tied here, once, from the module path that `go list -m` reports,
// so that the module root (written ".") and a package whose name ends like another one are
// matched exactly and not by a suffix.
type want struct{ arg, ip string }

func importPathOf(module, arg string) string {
	rel := strings.TrimPrefix(arg, "./")
	if rel == "." || rel == "" {
		return module
	}
	return module + "/" + rel
}

func runTests(sh Shard) []string {
	// An api shard with no named tests would switch off the check below that every named
	// test ran and passed and that nothing else did, which is the check a bad -run or -skip
	// pattern is caught by. The planner's proof checks the same, and this is the second lock.
	if (sh.Kind == "api-rest" || sh.Kind == "api-split") && len(sh.Tests) == 0 {
		return []string{"shard " + sh.ID + " (" + sh.Kind + ") names no tests, so nothing could judge what its pattern selected"}
	}
	module, err := goOut(sh.Dir, "list", "-m")
	if err != nil || strings.TrimSpace(module) == "" {
		return []string{"cannot read the module path (go list -m): " + fmt.Sprint(err)}
	}
	module = strings.TrimSpace(strings.Split(module, "\n")[0])

	var wants []want
	var pkgArgs []string
	if sh.Kind == "module" {
		out, err := goOut(sh.Dir, "list", "./...")
		if err != nil {
			return []string{"go list ./... failed: " + err.Error()}
		}
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				wants = append(wants, want{arg: l, ip: l})
			}
		}
		pkgArgs = []string{"./..."}
	} else {
		for _, pk := range sh.Packages {
			wants = append(wants, want{arg: pk, ip: importPathOf(module, pk)})
		}
		pkgArgs = sh.Packages
	}
	if len(wants) == 0 {
		return []string{"the shard has no packages"}
	}
	timeout := sh.TimeoutMinutes - 10
	if timeout < 20 {
		timeout = 20
	}
	// -count=1: container tests must run, not be replayed from the cache. The timeout stays
	// under the job's, so a hang ends in a stack dump and a summary and not a killed job.
	args := []string{"test", "-count=1", "-json", "-timeout", strconv.Itoa(timeout) + "m"}
	if sh.Parallel > 0 {
		args = append(args, "-p", strconv.Itoa(sh.Parallel))
	}
	if sh.Run != "" {
		args = append(args, "-run", sh.Run)
	}
	if sh.Skip != "" {
		args = append(args, "-skip", sh.Skip)
	}
	args = append(args, pkgArgs...)
	fmt.Println("shardrun: go " + strings.Join(args, " "))

	cmd := exec.Command("go", args...)
	cmd.Dir = sh.Dir
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return []string{err.Error()}
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return []string{"cannot start go test: " + err.Error()}
	}

	pkgResult := map[string]string{}
	pkgElapsed := map[string]float64{}
	noTestFiles := map[string]bool{}
	topLevel := map[string]string{} // package + "\x00" + test -> pass | fail | skip
	counts := map[string]int{}
	pending := map[string]*strings.Builder{} // output of the tests that have no result yet
	var skips []skipped

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		var ev event
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			fmt.Println(sc.Text()) // the go tool's own line
			continue
		}
		// Since Go 1.24 a compile or vet error reaches -json only as build-output events,
		// which carry an ImportPath and no Package. They are the only place the diagnostic
		// is, so they are printed: a shard that fails to build must say why in its log.
		if ev.Action == "build-output" {
			fmt.Print(ev.Output)
			continue
		}
		if ev.Action == "output" {
			fmt.Print(ev.Output)
			if ev.Test != "" {
				k := ev.Package + "\x00" + ev.Test
				if pending[k] == nil {
					pending[k] = &strings.Builder{}
				}
				pending[k].WriteString(ev.Output)
			} else if strings.Contains(ev.Output, "[no test files]") {
				noTestFiles[ev.Package] = true
			}
			continue
		}
		switch ev.Action {
		case "pass", "fail", "skip":
		default:
			continue
		}
		if ev.Test == "" {
			pkgResult[ev.Package] = ev.Action
			pkgElapsed[ev.Package] = ev.Elapsed
			continue
		}
		counts[ev.Action]++
		k := ev.Package + "\x00" + ev.Test
		top := !strings.Contains(ev.Test, "/")
		if top {
			topLevel[k] = ev.Action
		}
		if ev.Action == "skip" {
			raw := ""
			if b := pending[k]; b != nil {
				raw = b.String()
			}
			s := skipped{pkg: ev.Package, test: ev.Test, reason: skipReason(raw)}
			for _, re := range expectedSkips() {
				if re.MatchString(raw) {
					s.expected = true
				}
			}
			for _, re := range noiseSkips {
				if top && re.MatchString(raw) {
					s.noise = true
				}
			}
			skips = append(skips, s)
		}
		delete(pending, k)
	}
	waitErr := cmd.Wait()

	// A measuring guard that found the host too noisy is run again before it is judged.
	resolved := map[string]string{} // package + "\x00" + test -> how it was resolved
	for _, s := range skips {
		if !s.noise {
			continue
		}
		for a := 2; a <= noiseAttempts; a++ {
			fmt.Printf("shardrun: %s skipped as noise; attempt %d of %d\n", s.test, a, noiseAttempts)
			r := runOne(sh.Dir, s.pkg, s.test, timeout)
			if r == "pass" {
				resolved[s.pkg+"\x00"+s.test] = fmt.Sprintf("measured on attempt %d", a)
				break
			}
			if r == "fail" {
				break
			}
		}
	}
	wall := time.Since(start)

	var problems []string
	if waitErr != nil {
		problems = append(problems, "go test failed: "+waitErr.Error())
	}
	for _, w := range wants {
		switch r := pkgResult[w.ip]; {
		case r == "":
			problems = append(problems, "package "+w.arg+" reported no result: it was given to this shard and did not run")
		case r == "fail":
			problems = append(problems, "package "+w.arg+" failed")
		case r == "skip" && !noTestFiles[w.ip]:
			problems = append(problems, "package "+w.arg+" was skipped as a whole")
		}
	}
	// The tests the shard names must each have run, once, and passed. The patterns of
	// -run and -skip are the place a typo hides, so the result is judged by name.
	if len(sh.Tests) > 0 {
		named := map[string]bool{}
		for _, t := range sh.Tests {
			named[t] = true
		}
		ip := wants[0].ip
		for _, t := range sh.Tests {
			if !(strings.HasPrefix(t, "Test") || strings.HasPrefix(t, "Fuzz")) {
				continue // an Example may have no output to check and then is not run
			}
			r := topLevel[ip+"\x00"+t]
			if _, ok := resolved[ip+"\x00"+t]; ok && r == "skip" {
				r = "pass"
			}
			switch r {
			case "pass":
			case "":
				problems = append(problems, "test "+t+" did not run (no result: a pattern that selects nothing, or a test that was never reached)")
			default:
				problems = append(problems, "test "+t+" did not pass: "+r)
			}
		}
		for k, r := range topLevel {
			name := k[strings.Index(k, "\x00")+1:]
			if !named[name] {
				problems = append(problems, "test "+name+" ("+r+") ran in this shard and is not one of its tests: the -run or -skip pattern selects more than the plan says")
			}
		}
	}
	for _, s := range skips {
		if s.expected {
			continue
		}
		if _, ok := resolved[s.pkg+"\x00"+s.test]; ok {
			continue
		}
		if s.noise {
			problems = append(problems, fmt.Sprintf("test %s (%s) skipped as too noisy to measure on all %d attempts, or failed on a repeat: the guard did not measure anything. %s", s.test, s.pkg, noiseAttempts, s.reason))
			continue
		}
		problems = append(problems, fmt.Sprintf("test %s (%s) was skipped and that is not an expected skip: %s", s.test, s.pkg, s.reason))
	}
	sort.Strings(problems)
	appendSummary(testSummary(sh, wall, counts, pkgElapsed, skips, resolved))
	return problems
}

// runOne runs one top-level test of one package again and returns its result (pass, fail,
// skip, or "" when none was reported). Its output is printed, so the log shows the repeat.
func runOne(dir, pkg, test string, timeoutMin int) string {
	cmd := exec.Command("go", "test", "-count=1", "-json", "-timeout", strconv.Itoa(timeoutMin)+"m", "-run", "^"+regexp.QuoteMeta(test)+"$", pkg)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	out, _ := cmd.Output() // the verdict is read from the events, not from the exit status
	res := ""
	for _, l := range strings.Split(string(out), "\n") {
		var ev event
		if l == "" || json.Unmarshal([]byte(l), &ev) != nil {
			continue
		}
		switch ev.Action {
		case "output", "build-output":
			fmt.Print(ev.Output)
		case "pass", "fail", "skip":
			if ev.Test == test {
				res = ev.Action
			}
		}
	}
	return res
}

var fileLine = regexp.MustCompile(`^\s*(\S+\.go:\d+:\s*)?`)

// skipReason keeps the lines a test printed before it skipped, without the harness's own.
func skipReason(out string) string {
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "=== ") || strings.HasPrefix(t, "--- ") {
			continue
		}
		keep = append(keep, fileLine.ReplaceAllString(t, ""))
	}
	r := strings.Join(keep, " | ")
	if len(r) > 300 {
		r = r[:300] + "..."
	}
	return r
}

func testSummary(sh Shard, wall time.Duration, counts map[string]int, pkgElapsed map[string]float64, skips []skipped, resolved map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### test shard `%s`\n\nWall time %s. %d passed, %d failed, %d skipped (tests and subtests).\n\n",
		sh.ID, wall.Round(time.Second), counts["pass"], counts["fail"], counts["skip"])
	if len(skips) > 0 {
		b.WriteString("Skipped tests. The expected ones are by design: the workspace-document tests are owed by the local run, which has the workspace, and the rest are switches that regenerate a golden file or a corpus. Any other skip fails the shard.\n\n| test | package | status | reason |\n|---|---|---|---|\n")
		for _, s := range skips {
			st := "UNEXPECTED"
			switch note, ok := resolved[s.pkg+"\x00"+s.test]; {
			case s.expected:
				st = "expected"
			case ok:
				st = "noise skip, then " + note
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", s.test, s.pkg, st, strings.ReplaceAll(s.reason, "|", "/"))
		}
		b.WriteString("\n")
	}
	type pe struct {
		p string
		e float64
	}
	var ps []pe
	for p, e := range pkgElapsed {
		ps = append(ps, pe{p, e})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].e > ps[j].e })
	if len(ps) > 12 {
		ps = ps[:12]
	}
	b.WriteString("Slowest packages (seconds), to refresh `.github/ci/weights.json`:\n\n| package | seconds |\n|---|---|\n")
	for _, x := range ps {
		fmt.Fprintf(&b, "| %s | %.0f |\n", x.p, x.e)
	}
	b.WriteString("\n")
	return b.String()
}

// ---- mutants --------------------------------------------------------------------------

var (
	mutantLine  = regexp.MustCompile(`^mutant (\S+)\s+(killed|SURVIVED|INVALID|skipped)\b\s*(.*)$`)
	mutantTotal = regexp.MustCompile(`^mutants: (\d+) killed, (\d+) skipped, (\d+) total`)
)

func runMutants(sh Shard) []string {
	if len(sh.IDs) == 0 {
		return []string{"the shard has no mutant ids"}
	}
	jobs := sh.Jobs
	if jobs < 1 {
		jobs = 2
	}
	args := []string{"run", "./tools/mutants", "-only", strings.Join(sh.IDs, ","), "-j", strconv.Itoa(jobs)}
	fmt.Printf("shardrun: go run ./tools/mutants -only <%d ids> -j %d\n", len(sh.IDs), jobs)
	cmd := exec.Command("go", args...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return []string{err.Error()}
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return []string{"cannot start tools/mutants: " + err.Error()}
	}
	status := map[string][]string{} // id -> statuses seen
	detail := map[string]string{}
	var killed, skippedN, total = -1, -1, -1
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		l := sc.Text()
		fmt.Println(l)
		if m := mutantLine.FindStringSubmatch(l); m != nil {
			status[m[1]] = append(status[m[1]], m[2])
			detail[m[1]] = m[3]
		}
		if m := mutantTotal.FindStringSubmatch(l); m != nil {
			killed, _ = strconv.Atoi(m[1])
			skippedN, _ = strconv.Atoi(m[2])
			total, _ = strconv.Atoi(m[3])
		}
	}
	waitErr := cmd.Wait()
	wall := time.Since(start)

	var problems []string
	if waitErr != nil {
		problems = append(problems, "tools/mutants failed: "+waitErr.Error())
	}
	// The count is the guard against an id the tool ignored: -only drops a name it does not
	// know without a word, and the summary would then be smaller than the list.
	switch {
	case total < 0:
		problems = append(problems, "tools/mutants printed no summary line; the shard cannot say how many mutants it judged")
	case total != len(sh.IDs) || killed != len(sh.IDs) || skippedN != 0:
		problems = append(problems, fmt.Sprintf("the summary says %d killed, %d skipped, %d total; the shard was given %d ids and every one must be killed", killed, skippedN, total, len(sh.IDs)))
	}
	want := map[string]bool{}
	for _, id := range sh.IDs {
		want[id] = true
		switch st := status[id]; {
		case len(st) == 0:
			problems = append(problems, "mutant "+id+" has no result line")
		case len(st) > 1:
			problems = append(problems, fmt.Sprintf("mutant %s has %d result lines", id, len(st)))
		case st[0] != "killed":
			problems = append(problems, "mutant "+id+" is "+st[0]+" "+detail[id])
		}
	}
	for id := range status {
		if !want[id] {
			problems = append(problems, "mutant "+id+" ran and is not one of this shard's ids")
		}
	}
	sort.Strings(problems)
	appendSummary(fmt.Sprintf("### mutant shard `%s`\n\nWall time %s. %d ids given, %d killed, %d skipped, %d judged in total.\n\n",
		sh.ID, wall.Round(time.Second), len(sh.IDs), killed, skippedN, total))
	return problems
}
