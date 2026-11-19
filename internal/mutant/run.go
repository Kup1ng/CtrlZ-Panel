package mutant

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is what became of one mutant.
type Status string

const (
	// Killed is the only good outcome: every named test failed under the edit.
	Killed Status = "killed"
	// Survived means a named test passed (or was skipped) with the code broken. The
	// test cannot see the thing it was written for.
	Survived Status = "SURVIVED"
	// Invalid means the mutant proved nothing: the edit did not apply, the tree did
	// not compile with it, a named test did not run, or the test failed before the
	// edit (so its failure under the edit says nothing).
	Invalid Status = "INVALID"
	// Skipped is a mutant left out on purpose (-short, or no workspace). It is
	// reported, never counted as killed.
	Skipped Status = "skipped"
)

// Result is the outcome of one mutant.
type Result struct {
	ID     string
	Status Status
	Detail string
}

// Options configure a run.
type Options struct {
	// Root is the repository (the directory with go.mod and mutants.yaml).
	Root string
	// Short skips the mutants marked docker.
	Short bool
	// Only runs the mutants with these ids; empty runs all.
	Only []string
	// Env is added to the environment of every go test. The scratch tree sits outside
	// the workspace, so the lint tests find the spec and rules.md only through
	// CTRLZ_SPEC and CTRLZ_RULES set here.
	Env []string
	// HaveWorkspace says Env points the lint tests at the workspace documents.
	HaveWorkspace bool
	// Timeout is the go test timeout of each package run.
	Timeout time.Duration
	// Log receives progress lines. Diff lines are written to it too.
	Log io.Writer
	// Jobs is how many mutants run at once, each in its own scratch copy (default 1).
	Jobs int
	// ShowDiff prints a unified diff of every applied edit, as the proof that it applied.
	ShowDiff bool
}

// Run copies the tree to a scratch directory, and for each mutant applies its edits
// there, runs the named tests and puts the files back. The real tree is never written.
// The error is non-nil when any mutant is not Killed or Skipped; the results are
// returned either way.
func Run(ctx context.Context, reg *Registry, opt Options) ([]Result, error) {
	if opt.Log == nil {
		opt.Log = io.Discard
	}
	if opt.Timeout == 0 {
		opt.Timeout = 20 * time.Minute
	}
	if problems := Validate(reg, opt.Root); len(problems) > 0 {
		return nil, fmt.Errorf("mutants.yaml is not valid:\n  %s", strings.Join(problems, "\n  "))
	}
	only := map[string]bool{}
	for _, id := range opt.Only {
		only[id] = true
	}
	var todo []Mutant
	for _, m := range reg.Mutants {
		if len(only) == 0 || only[m.ID] {
			todo = append(todo, m)
		}
	}
	jobs := opt.Jobs
	if jobs < 1 {
		jobs = 1
	}
	if jobs > len(todo) {
		jobs = len(todo)
	}

	// One scratch copy per worker: a mutant rewrites files in its copy, so two cannot
	// share one. Each copy is the tree as it is now, uncommitted work included.
	base := &baselines{done: map[string]*baselineEntry{}}
	results := make([]Result, len(todo))
	var logMu sync.Mutex
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < jobs; w++ {
		scratch, err := os.MkdirTemp("", "ctrlz-mutants-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(scratch)
		if err := copyTree(opt.Root, scratch); err != nil {
			return nil, fmt.Errorf("copy the tree: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				m := todo[i]
				var diff strings.Builder
				var r Result
				switch {
				case m.Docker && opt.Short:
					r = Result{m.ID, Skipped, "starts containers; -short"}
				case m.Workspace && !opt.HaveWorkspace:
					r = Result{m.ID, Skipped, "needs the workspace documents; none found"}
				default:
					r = runOne(ctx, m, scratch, opt, base, &diff)
				}
				results[i] = r
				logMu.Lock()
				fmt.Fprint(opt.Log, diff.String())
				fmt.Fprintf(opt.Log, "mutant %-60s %s %s\n", m.ID, r.Status, r.Detail)
				logMu.Unlock()
			}
		}()
	}
	for i := range todo {
		next <- i
	}
	close(next)
	wg.Wait()

	var bad []string
	for _, r := range results {
		if r.Status != Killed && r.Status != Skipped {
			bad = append(bad, fmt.Sprintf("%s: %s %s", r.ID, r.Status, r.Detail))
		}
	}
	if len(bad) > 0 {
		return results, fmt.Errorf("%d mutant(s) did not die:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	return results, nil
}

// runOne applies a mutant in the scratch tree and always puts the files back.
func runOne(ctx context.Context, m Mutant, scratch string, opt Options, base *baselines, diff io.Writer) Result {
	// Every named test must pass before the edit. A test that fails on its own, or one
	// that skips, would "die" under every mutant and prove nothing.
	for _, ex := range m.MustFail {
		key := ex.Pkg + " " + strings.Join(sortedCopy(ex.Tests), ",")
		err := base.check(ctx, key, scratch, ex, opt)
		if err != nil {
			return Result{m.ID, Invalid, "before the edit: " + err.Error()}
		}
	}

	originals := map[string][]byte{}
	restore := func() {
		for f, b := range originals {
			// A failed restore would poison every later mutant, so stop loudly.
			if err := os.WriteFile(filepath.Join(scratch, filepath.FromSlash(f)), b, 0o644); err != nil {
				panic("mutant: cannot restore " + f + ": " + err.Error())
			}
		}
	}
	defer restore()

	byFile := map[string][]Edit{}
	var order []string
	for _, e := range m.Edits {
		if _, ok := byFile[e.File]; !ok {
			order = append(order, e.File)
		}
		byFile[e.File] = append(byFile[e.File], e)
	}
	for _, f := range order {
		p := filepath.Join(scratch, filepath.FromSlash(f))
		orig, err := os.ReadFile(p)
		if err != nil {
			return Result{m.ID, Invalid, err.Error()}
		}
		mut, err := Apply(orig, byFile[f])
		if err != nil {
			return Result{m.ID, Invalid, err.Error()}
		}
		if bytes.Equal(orig, mut) {
			return Result{m.ID, Invalid, "the edit left " + f + " unchanged"}
		}
		originals[f] = orig
		if err := os.WriteFile(p, mut, 0o644); err != nil {
			return Result{m.ID, Invalid, err.Error()}
		}
		if opt.ShowDiff {
			fmt.Fprint(diff, unifiedDiff(f, orig, mut))
		}
	}

	var survived, invalid []string
	for _, ex := range m.MustFail {
		out, err := goTestRetryingInfra(ctx, scratch, ex, opt)
		if err != nil {
			return Result{m.ID, Invalid, err.Error()}
		}
		if out.buildFailed {
			invalid = append(invalid, ex.Pkg+" does not compile with the edit")
			continue
		}
		for _, tn := range ex.Tests {
			switch out.tests[tn] {
			case "fail":
			case "pass":
				survived = append(survived, tn+" passed")
			case "skip":
				survived = append(survived, tn+" was skipped")
			default:
				invalid = append(invalid, tn+" did not run"+clue(out.pkgOutput))
			}
		}
	}
	switch {
	case len(invalid) > 0:
		return Result{m.ID, Invalid, strings.Join(invalid, "; ")}
	case len(survived) > 0:
		return Result{m.ID, Survived, strings.Join(survived, "; ")}
	}
	return Result{m.ID, Killed, ""}
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

func baseline(ctx context.Context, dir string, ex Expected, opt Options) error {
	out, err := goTestRetryingInfra(ctx, dir, ex, opt)
	if err != nil {
		return err
	}
	if out.buildFailed {
		return fmt.Errorf("%s does not compile", ex.Pkg)
	}
	for _, tn := range ex.Tests {
		if got := out.tests[tn]; got != "pass" {
			return fmt.Errorf("%s %s is %q, it must pass on the unchanged tree", ex.Pkg, tn, orNone(got))
		}
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "not run"
	}
	return s
}

type testOutcome struct {
	tests       map[string]string // top-level test -> pass | fail | skip
	buildFailed bool
	// pkgOutput is the tail of what the package printed outside any test (a TestMain or an
	// init that died, a container that did not start). A test with no result gives it as the
	// only clue why, so an infrastructure failure can be told from a real defect (round 5:
	// a mutant read "did not run" once under load with nothing to say why).
	pkgOutput []string
}

type event struct {
	Action  string
	Package string
	Test    string
	Output  string
}

// goTest runs the named tests of one package and reads the JSON event stream. A test
// that failed because the package did not compile has no event of its own, which is
// how a broken build is told apart from a test that noticed the edit.
// infraAttempts and infraPause bound the retry of a package whose test container did not start.
const (
	infraAttempts = 3
	infraPause    = 10 * time.Second
)

// infrastructureFailure says the package never reached its tests because Docker could not start
// the Postgres or Valkey container (testpg and testvalkey print these two lines before they
// exit). With the four parallel mutant jobs of the full CI, Docker Desktop on Windows answered
// "get provider: rootless Docker is not supported" now and then, a mutant read INVALID, and the
// whole 2.5 hour CI had to be run again for something no edit had done. Only this exact
// signature, with no test result at all, counts: a test that ran, or a package that died of
// anything else, is judged as before, and a mutant that survives is never retried.
func infrastructureFailure(out testOutcome) bool {
	if len(out.tests) > 0 || out.buildFailed {
		return false
	}
	for _, l := range out.pkgOutput {
		if strings.Contains(l, "testpg: cannot start Postgres") || strings.Contains(l, "testvalkey: cannot start Valkey") {
			return true
		}
	}
	return false
}

// retryInfra runs one go test up to attempts times while it fails the way
// infrastructureFailure describes, and returns the last outcome.
func retryInfra(ctx context.Context, attempts int, pause time.Duration, run func() (testOutcome, error)) (testOutcome, error) {
	var out testOutcome
	var err error
	for i := 0; i < attempts; i++ {
		if out, err = run(); err != nil || !infrastructureFailure(out) {
			return out, err
		}
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return out, ctx.Err()
			case <-time.After(pause):
			}
		}
	}
	return out, nil
}

func goTestRetryingInfra(ctx context.Context, dir string, ex Expected, opt Options) (testOutcome, error) {
	return retryInfra(ctx, infraAttempts, infraPause, func() (testOutcome, error) { return goTest(ctx, dir, ex, opt) })
}

func goTest(ctx context.Context, dir string, ex Expected, opt Options) (testOutcome, error) {
	pat := "^(" + strings.Join(ex.Tests, "|") + ")$"
	args := []string{"test", "-count=1", "-json", "-timeout", opt.Timeout.String(), "-run", pat, ex.Pkg}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), opt.Env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return testOutcome{}, err
	}
	if err := cmd.Start(); err != nil {
		return testOutcome{}, err
	}
	out := testOutcome{tests: map[string]string{}}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var ev event
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			// Non JSON lines are the go tool's own build output.
			if strings.Contains(sc.Text(), "build failed") || strings.Contains(sc.Text(), "setup failed") {
				out.buildFailed = true
			}
			continue
		}
		if strings.Contains(ev.Output, "[build failed]") || strings.Contains(ev.Output, "[setup failed]") {
			out.buildFailed = true
		}
		if ev.Test == "" || strings.Contains(ev.Test, "/") {
			if ev.Test == "" && ev.Action == "output" && strings.TrimSpace(ev.Output) != "" {
				out.pkgOutput = append(out.pkgOutput, strings.TrimRight(ev.Output, "\r\n"))
				if len(out.pkgOutput) > 12 {
					out.pkgOutput = out.pkgOutput[1:]
				}
			}
			continue
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			out.tests[ev.Test] = ev.Action
		}
	}
	waitErr := cmd.Wait()
	var exit *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exit) {
		return out, waitErr
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if stderr.Len() > 0 && len(out.tests) == 0 && strings.Contains(stderr.String(), "build failed") {
		out.buildFailed = true
	}
	return out, nil
}

// copyTree copies the files git would track or show as new (so a tree with uncommitted
// work is tested as it is) into dst. Outside a git work tree it walks the directory.
func copyTree(src, dst string) error {
	files, err := listFiles(src)
	if err != nil {
		return err
	}
	for _, f := range files {
		from := filepath.Join(src, filepath.FromSlash(f))
		info, err := os.Stat(from)
		if err != nil || info.IsDir() {
			continue // deleted in the work tree but still in the index
		}
		b, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(to, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func listFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if b, err := cmd.Output(); err == nil && len(b) > 0 {
		var out []string
		for _, f := range strings.Split(string(b), "\x00") {
			if f != "" {
				out = append(out, f)
			}
		}
		return out, nil
	}
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".next", ".codegraph":
				return fs.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}

// unifiedDiff is a plain before/after block of the changed lines, enough to show that
// an edit applied. It is not a patch format; git diff --no-index would need a process
// per edit and gives the same information.
func unifiedDiff(file string, before, after []byte) string {
	a := strings.Split(string(before), "\n")
	b := strings.Split(string(after), "\n")
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	ja, jb := len(a), len(b)
	for ja > i && jb > i && a[ja-1] == b[jb-1] {
		ja--
		jb--
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n@@ line %d @@\n", file, file, i+1)
	for _, l := range a[i:ja] {
		sb.WriteString("-" + strings.TrimRight(l, "\r") + "\n")
	}
	for _, l := range b[i:jb] {
		sb.WriteString("+" + strings.TrimRight(l, "\r") + "\n")
	}
	return sb.String()
}

// baselines remembers, per package and test set, whether the tests pass on the tree
// as it is. Many mutants name the same tests; the answer is the same and costs a
// compile and a run, so it is computed once even when workers ask together.
type baselines struct {
	mu   sync.Mutex
	done map[string]*baselineEntry
}

type baselineEntry struct {
	once sync.Once
	err  error
}

func (b *baselines) check(ctx context.Context, key, dir string, ex Expected, opt Options) error {
	b.mu.Lock()
	e, ok := b.done[key]
	if !ok {
		e = &baselineEntry{}
		b.done[key] = e
	}
	b.mu.Unlock()
	e.once.Do(func() { e.err = baseline(ctx, dir, ex, opt) })
	return e.err
}

// clue renders the package output kept by goTest for an Invalid detail, bounded so one
// noisy package cannot fill the report.
func clue(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	s := strings.Join(lines, " | ")
	if len(s) > 600 {
		s = s[len(s)-600:]
	}
	return " (package output: " + s + ")"
}
