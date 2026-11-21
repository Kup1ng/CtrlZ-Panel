package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Rule tests-wait-on-conditions (round 16, admin-r16-10 and -20; rebuilt in round 17, admin-r17-11). A test that
// sleeps for a fixed time to stand for "the other side has done it by now" passes vacuously on a slow runner
// whenever what it asserts is an ABSENCE (no canary in the log, no marker file): the sleep ends before the thing
// could have happened, and the absence proves nothing.
//
// The invariant: a wait in a test is on a condition. What it judges, as an allow list over EVERY test file of
// the module (round 17, tenant-r17-13: the first form listed the directories of the
// admin area, so the same shape in the tenant, SMS and database tests was never read, and a test that slept
// for "the login is now parked on the row lock" passed on a runner that scheduled the goroutine late, without
// the race it was written for ever running): a call of time.Sleep (the package, however it is imported) is
// allowed only inside a for or range statement, where the loop's own condition ends the wait and the sleep
// is the pause between two looks; anywhere else it is a problem unless the file and function are on
// testSleepExempt with the reason. What it does not judge: a wait written with time.After, a timer or a
// ticker, a loop whose condition is itself a clock (`for time.Now().Before(end)` with no look at the state).
//
// The conditions the tests wait on: a Postgres backend parked on a lock (authtest.Env.WaitForLockWaiters, which
// reads pg_stat_activity), callers joined to a cache load (cachex.Loader.Waiting), a key that Valkey no longer
// has, a channel the other side closes.
//
// Two guards share the rule, with different reach (merge of the round 17 fixes of the tenant and the admin areas).
// Guard B (tenant-r17-13 and -18, above) reads EVERY test file. Guard A (admin-r17-11 and -21, below) is the
// stricter construction for the test files of the admin area: no member of package time that waits or schedules
// at all, and every wait through internal/testwait. The admin area is held to A because its tests were
// converted to it; the other areas are held to B until they are converted.
//
// Round 16 allowed time.Sleep inside any for or range statement, and judged nothing else. That was a call shape:
// `for range 1 { time.Sleep(time.Second) }` and `<-time.After(time.Second)` before an assertion of absence both
// passed, and so did a ticker and a timer. The rule is a construction now (internal/testwait): the tests of
// the admin area wait through testwait.Until, UntilEvery, Holds, Receive and TryReceive, each of which takes the
// predicate or the channel that ends the wait, so the clock is only the limit after which the wait gives up.
//
// What it judges, over the test files of the admin area (internal/lint, internal/adminapi, internal/admincli,
// internal/app, internal/testvalkey, internal/adminname, internal/auth/adminnotice and cmd):
//
//  1. every reference to a member of package time, however the package is imported and whether it is called or
//     handed on as a value, must be a member of testTimeAllowed, which is the members of the real package that
//     only make, parse or compare a value (timeSafe and timeClockReaders of clock_test.go, which
//     TestTimeMembersAreAllClassified keeps equal to the package's own member list, so a member a later Go
//     release adds fails there until somebody classifies it) less testTimeWaits, the members that wait or
//     schedule (Sleep, After, AfterFunc, NewTimer, NewTicker, Tick, and the types Timer and Ticker). Anything else
//     fails: the guard is the allow list and not the six names;
//  2. a dot import of package time, where a member is a bare identifier;
//  3. a call of testwait.Until, UntilEvery or Holds whose condition is the literal nil;
//  4. (round 17 fix gate, admin-r17-21) the answer of testwait.Holds and TryReceive is USED: a call that stands
//     alone as a statement, or whose results are all assigned to the blank identifier, is a sleep with extra
//     steps (it waits the limit out when nothing signals), so it fails. The one wait whose answer is not
//     needed is testwait.Bound, a bound on another goroutine, which only the files of testBoundFiles may call,
//     each with its reason; a listed file that no longer calls it fails. Any reference to Holds, TryReceive
//     or Bound that is not the function of a call (a value handed on, a variable of it) fails too, since the
//     call it makes is then out of sight.
//
// What it does not judge: a deadline handed to the code under test (context.WithTimeout), which bounds that
// code and is no wait of the test; a channel receive or WaitGroup.Wait, which are events; a loop that spins on
// the state with no pause (it consumes CPU and does not stand for a condition); and the test files of the other
// areas, whose fixers own them.
var testSleepRoots = []string{"."}

// testSleepSkipDirs are the directories that hold no Go test of this module: the JavaScript workspaces, the
// dependencies they install and the tools' own state.
var testSleepSkipDirs = map[string]bool{"node_modules": true, ".git": true, ".worktrees": true, "apps": true, "packages": true, ".next": true}

// sleepExemption is one entry of testSleepExempt: how many sleeps outside a loop the function has, and why each
// is not a wait for another party. The count is part of the entry (round 17, tenant-r17-18): an entry keyed by
// the function alone also let a NEW sleep added to a listed function pass.
type sleepExemption struct {
	sleeps int
	why    string
}

// testSleepExempt lists the sleeps that are not a wait for another party, each as "path:function" with the
// number of sleeps and the reason. Two kinds are allowed. SCENARIO: the sleep is the fault under test (a dial
// that hangs for a fixed time, a caller that gives up after a delay, a provider that answers slowly), so there
// is nothing to wait for. CLOCK: the thing under test acts on an age or a lease that Postgres measures on its
// own clock, so real seconds must pass. A sleep that stands for "the other side has got there" (a session
// holding a row, a call parked on a lock, a worker's first drain) is not one of these: it is converted to the
// condition (authtest.Env.WaitForLockWaiters and WaitForSleepers, testpg.AwaitLockWaiters, a log line the
// worker writes after its drain). The nine entries of the first form of this list that were kept as OWED
// are converted, and there is no third kind.
var testSleepExempt = map[string]sleepExemption{
	"internal/ratelimit/valkey_test.go:TestValkeyColdDialOfABlackholeDoesNotStallInSeries":                                   {1, "SCENARIO: the sleep is the dial that hangs for a fixed time, and the test measures the callers against it"},
	"internal/api/review_r1_test.go:stormTx":                                                                                 {1, "SCENARIO: the probe starts a little after the storm so that it runs during it; it asserts its own latency, which a late start cannot hide"},
	"internal/auth/password/password_test.go:TestGate":                                                                       {1, "SCENARIO: a caller that cancels after a delay is the case under test"},
	"internal/auth/password/gate_subject_test.go:TestAProvedFloodFromOneAccountCannotKeepStrangersOut":                       {1, "SCENARIO: the flood has to be running when the strangers arrive; the assertion is that they are served, a positive one that a slow start cannot satisfy by accident"},
	"internal/sms/smshttp/smshttp_test.go:TestDoReportsCancelAndTimeoutApart":                                                {1, "SCENARIO: a caller that cancels after a delay is the case under test"},
	"internal/sms/smsir/smsir_test.go:TestCancelledContextIsNotAGatewayFailure":                                              {1, "SCENARIO: a caller that cancels after a delay is the case under test"},
	"internal/store/catalogtest/watchdog_honest_test.go:TestTheWatchdogEndsAHolderThatNeverGoesIdle":                         {1, "CLOCK: the watchdog acts on the age of a transaction, so seconds of the real clock must pass"},
	"internal/store/catalogtest/watchdog_honest_test.go:TestTheWatchdogEndsTheQueuedMembersOfAStuckRoleOnly":                 {2, "CLOCK: the watchdog acts on the age of a transaction and a wait, so seconds of the real clock must pass"},
	"internal/store/catalogtest/watchdog_honest_test.go:TestTheWatchdogEndsAHolderThatLoopsShortLockWaits":                   {1, "CLOCK: the watchdog's block bound is an age of a wait, so the console must have waited seconds of the real clock before the sweep looks (db-r17-1, merged with the tenant guard)"},
	"internal/store/catalogtest/watchdog_honest_test.go:TestTheShippedHoldBoundLeavesAnHonestHolderThatWaitedAndWorkedAlone": {2, "CLOCK: the hold bound is an age of a transaction and the console's wait must be older than the block bound, so the timeline runs on the real clock (db-r17-16, merged with the tenant guard)"},
	"internal/store/catalogtest/watchdog_lock_test.go:TestTheWatchdogEndsALockThatIsHandedOverNotOnlyAnOldTransaction":       {3, "CLOCK: the watchdog acts on the age of a transaction and a wait, so seconds of the real clock must pass"},
	"internal/store/catalogtest/watchdog_lock_test.go:TestTheWatchdogLeavesAnHonestWaiterAndItsHolderAlone":                  {3, "CLOCK: the watchdog acts on the age of a transaction and a wait, so seconds of the real clock must pass"},
	"internal/store/catalogtest/watchdog_test.go:TestTheWatchdogEndsATransactionThatSetItsOwnTimeoutsToZero":                 {1, "CLOCK: the watchdog acts on the age of a transaction, so seconds of the real clock must pass"},
	"internal/store/catalogtest/watchdog_wiring_test.go:TestTheWatchdogRunsInTheContainerTheComposeFileStarts":               {2, "CLOCK: the sweep of the watchdog runs every few seconds of the real clock"},
	"internal/store/fault_test.go:TestIdleInTransactionTimeoutAnswersConnectionLost":                                         {1, "CLOCK: idle_in_transaction_session_timeout is a duration of the server's clock"},
	"internal/store/worker_sms_r6_test.go:TestTheClaimLeaseStartsWhenTheClaimRunsNotWhenTheTransactionBegan":                 {1, "CLOCK: the lease is measured against the database clock, so time must pass in the claim transaction"},
	"internal/store/worker_sms_r7_test.go:TestClaimLeaseLeftIsMeasuredWhenAskedAndTakesTheShortestRow":                       {1, "CLOCK: the lease is measured against the database clock, so time must pass in the claim transaction"},
	"internal/store/worker_sms_r7_test.go:TestTheOutboxClaimLeaseStartsWhenTheClaimRunsNotWhenTheTransactionBegan":           {1, "CLOCK: the lease is measured against the database clock, so time must pass in the claim transaction"},
	"internal/worker/smssend/smssend_r10_test.go:TestARecordThatMeetsALockTimeoutIsRetriedAndTheCodeGoesOnce":                {1, "SCENARIO: the stub of the store takes 1.4 s to answer, which is the lock timeout the record meets"},
	"internal/worker/smssend/smssend_r10_test.go:TestRetryRecordPausesDoubleAndEndWithTheContext":                            {1, "CLOCK: the pauses of the retry are durations of the real clock"},
	"internal/worker/smssend/smssend_r2_test.go:TestAStreamOfCodesCannotStarveAnInvite":                                      {1, "SCENARIO: the provider answers slowly, so the rows of one pass overlap"},
}

var testSleepDirs = []string{"internal/lint", "internal/adminapi", "internal/admincli", "internal/app", "internal/testvalkey", "internal/adminname", "internal/auth/adminnotice", "cmd"}

// testBoundFiles are the files that may call testwait.Bound, with the reason.
var testBoundFiles = map[string]string{
	"internal/adminapi/review_r11_admin_test.go": "the first writer gives the second a bound to read the limits, which it may never do while queued behind a lock",
	"internal/adminapi/review_r5_admin_test.go":  "a worker holds an Argon2 slot for a bounded time, or until the pressure is lifted",
	"internal/adminapi/review_r6_admin_test.go":  "a writer waits a bound for the other to reach a step of the race",
}

// testWaitUsed are the testwait functions whose answer the caller must use.
var testWaitUsed = map[string]bool{"Holds": true, "TryReceive": true}

// testTimeWaits are the members of package time that wait or schedule. A member that is on neither this list
// nor the allowed set is refused too, so this list names what is known and the allow list is what holds.
var testTimeWaits = map[string]string{
	"Sleep": "blocks for a length of time", "After": "a channel that fires after a length of time",
	"AfterFunc": "runs a function after a length of time", "NewTimer": "a timer", "NewTicker": "a ticker",
	"Tick": "a ticker's channel", "Timer": "a timer", "Ticker": "a ticker",
}

// testTimeAllowed is derived, not typed: the members that make, parse or compare a value.
func testTimeAllowed() map[string]bool {
	out := map[string]bool{}
	for k := range timeSafe {
		out[k] = true
	}
	for k := range timeClockReaders {
		out[k] = true
	}
	for k := range testTimeWaits {
		delete(out, k)
	}
	return out
}

// testSleepProblems reports the problems of one Go file under the guard that reaches it: guard A for a file of
// the admin area, guard B for every other test file.
func testSleepProblems(path, src string) []string {
	return testSleepProblemsWith(path, src, testSleepExempt)
}

// testSleepAdminScoped reports whether a file is held to guard A (the admin area, testSleepDirs).
func testSleepAdminScoped(path string) bool {
	for _, d := range testSleepDirs {
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// testSleepProblemsWith is testSleepProblems against a given exemption list, so the stale-entry check can read
// a file with none. A file of the admin area is judged by guard A alone (it allows no sleep at all, so an
// exemption list has nothing to say about it), every other file by guard B.
func testSleepProblemsWith(path, src string, exempt map[string]sleepExemption) []string {
	if testSleepAdminScoped(path) {
		return testWaitProblems(path, src)
	}
	return testSleepOutsideLoops(path, src, exempt)
}

// testSleepOutsideLoops is guard B (tenant-r17-13 and -18): a call of time.Sleep outside a for or range statement
// is a problem unless the function is on the exemption list with that many sleeps.
func testSleepOutsideLoops(path, src string, exempt map[string]sleepExemption) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	timeName := ""
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "time" {
			timeName = "time"
			if im.Name != nil {
				timeName = im.Name.Name
			}
		}
	}
	if timeName == "" {
		return nil
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		seen := 0 // sleeps outside a loop in this function, counted against its exemption
		var stack []ast.Node
		ast.Inspect(fd, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Sleep" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || id.Name != timeName {
				return true
			}
			inLoop := false
			for _, a := range stack {
				switch a.(type) {
				case *ast.ForStmt, *ast.RangeStmt:
					inLoop = true
				}
			}
			if !inLoop {
				seen++
				if seen > exempt[path+":"+fd.Name.Name].sleeps {
					out = append(out, path+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+": time.Sleep in "+fd.Name.Name+" stands for a condition; wait on the condition")
				}
			}
			return true
		})
	}
	return out
}

// testWaitProblems is guard A (admin-r17-11 and -21): each use of a member of package time that is not allowed
// in one Go file, and each call of the testwait helpers with no condition or whose answer is dropped.
func testWaitProblems(path, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	timeName, waitName := "", ""
	var out []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		switch p {
		case "time":
			timeName = "time"
			if im.Name != nil {
				timeName = im.Name.Name
			}
			if timeName == "." {
				out = append(out, path+": a dot import of time makes every member a bare identifier the lint cannot read")
				timeName = ""
			}
		case "github.com/Kup1ng/CtrlZ-Panel/internal/testwait":
			waitName = "testwait"
			if im.Name != nil {
				waitName = im.Name.Name
			}
		}
	}
	allowed := testTimeAllowed()
	pos := func(n ast.Node) string { return path + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) + ": " }
	// waitCall returns the member of testwait that a call expression calls, or "".
	waitCall := func(e ast.Expr) string {
		c, ok := e.(*ast.CallExpr)
		if !ok || waitName == "" {
			return ""
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != waitName {
			return ""
		}
		return sel.Sel.Name
	}
	called := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ExprStmt:
			if m := waitCall(x.X); testWaitUsed[m] {
				out = append(out, pos(x)+"the answer of testwait."+m+" is dropped: a wait that nobody reads is a sleep; use the result, or testwait.Bound for a bound on another goroutine")
			}
		case *ast.AssignStmt:
			blank := true
			for _, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); !ok || id.Name != "_" {
					blank = false
				}
			}
			if len(x.Rhs) == 1 && blank {
				if m := waitCall(x.Rhs[0]); testWaitUsed[m] {
					out = append(out, pos(x)+"the answer of testwait."+m+" is thrown away with _: a wait that nobody reads is a sleep; use the result, or testwait.Bound")
				}
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && waitName != "" && id.Name == waitName && (testWaitUsed[x.Sel.Name] || x.Sel.Name == "Bound") && !called[x] {
				out = append(out, pos(x)+"testwait."+x.Sel.Name+" is used as a value: call it where it is named, so its answer can be judged")
			}
			if id, ok := x.X.(*ast.Ident); ok && timeName != "" && id.Name == timeName && !allowed[x.Sel.Name] {
				why := testTimeWaits[x.Sel.Name]
				if why == "" {
					why = "a member nobody classified"
				}
				out = append(out, pos(x)+"time."+x.Sel.Name+" ("+why+") in a test of the admin area: wait on the condition with testwait")
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || waitName == "" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || id.Name != waitName {
				return true
			}
			called[sel] = true
			switch sel.Sel.Name {
			case "Bound":
				if _, ok := testBoundFiles[path]; !ok {
					out = append(out, pos(x)+"testwait.Bound is for the files of testBoundFiles, each with its reason: a wait whose answer is not read is a sleep")
				}
			case "Until", "UntilEvery", "Holds":
				if len(x.Args) > 0 {
					if last, ok := x.Args[len(x.Args)-1].(*ast.Ident); ok && last.Name == "nil" {
						out = append(out, pos(x)+"testwait."+sel.Sel.Name+" with no condition waits on nothing")
					}
				}
			}
		}
		return true
	})
	return out
}

func TestTestsWaitOnConditionsNotOnClocks(t *testing.T) {
	root := repoRoot(t)
	var problems []string
	n := 0
	read := map[string]bool{}
	bounded := map[string]bool{}
	for _, dir := range testSleepRoots {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() && testSleepSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, p)
			n++
			read[filepath.ToSlash(rel)] = true
			if strings.Contains(string(b), "testwait.Bound(") {
				bounded[filepath.ToSlash(rel)] = true
			}
			problems = append(problems, testSleepProblems(filepath.ToSlash(rel), string(b))...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// The list of files comes from a second source, the parse of the whole module (parseRepo), so a root that
	// is narrowed, a directory that is skipped by mistake or a new tree of tests is a failure and not a silence.
	_, all := parseRepo(t)
	for _, p := range testSleepUnread(read, all) {
		t.Error(p)
	}
	if n < 200 {
		t.Fatalf("only %d test files were read: the lint would judge nothing", n)
	}
	for _, p := range staleSleepExemptions(root, testSleepExempt) {
		t.Error(p)
	}
	for p := range testBoundFiles {
		if !bounded[p] {
			problems = append(problems, "testBoundFiles lists "+p+", which no longer calls testwait.Bound: remove the entry")
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		t.Fatalf("%s", strings.Join(problems, "\n"))
	}
}

// testSleepUnread is the comparison with the second source: every test file that parseRepo found and the walk
// did not read. It is a function of its two inputs so that TestTheSleepLintReadsEveryTestFile can hand it a
// narrowed walk and see it fail; a comparison that only ran against the real tree had no test of its own, since
// the older "fewer than 200 files" check also fails for a narrowed root (round 17, tenant-r17-17).
func testSleepUnread(read map[string]bool, all []file) []string {
	var out []string
	for _, f := range all {
		if f.test && !read[f.path] {
			out = append(out, "the sleep lint did not read "+f.path+", a test file of the module")
		}
	}
	return out
}

// TestTheSleepLintReadsEveryTestFile plants a walk that read one file, none, and all of them.
func TestTheSleepLintReadsEveryTestFile(t *testing.T) {
	_, all := parseRepo(t)
	var tests []string
	for _, f := range all {
		if f.test {
			tests = append(tests, f.path)
		}
	}
	if len(tests) < 200 {
		t.Fatalf("%d test files: the plant has nothing to narrow", len(tests))
	}
	if got := testSleepUnread(map[string]bool{tests[0]: true}, all); len(got) != len(tests)-1 {
		t.Errorf("a walk that read one file left %d unread, want %d", len(got), len(tests)-1)
	}
	if got := testSleepUnread(map[string]bool{}, all); len(got) != len(tests) {
		t.Errorf("a walk that read nothing left %d unread, want %d", len(got), len(tests))
	}
	all2 := map[string]bool{}
	for _, p := range tests {
		all2[p] = true
	}
	if got := testSleepUnread(all2, all); len(got) != 0 {
		t.Errorf("a walk that read every file reported %v", got)
	}
}

// TestTestTimeWaitsAreMembersOfTime keeps testTimeWaits honest: every entry is a member the package declares
// (the classification of the rest is TestTimeMembersAreAllClassified).
func TestTestTimeWaitsAreMembersOfTime(t *testing.T) {
	pkg, err := stdlibImporter().Import("time")
	if err != nil {
		t.Fatal(err)
	}
	for name := range testTimeWaits {
		if pkg.Scope().Lookup(name) == nil {
			t.Errorf("testTimeWaits lists time.%s, which the package does not declare", name)
		}
	}
	if allowed := testTimeAllowed(); !allowed["Duration"] || !allowed["Now"] || allowed["Sleep"] || allowed["After"] {
		t.Error("the derived allow list is not what the rule says: Duration and Now allowed, Sleep and After not")
	}
}

// TestTestSleepLintCanFail plants each form Go allows for guard B (tenant): a bare call, an aliased import, a
// sleep in a closure, a method, a sleep after a loop, and the allowed shapes.
func TestTestSleepLintCanFail(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		bad       bool
	}{
		{"a bare sleep", "package x\nimport \"time\"\nfunc f() { time.Sleep(time.Second) }\n", true},
		{"an aliased import", "package x\nimport tm \"time\"\nfunc f() { tm.Sleep(1) }\n", true},
		{"in a closure", "package x\nimport \"time\"\nfunc f() { go func() { time.Sleep(1) }() }\n", true},
		{"in a method", "package x\nimport \"time\"\ntype a struct{}\nfunc (a) g() { time.Sleep(1) }\n", true},
		{"after a loop", "package x\nimport \"time\"\nfunc f() { for i := 0; i < 3; i++ {}\n time.Sleep(1) }\n", true},
		{"after the body of an if", "package x\nimport \"time\"\nfunc f(b bool) { if b { time.Sleep(1) } }\n", true},
		{"in a for body", "package x\nimport \"time\"\nfunc f() { for !done() { time.Sleep(1) } }\nfunc done() bool { return true }\n", false},
		{"in the post statement of a for", "package x\nimport \"time\"\nfunc f() { for end := time.Now(); time.Now().Before(end); time.Sleep(1) {} }\n", false},
		{"in a range", "package x\nimport \"time\"\nfunc f(c chan int) { for range c { time.Sleep(1) } }\n", false},
		{"in a closure inside a loop", "package x\nimport \"time\"\nfunc f() { for { func() { time.Sleep(1) }() } }\n", false},
		{"a sleep of another package", "package x\nimport \"time\"\ntype s struct{}\nfunc (s) Sleep(int) {}\nfunc f() { var z s; z.Sleep(1); _ = time.Second }\n", false},
	} {
		got := testSleepProblems("x/x_test.go", tc.src)
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: problems %v, want a problem: %v", tc.name, got, tc.bad)
		}
	}
}

// TestTheTwoSleepGuardsDivideTheTestFilesByDirectory plants the same loop of one pass in a file of the admin
// area (guard A refuses it) and in another area (guard B allows a sleep in a loop).
func TestTheTwoSleepGuardsDivideTheTestFilesByDirectory(t *testing.T) {
	const src = "package x\nimport \"time\"\nfunc f() { for range 1 { time.Sleep(1) } }\n"
	if got := testSleepProblems("internal/adminapi/x_test.go", src); len(got) == 0 {
		t.Error("a sleep in a loop in the admin area passed guard A")
	}
	if got := testSleepProblems("internal/store/x_test.go", src); len(got) != 0 {
		t.Errorf("a sleep in a loop outside the admin area was refused: %v", got)
	}
	if !testSleepAdminScoped("cmd/ctrlz/x_test.go") || testSleepAdminScoped("internal/applause/x_test.go") {
		t.Error("the admin scope must match whole directories, so internal/app does not cover internal/applause")
	}
}

// TestTestTimeWaitLintCanFail plants each form Go allows for guard A in good-faith code: a bare call, an
// aliased import, a closure, a method, a loop wrapper, a call in a loop of one pass, a receive from time.After,
// a timer, a ticker, a tick channel, AfterFunc, the function handed on as a value, a variable of it, a dot
// import and a helper call with no condition; and the allowed shapes.
func TestTestTimeWaitLintCanFail(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		bad       bool
	}{
		{"a bare sleep", "package x\nimport \"time\"\nfunc f() { time.Sleep(time.Second) }\n", true},
		{"an aliased import", "package x\nimport tm \"time\"\nfunc f() { tm.Sleep(1) }\n", true},
		{"in a closure", "package x\nimport \"time\"\nfunc f() { go func() { time.Sleep(1) }() }\n", true},
		{"in a method", "package x\nimport \"time\"\ntype a struct{}\nfunc (a) g() { time.Sleep(1) }\n", true},
		{"after a loop", "package x\nimport \"time\"\nfunc f() { for i := 0; i < 3; i++ {}\n time.Sleep(1) }\n", true},
		{"in a for body", "package x\nimport \"time\"\nfunc f() { for !done() { time.Sleep(1) } }\nfunc done() bool { return true }\n", true},
		{"in a loop of one pass", "package x\nimport \"time\"\nfunc f() { for range 1 { time.Sleep(time.Second) } }\n", true},
		{"in the post statement of a for", "package x\nimport \"time\"\nfunc f() { for end := time.Now(); time.Now().Before(end); time.Sleep(1) {} }\n", true},
		{"in a range", "package x\nimport \"time\"\nfunc f(c chan int) { for range c { time.Sleep(1) } }\n", true},
		{"a receive from time.After", "package x\nimport \"time\"\nfunc f() { <-time.After(time.Second) }\n", true},
		{"a select with time.After", "package x\nimport \"time\"\nfunc f(c chan int) { select { case <-c: case <-time.After(1): } }\n", true},
		{"a timer", "package x\nimport \"time\"\nfunc f() { t := time.NewTimer(1); <-t.C }\n", true},
		{"a ticker", "package x\nimport \"time\"\nfunc f() { t := time.NewTicker(1); <-t.C }\n", true},
		{"a tick channel", "package x\nimport \"time\"\nfunc f() { <-time.Tick(1) }\n", true},
		{"AfterFunc", "package x\nimport \"time\"\nfunc f() { time.AfterFunc(1, func() {}) }\n", true},
		{"the function as a value", "package x\nimport \"time\"\nfunc f() { s := time.Sleep; s(1) }\n", true},
		{"the function handed to a helper", "package x\nimport \"time\"\nfunc g(func(time.Duration)) {}\nfunc f() { g(time.Sleep) }\n", true},
		{"a timer type in a declaration", "package x\nimport \"time\"\nvar t *time.Timer\n", true},
		{"a dot import", "package x\nimport . \"time\"\nfunc f() { Sleep(1) }\n", true},
		{"a helper with no condition", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f(t T) { testwait.Until(t, 1, \"x\", nil) }\ntype T = interface{}\n", true},
		{"a helper with no condition, aliased", "package x\nimport w \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f() { w.Holds(1, 1, nil) }\n", true},
		{"a helper with a condition", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f() bool { return testwait.Holds(1, 1, func() bool { return true }) }\n", false},
		// Round 17 fix gate, admin-r17-21: a wait whose answer is not read is a sleep.
		{"Holds as a statement", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f() { testwait.Holds(1, 1, func() bool { return true }) }\n", true},
		{"Holds thrown away", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f() { _ = testwait.Holds(1, 1, func() bool { return true }) }\n", true},
		{"TryReceive as a statement", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f(c chan int) { testwait.TryReceive(c, 1) }\n", true},
		{"TryReceive thrown away", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f(c chan int) { _, _ = testwait.TryReceive(c, 1) }\n", true},
		{"TryReceive handed on as a value", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f(c chan int) { g := testwait.TryReceive[int]; _, _ = g(c, 1) }\n", true},
		{"an aliased import dropping the answer", "package x\nimport w \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f() { w.Holds(1, 1, func() bool { return true }) }\n", true},
		{"TryReceive with its answer used", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f(c chan int) bool { _, ok := testwait.TryReceive(c, 1); return ok }\n", false},
		{"Bound in a file nobody listed", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f(c chan int) { testwait.Bound(c, 1) }\n", true},
		{"durations and values", "package x\nimport \"time\"\nvar d = 5 * time.Second\nvar _ = time.Now().Add(d).Before(time.Now())\nvar _ time.Time\nvar _, _ = time.Parse(time.RFC3339, \"x\")\n", false},
		{"a method named Sleep of another type", "package x\nimport \"time\"\ntype s struct{}\nfunc (s) Sleep(int) {}\nfunc f() { var z s; z.Sleep(1); _ = time.Second }\n", false},
		{"no time import", "package x\nfunc f() {}\n", false},
	} {
		got := testSleepProblems("internal/adminapi/x_test.go", tc.src) // a file of the admin area, so guard A reads it
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: problems %v, want a problem: %v", tc.name, got, tc.bad)
		}
	}
}

// staleSleepExemptions reports the entries of an exemption list that have no reason, or whose function no longer
// sleeps outside a loop (it was converted to a condition, or the file moved), so the list cannot outlive its
// reasons.
func staleSleepExemptions(root string, exempt map[string]sleepExemption) []string {
	var out []string
	for key, ex := range exempt {
		if strings.TrimSpace(ex.why) == "" {
			out = append(out, "the exemption "+key+" has no reason")
		}
		path, fn, _ := strings.Cut(key, ":")
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			out = append(out, "the exemption "+key+" names a file that cannot be read: "+err.Error())
			continue
		}
		have := 0
		for _, p := range testSleepProblemsWith(path, string(b), nil) {
			if strings.Contains(p, " in "+fn+" stands for") {
				have++
			}
		}
		switch {
		case have != ex.sleeps && have == 0:
			out = append(out, "the exemption "+key+" no longer has a sleep outside a loop; delete the entry")
		case have != ex.sleeps:
			out = append(out, fmt.Sprintf("the exemption %s says %d sleeps outside a loop and the function has %d; a sleep that was added or converted changes the entry", key, ex.sleeps, have))
		}
	}
	sort.Strings(out)
	return out
}

// TestTheSleepExemptionListCannotOutliveItsSleeps plants an exemption for a function that does not sleep, one
// with no reason and one for a file that is not there.
func TestTheSleepExemptionListCannotOutliveItsSleeps(t *testing.T) {
	root := repoRoot(t)
	got := staleSleepExemptions(root, map[string]sleepExemption{
		"internal/lint/testsleep_test.go:TestTestSleepLintCanFail": {1, "a reason"},
		"internal/lint/testsleep_test.go:staleSleepExemptions":     {1, ""},
		"internal/lint/not_there_test.go:f":                        {1, "a reason"},
	})
	if len(got) != 4 {
		t.Errorf("%d findings %v, want four (no sleep; no reason, which also has no sleep; no file)", len(got), got)
	}
	// The two entries whose function has no sleep at all are told to be deleted, and not told a count: the check
	// that an entry outlived its sleep must hold on its own, apart from the one that compares counts.
	deleted := 0
	for _, g := range got {
		if strings.Contains(g, "delete the entry") {
			deleted++
		}
	}
	if deleted != 2 {
		t.Errorf("%d findings say to delete the entry, want 2: %v", deleted, got)
	}
	if got := staleSleepExemptions(root, nil); len(got) != 0 {
		t.Errorf("an empty list reported %v", got)
	}
	// An entry that names more sleeps than the function has (a real one, so a conversion that removes one of
	// two bare sleeps changes the entry) is a finding of its own.
	var key string
	for k := range testSleepExempt {
		if key == "" || k < key {
			key = k
		}
	}
	ex := testSleepExempt[key]
	got = staleSleepExemptions(root, map[string]sleepExemption{key: {ex.sleeps + 5, ex.why}})
	if len(got) != 1 || !strings.Contains(got[0], "says") {
		t.Errorf("an entry that names the wrong number of sleeps reported %v, want one finding", got)
	}
	if got := staleSleepExemptions(root, map[string]sleepExemption{key: ex}); len(got) != 0 {
		t.Errorf("the entry as it stands reported %v", got)
	}
}

// TestAListedFunctionCannotGainASleep plants a function that has two sleeps outside a loop against an entry that
// names one (tenant-r17-18): the second is a problem, where an entry keyed by the function name alone passed it.
func TestAListedFunctionCannotGainASleep(t *testing.T) {
	const src = "package x\nimport \"time\"\nfunc f() { time.Sleep(1)\n time.Sleep(2) }\n"
	exempt := map[string]sleepExemption{"x/x_test.go:f": {1, "SCENARIO: the first is the fault under test"}}
	if got := testSleepProblemsWith("x/x_test.go", src, exempt); len(got) != 1 {
		t.Errorf("two sleeps against an entry of one: %v, want exactly one problem", got)
	}
	exempt["x/x_test.go:f"] = sleepExemption{2, "SCENARIO: both"}
	if got := testSleepProblemsWith("x/x_test.go", src, exempt); len(got) != 0 {
		t.Errorf("two sleeps against an entry of two: %v, want none", got)
	}
	if got := testSleepProblemsWith("x/x_test.go", src, nil); len(got) != 2 {
		t.Errorf("two sleeps and no entry: %v, want two problems", got)
	}
}
