package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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
// testSleepExempt with the reason. A wait written with time.After, a timer or a ticker (After, AfterFunc, NewTimer,
// NewTicker, Tick) is judged the same way since round 18 (tenant-r18-4): it is allowed only as the channel in the
// Comm of a select case whose body fails the test, on a receiver of a testing type (failsTheTest, tenant-r18-16).
// What it does not judge: a loop whose condition is itself a clock (`for time.Now().Before(end)` with no look at
// the state).
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
	"internal/sms/router_budget_test.go:Send":                                                                                {1, "SCENARIO: the stub provider takes a fixed time to answer, which is the case under test"},
	"internal/sms/sms_test.go:Load":                                                                                          {1, "SCENARIO: the stub of the settings source takes a fixed time to answer"},
	"internal/store/caps_race_test.go:newBarrier":                                                                            {1, "BARRIER: the limit after which the racers go on when one never arrives (a spender that failed earlier); the barrier ends on the arrival of the last one and the timer only stops a hang"},
	"internal/store/caps_race_test.go:driveCostNeedsPrice":                                                                   {1, "BARRIER: the same limit on a two-party barrier; both sides proceed whichever way it ends and the assertions read rows"},
	"internal/store/locks_test.go:TestWritersOfSharedRowsNeverDeadlock":                                                      {1, "SCENARIO: B runs for a stretch to find out whether it blocks behind A; both outcomes are allowed and asserted alike, so the stretch only chooses the interleaving"},
	"internal/worker/smssend/smssend_r6_test.go:TestASendThatHangsIsCutBeforeItsClaimLapses":                                 {1, "SCENARIO: the provider hangs until released; the timer is the cap that keeps the stub goroutine from outliving the test"},
	"internal/store/catalogtest/watchdog_lock_test.go:TestTheWatchdogEndsALockThatIsHandedOverNotOnlyAnOldTransaction":       {4, "CLOCK: the watchdog acts on the age of a transaction and a wait, so seconds of the real clock must pass"},
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
	"internal/store/catalogtest/watchdog_honest_test.go:TestTheWatchdogLeavesAnHonestQueueOnAHotRowAlone":                    {1, "SCENARIO: the sweep runs on a fixed cadence, as the watchdog's own does, while the honest transactions contend; the loop ends on the channel of the contenders and the tick is the sweep itself, not a wait for something to have happened (tenant-r18-16)"},
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
func testSleepProblems(path, src string, siblings ...string) []string {
	return testSleepProblemsWith(path, src, testSleepExempt, siblings...)
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
func testSleepProblemsWith(path, src string, exempt map[string]sleepExemption, siblings ...string) []string {
	if testSleepAdminScoped(path) {
		return testWaitProblems(path, src)
	}
	return testSleepOutsideLoops(path, src, exempt, siblings...)
}

// testSleepOutsideLoops is guard B (tenant-r17-13 and -18): a call of time.Sleep outside a for or range statement
// is a problem unless the function is on the exemption list with that many sleeps. siblings are the other files of
// the package, read for the struct fields that hold the test.
func testSleepOutsideLoops(path, src string, exempt map[string]sleepExemption, siblings ...string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	// Every name the file gives package time and package testing is judged (localNames, round 18,
	// primitives-r18-10): a test file may import a path twice, and the last name was the only one read.
	timeNames := usableNames(localNames(f, "time"))
	testingNames := usableNames(localNames(f, "testing"))
	if len(timeNames) == 0 {
		return nil
	}
	// The struct fields of the package that hold the test (the siblings are the other files of its directory).
	fields := newTestingFieldIndex(append([]string{src}, siblings...))
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
			if !ok || !testWaitMembers[sel.Sel.Name] {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || !slices.Contains(timeNames, id.Name) {
				return true
			}
			inLoop := false
			for _, a := range stack {
				switch a.(type) {
				case *ast.ForStmt, *ast.RangeStmt:
					inLoop = true
				}
			}
			// A sleep inside a loop is the pause between two looks at a condition the loop tests. A timer, a ticker and
			// time.After are not that: each is a wait on the clock that nothing else ends, so it is allowed only as the
			// deadline of a select (the case that fails the test when the event never comes), and every other use is
			// listed with its reason like a sleep outside a loop (tenant-r18-4).
			wait := !inLoop
			if sel.Sel.Name != "Sleep" {
				wait = !failsTheTest(stack, testingNames, fields)
			}
			if wait {
				seen++
				if seen > exempt[path+":"+fd.Name.Name].sleeps {
					out = append(out, path+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+": time."+sel.Sel.Name+" in "+fd.Name.Name+" stands for a condition; wait on the condition, or let it be the deadline of a select whose case fails the test")
				}
			}
			return true
		})
	}
	return out
}

// testWaitMembers are the members of package time that wait on the clock, which guard B judges in every test file
// (the members that are not waits are the business of guard A in the admin area).
var testWaitMembers = map[string]bool{"Sleep": true, "After": true, "AfterFunc": true, "NewTimer": true, "NewTicker": true, "Tick": true}

// testFailMethods are the methods of testing.TB that fail the running test. The guard is the allow list: a
// method that is not here is not a failure, whatever its name suggests (tenant-r18-16: `err.Error()` is not one).
var testFailMethods = map[string]bool{"Fatal": true, "Fatalf": true, "FailNow": true, "Error": true, "Errorf": true, "Fail": true}

// testingFieldIndex is the set of "Type.field" for every struct field of the package whose type is a testing
// type, read from the sources of the package's files (a helper type that keeps the *testing.T of its test, such
// as the lab of a catalog test, is a handle on the test as much as a parameter is).
type testingFieldIndex map[string]bool

// newTestingFieldIndex reads the struct types declared in the given sources.
func newTestingFieldIndex(srcs []string) testingFieldIndex {
	out := testingFieldIndex{}
	for _, src := range srcs {
		f, err := parser.ParseFile(token.NewFileSet(), "", src, 0)
		if err != nil {
			continue
		}
		names := usableNames(localNames(f, "testing"))
		if len(names) == 0 {
			continue
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				ts, ok := sp.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, fld := range st.Fields.List {
					if !isTestingType(fld.Type, names) {
						continue
					}
					for _, n := range fld.Names {
						out[ts.Name.Name+"."+n.Name] = true
					}
				}
			}
		}
	}
	return out
}

// failsTheTest says the timer call on top of the stack is the channel of a select case that fails the test. It is
// a deadline: it bounds the wait for the event of the other cases and passes no time that a slow runner could
// shorten into a vacuous pass. Three things must hold, and anything else fails closed (tenant-r18-16):
//
//  1. the call stands in the Comm of the innermost CommClause (`case <-time.After(d):`), not in its body: a
//     wait inside a body is a stand-in sleep, whatever the clause does after it;
//  2. a statement of that clause's body, at its top level (not in a closure, a branch or a loop), calls a method
//     of testFailMethods on a handle of the test, or the builtin panic. A handle is a parameter of an enclosing
//     function declared as *testing.T, *testing.B, *testing.F or testing.TB, or a field of a parameter or
//     receiver (`l.t`) whose struct type, declared in the package, has that field with such a type. A receiver
//     of any other type (an error, a fake, a local interface) is not a failure of the test;
//  3. the name of the parameter or receiver is declared nowhere else inside the function that declares it (a
//     `t := fake{}` that shadows it would make the call a no-op), and `panic` is not redeclared either.
func failsTheTest(stack []ast.Node, testingNames []string, fields testingFieldIndex) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		cc, ok := stack[i].(*ast.CommClause)
		if !ok {
			continue
		}
		if cc.Comm == nil || i+1 >= len(stack) || stack[i+1] != cc.Comm {
			return false
		}
		for _, st := range cc.Body {
			es, ok := st.(*ast.ExprStmt)
			if !ok {
				continue
			}
			c, ok := es.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			switch f := c.Fun.(type) {
			case *ast.SelectorExpr:
				if testFailMethods[f.Sel.Name] && testingHandle(stack[:i], f.X, testingNames, fields) {
					return true
				}
			case *ast.Ident:
				if f.Name == "panic" && !declaredInEnclosing(stack[:i], "panic") {
					return true
				}
			}
		}
		return false
	}
	return false
}

// funcParts returns the type and body of a function node on the path, and its receiver list, if it is one.
func funcParts(n ast.Node) (ft *ast.FuncType, recv *ast.FieldList, body *ast.BlockStmt, ok bool) {
	switch fn := n.(type) {
	case *ast.FuncDecl:
		return fn.Type, fn.Recv, fn.Body, true
	case *ast.FuncLit:
		return fn.Type, nil, fn.Body, true
	}
	return nil, nil, nil, false
}

// baseTypeName is the name T of a parameter type T or *T, or "".
func baseTypeName(e ast.Expr) string {
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// testingHandle reports whether expr is a handle on the running test (see failsTheTest, 2 and 3): an identifier
// that is a testing-typed parameter of an enclosing function, or `x.f` where x is a parameter or receiver of type
// T or *T and fields has "T.f".
func testingHandle(outer []ast.Node, expr ast.Expr, testingNames []string, fields testingFieldIndex) bool {
	var name, field string
	switch x := expr.(type) {
	case *ast.Ident:
		name = x.Name
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if !ok {
			return false
		}
		name, field = id.Name, x.Sel.Name
	default:
		return false
	}
	for i := len(outer) - 1; i >= 0; i-- {
		ft, recv, body, ok := funcParts(outer[i])
		if !ok {
			continue
		}
		lists := []*ast.FieldList{ft.Params}
		if recv != nil {
			lists = append(lists, recv)
		}
		for _, l := range lists {
			for _, fld := range l.List {
				for _, n := range fld.Names {
					if n.Name != name {
						continue
					}
					good := false
					if field == "" {
						good = isTestingType(fld.Type, testingNames)
					} else if t := baseTypeName(fld.Type); t != "" {
						good = fields[t+"."+field]
					}
					return good && body != nil && declarations(body, name) == 0
				}
			}
		}
	}
	return false
}

// isTestingType reports whether a parameter type is *testing.T, *testing.B, *testing.F or testing.TB.
func isTestingType(e ast.Expr, testingNames []string) bool {
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || !slices.Contains(testingNames, id.Name) {
		return false
	}
	switch sel.Sel.Name {
	case "T", "B", "F", "TB":
		return true
	}
	return false
}

// declaredInEnclosing reports whether name is declared inside any function on the path.
func declaredInEnclosing(outer []ast.Node, name string) bool {
	for _, n := range outer {
		if _, _, body, ok := funcParts(n); ok && body != nil && declarations(body, name) > 0 {
			return true
		}
	}
	return false
}

// declarations counts the places inside a body that declare name: a := or var, a range variable, a type switch
// binding, a parameter of a nested function literal.
func declarations(body *ast.BlockStmt, name string) int {
	n := 0
	ast.Inspect(body, func(x ast.Node) bool {
		switch d := x.(type) {
		case *ast.AssignStmt:
			if d.Tok == token.DEFINE {
				for _, l := range d.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name == name {
						n++
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range d.Names {
				if id.Name == name {
					n++
				}
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{d.Key, d.Value} {
				if id, ok := e.(*ast.Ident); ok && id.Name == name && d.Tok == token.DEFINE {
					n++
				}
			}
		case *ast.FuncLit:
			for _, fld := range d.Type.Params.List {
				for _, id := range fld.Names {
					if id.Name == name {
						n++
					}
				}
			}
		case *ast.TypeSwitchStmt:
			if as, ok := d.Assign.(*ast.AssignStmt); ok {
				for _, l := range as.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name == name {
						n++
					}
				}
			}
		}
		return true
	})
	return n
}

// testWaitProblems is guard A (admin-r17-11 and -21): each use of a member of package time that is not allowed
// in one Go file, and each call of the testwait helpers with no condition or whose answer is dropped.
func testWaitProblems(path, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	var out []string
	timeAll := localNames(f, "time")
	if hasDot(timeAll) {
		out = append(out, path+": a dot import of time makes every member a bare identifier the lint cannot read")
	}
	timeNames := usableNames(timeAll)
	waitNames := usableNames(localNames(f, "github.com/Kup1ng/CtrlZ-Panel/internal/testwait"))
	allowed := testTimeAllowed()
	pos := func(n ast.Node) string { return path + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) + ": " }
	// waitCall returns the member of testwait that a call expression calls, or "".
	waitCall := func(e ast.Expr) string {
		c, ok := e.(*ast.CallExpr)
		if !ok || len(waitNames) == 0 {
			return ""
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		if id, ok := sel.X.(*ast.Ident); !ok || !slices.Contains(waitNames, id.Name) {
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
			if id, ok := x.X.(*ast.Ident); ok && slices.Contains(waitNames, id.Name) && (testWaitUsed[x.Sel.Name] || x.Sel.Name == "Bound") && !called[x] {
				out = append(out, pos(x)+"testwait."+x.Sel.Name+" is used as a value: call it where it is named, so its answer can be judged")
			}
			if id, ok := x.X.(*ast.Ident); ok && slices.Contains(timeNames, id.Name) && !allowed[x.Sel.Name] {
				why := testTimeWaits[x.Sel.Name]
				if why == "" {
					why = "a member nobody classified"
				}
				out = append(out, pos(x)+"time."+x.Sel.Name+" ("+why+") in a test of the admin area: wait on the condition with testwait")
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || len(waitNames) == 0 {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || !slices.Contains(waitNames, id.Name) {
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
			problems = append(problems, testSleepProblems(filepath.ToSlash(rel), string(b), packageSources(filepath.Dir(p), p)...)...)
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
		{"two aliases of time", "package x\nimport a \"time\"\nimport b \"time\"\nfunc f() { a.Sleep(1); _ = b.Second }\n", true},
		{"a blank import beside the name", "package x\nimport \"time\"\nimport _ \"time\"\nfunc f() { time.Sleep(1) }\n", true},
		{"in a closure", "package x\nimport \"time\"\nfunc f() { go func() { time.Sleep(1) }() }\n", true},
		{"in a method", "package x\nimport \"time\"\ntype a struct{}\nfunc (a) g() { time.Sleep(1) }\n", true},
		{"after a loop", "package x\nimport \"time\"\nfunc f() { for i := 0; i < 3; i++ {}\n time.Sleep(1) }\n", true},
		{"after the body of an if", "package x\nimport \"time\"\nfunc f(b bool) { if b { time.Sleep(1) } }\n", true},
		{"in a for body", "package x\nimport \"time\"\nfunc f() { for !done() { time.Sleep(1) } }\nfunc done() bool { return true }\n", false},
		{"in the post statement of a for", "package x\nimport \"time\"\nfunc f() { for end := time.Now(); time.Now().Before(end); time.Sleep(1) {} }\n", false},
		{"in a range", "package x\nimport \"time\"\nfunc f(c chan int) { for range c { time.Sleep(1) } }\n", false},
		{"in a closure inside a loop", "package x\nimport \"time\"\nfunc f() { for { func() { time.Sleep(1) }() } }\n", false},
		{"a sleep of another package", "package x\nimport \"time\"\ntype s struct{}\nfunc (s) Sleep(int) {}\nfunc f() { var z s; z.Sleep(1); _ = time.Second }\n", false},
		// Round 18, tenant-r18-4: the clock waits other than Sleep, in every test file. A deadline of a select whose case
		// fails the test is the only allowed shape; a timer that is the success path is a wait on the clock.
		{"a receive from time.After", "package x\nimport \"time\"\nfunc f() { <-time.After(time.Second) }\n", true},
		{"a select whose timer case does nothing", "package x\nimport \"time\"\nfunc f(c chan int) { select { case <-c: case <-time.After(1): } }\n", true},
		{"a select whose timer case returns", "package x\nimport \"time\"\nfunc f(c chan int) int { select { case <-c: return 1; case <-time.After(1): return 0 } }\n", true},
		{"a timer", "package x\nimport \"time\"\nfunc f() { t := time.NewTimer(1); <-t.C }\n", true},
		{"a ticker", "package x\nimport \"time\"\nfunc f() { t := time.NewTicker(1); <-t.C }\n", true},
		{"a tick channel", "package x\nimport \"time\"\nfunc f() { <-time.Tick(1) }\n", true},
		{"AfterFunc", "package x\nimport \"time\"\nfunc f() { time.AfterFunc(1, func() {}) }\n", true},
		{"an aliased import of the timer", "package x\nimport tm \"time\"\nfunc f(c chan int) { select { case <-c: case <-tm.After(1): } }\n", true},
		{"time.After kept in a variable", "package x\nimport (\"time\"; \"testing\")\nfunc f(t *testing.T, c chan int) { d := time.After(1); select { case <-c: case <-d: t.Fatal(1) } }\n", true},
		{"a deadline whose case fails the test", "package x\nimport (\"time\"; \"testing\")\nfunc f(t *testing.T, c chan int) { select { case <-c: case <-time.After(time.Second): t.Fatalf(\"x\") } }\n", false},
		{"a deadline whose case panics", "package x\nimport \"time\"\nfunc f(c chan int) { select { case <-c: case <-time.After(time.Second): panic(\"x\") } }\n", false},
		{"a deadline in a closure", "package x\nimport (\"time\"; \"testing\")\nfunc f(t *testing.T, c chan int) { go func() { select { case <-c: case <-time.After(time.Second): t.Error(1) } }() }\n", false},
		{"a deadline on a testing.TB", "package x\nimport (\"time\"; \"testing\")\nfunc f(t testing.TB, c chan int) { select { case <-c: case <-time.After(time.Second): t.FailNow() } }\n", false},
		{"a deadline with the testing package renamed", "package x\nimport (\"time\"; tt \"testing\")\nfunc f(t *tt.T, c chan int) { select { case <-c: case <-time.After(time.Second): t.Fatal(1) } }\n", false},
		// Round 18, tenant-r18-16: the case must FAIL the test, by a method of a testing type on a parameter of that type.
		{"an Error method of an error is no failure", "package x\nimport (\"time\"; \"errors\")\nfunc f(c chan int) { select { case <-c: case <-time.After(1): _ = errors.New(\"x\").Error() } }\n", true},
		{"a Fatal of a local interface is no failure", "package x\nimport \"time\"\ntype T interface{ Fatal(...any) }\nfunc f(t T, c chan int) { select { case <-c: case <-time.After(1): t.Fatal(1) } }\n", true},
		{"a timer in the body of a case that fails", "package x\nimport (\"time\"; \"testing\")\nfunc f(t *testing.T, c chan int) { select { case <-c: <-time.After(300 * time.Millisecond); t.Fatal(1) } }\n", true},
		{"a timer in the body of the other case", "package x\nimport (\"time\"; \"testing\")\nfunc f(t *testing.T, c, d chan int) { select { case <-c: <-time.After(1); case <-d: t.Fatal(1) } }\n", true},
		{"a failure that is a branch of the case", "package x\nimport (\"time\"; \"testing\")\nfunc f(t *testing.T, c chan int, b bool) { select { case <-c: case <-time.After(1): if b { t.Fatal(1) } } }\n", true},
		{"a failure inside a closure the case starts", "package x\nimport (\"time\"; \"testing\")\nfunc f(t *testing.T, c chan int) { select { case <-c: case <-time.After(1): go func() { t.Fatal(1) }() } }\n", true},
		{"a method of the testing type that does not fail", "package x\nimport (\"time\"; \"testing\")\nfunc f(t *testing.T, c chan int) { select { case <-c: case <-time.After(1): t.Log(1) } }\n", true},
		{"a deadline that fails through a field that holds the test", "package x\nimport (\"time\"; \"testing\")\ntype lab struct{ t *testing.T }\nfunc (l *lab) f(c chan int) { select { case <-c: case <-time.After(time.Second): l.t.Fatal(1) } }\n", false},
		{"a field of another type is no handle", "package x\nimport \"time\"\ntype fake struct{}\nfunc (fake) Fatal(...any) {}\ntype lab struct{ t fake }\nfunc (l *lab) f(c chan int) { select { case <-c: case <-time.After(time.Second): l.t.Fatal(1) } }\n", true},
		{"a field that is not declared in the package is no handle", "package x\nimport \"time\"\nfunc (l *lab) f(c chan int) { select { case <-c: case <-time.After(time.Second): l.t.Fatal(1) } }\n", true},
		{"a field of a shadowed receiver", "package x\nimport (\"time\"; \"testing\")\ntype lab struct{ t *testing.T }\ntype fake struct{ t interface{ Fatal(...any) } }\nfunc (l *lab) f(c chan int) { l := fake{}; select { case <-c: case <-time.After(time.Second): l.t.Fatal(1) } }\n", true},
		{"a receiver shadowed by a fake", "package x\nimport (\"time\"; \"testing\")\ntype fake struct{}\nfunc (fake) Fatal(...any) {}\nfunc f(t *testing.T, c chan int) { { t := fake{}; select { case <-c: case <-time.After(1): t.Fatal(1) } } }\n", true},
		{"a receiver that is not a parameter", "package x\nimport (\"time\"; \"testing\")\nvar t *testing.T\nfunc f(c chan int) { select { case <-c: case <-time.After(1): t.Fatal(1) } }\n", true},
		{"a panic that is redeclared", "package x\nimport \"time\"\nfunc f(c chan int) { panic := func(any) {}; select { case <-c: case <-time.After(1): panic(1) } }\n", true},
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
		{"two aliases of time, the sleep through the first", "package x\nimport a \"time\"\nimport b \"time\"\nfunc f() { a.Sleep(1); _ = b.Second }\n", true},
		{"two aliases of time, the sleep through the last", "package x\nimport a \"time\"\nimport b \"time\"\nfunc f() { _ = a.Second; b.Sleep(1) }\n", true},
		{"two imports of testwait, the answer dropped through the first", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nimport w \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f() { testwait.Holds(1, 1, func() bool { return true }) }\n", true},
		{"two imports of testwait, the answer dropped through the last", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nimport w \"github.com/Kup1ng/CtrlZ-Panel/internal/testwait\"\nfunc f() { w.Holds(1, 1, func() bool { return true }) }\n", true},
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
		for _, p := range testSleepProblemsWith(path, string(b), nil, packageSources(filepath.Dir(filepath.Join(root, filepath.FromSlash(path))), filepath.Join(root, filepath.FromSlash(path)))...) {
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

// packageSources reads the other Go files of a directory (the package of the file under test), so the lint can
// find the struct fields that hold a test. The file itself is left out: its own source is read already.
func packageSources(dir, self string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || p == self {
			continue
		}
		if b, err := os.ReadFile(p); err == nil {
			out = append(out, string(b))
		}
	}
	return out
}

// TestASleepDeadlineMayFailThroughAFieldDeclaredInAnotherFile plants the lab of the catalog tests: the struct that
// holds the *testing.T is declared in a sibling file, and the deadline fails the test through it.
func TestASleepDeadlineMayFailThroughAFieldDeclaredInAnotherFile(t *testing.T) {
	const use = "package x\nimport \"time\"\nfunc (l *lab) f(c chan int) { select { case <-c: case <-time.After(time.Second): l.t.Fatal(1) } }\n"
	const real = "package x\nimport \"testing\"\ntype lab struct{ t *testing.T }\n"
	const other = "package x\ntype lab struct{ t interface{ Fatal(...any) } }\n"
	if got := testSleepProblems("x/x_test.go", use, real); len(got) != 0 {
		t.Errorf("a deadline through a testing field of a sibling file was refused: %v", got)
	}
	if got := testSleepProblems("x/x_test.go", use, other); len(got) == 0 {
		t.Error("a deadline through a field of another type passed")
	}
	if got := testSleepProblems("x/x_test.go", use); len(got) == 0 {
		t.Error("a deadline through a field nobody declares passed")
	}
}
