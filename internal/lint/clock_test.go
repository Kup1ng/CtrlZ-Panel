package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/clockrule"
)

// The clock rule (P1 auth review, round 5, topic clock-source; spec 3.3, 3.5, 4.5,
// 10.2, 10.5, 16.1).
//
// Every security timestamp column has one clock, declared in
// migrations/catalog/clocks.yaml. Two things keep that true for code nobody has
// written yet:
//
//  1. Every SQL constant that reaches a database call is judged by clockrule: a
//     statement that names an application-clock column and reads a database clock
//     fails, and so does one that hands a database-clock column to Go as a time or
//     writes or compares it with a Go value. The live bodies of the definer
//     functions and the column defaults are judged by catalog check 24.
//  2. Go reads the time from one place. time.Now, time.Since and time.Until are
//     called in internal/appclock and nowhere else under internal/auth, internal/api,
//     internal/adminapi and internal/store, so a test that moves the application
//     clock moves every window, and a window cannot be decided by a clock the test
//     did not move.
//
// The boundary test (internal/store, TestClockWindows) moves the application clock
// three hours either way for every app and db column of the registry.

// clockProblems judges every constant SQL text that reaches a database call.
func clockProblems(fset *token.FileSet, files []file, reg *clockrule.Registry) []string {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	var out []string
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			idx, isSink := sqlSinks()[calleeName(call.Fun)]
			if !isSink || idx < 0 || len(call.Args) <= idx {
				return true
			}
			tv, known := info.Types[call.Args[idx]]
			if !known || tv.Value == nil || tv.Value.Kind() != constant.String {
				return true // the sql-const rule reports it
			}
			for _, fd := range reg.Analyze(constant.StringVal(tv.Value), clockrule.Options{GoBound: true}) {
				out = append(out, fmt.Sprintf("%s:%d: %s", f.path, fset.Position(call.Pos()).Line, fd))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// timeSafe are the members of package time that do not read the machine's clock: the types, the
// constants and the functions that make or parse a value, and the timers (which count a length of
// time and compare nothing with a stamp). Every other member of the package is a read of the clock
// (Now, Since, Until today) or something nobody has classified, and a use of it is judged by
// wallClockProblems. TestTimeMembersAreAllClassified reads the real package, so a member a later Go
// release adds fails until a person puts it on one side.
var timeSafe = map[string]bool{
	"Time": true, "Duration": true, "Month": true, "Weekday": true, "Location": true, "Timer": true, "Ticker": true,
	"ParseError": true, "UTC": true, "Local": true,
	"Unix": true, "UnixMilli": true, "UnixMicro": true, "Date": true, "Parse": true, "ParseInLocation": true,
	"ParseDuration": true, "LoadLocation": true, "LoadLocationFromTZData": true, "FixedZone": true,
	"NewTimer": true, "NewTicker": true, "After": true, "AfterFunc": true, "Tick": true, "Sleep": true,
	"Nanosecond": true, "Microsecond": true, "Millisecond": true, "Second": true, "Minute": true, "Hour": true,
	"Layout": true, "ANSIC": true, "UnixDate": true, "RubyDate": true, "RFC822": true, "RFC822Z": true, "RFC850": true,
	"RFC1123": true, "RFC1123Z": true, "RFC3339": true, "RFC3339Nano": true, "Kitchen": true, "Stamp": true,
	"StampMilli": true, "StampMicro": true, "StampNano": true, "DateTime": true, "DateOnly": true, "TimeOnly": true,
	"January": true, "February": true, "March": true, "April": true, "May": true, "June": true, "July": true,
	"August": true, "September": true, "October": true, "November": true, "December": true,
	"Sunday": true, "Monday": true, "Tuesday": true, "Wednesday": true, "Thursday": true, "Friday": true, "Saturday": true,
}

// timeClockReaders are the members that read the machine's clock.
var timeClockReaders = map[string]bool{"Now": true, "Since": true, "Until": true}

// wallUse is a file that may read the machine's clock, with how many reads it holds and why that is
// not a security window decided on the wrong clock.
type wallUse struct {
	n   int
	why string
}

// wallClockAllowed is every declaration of a non-test file of the module that reads the machine's clock, by exact
// count (round 16, primitives-r16-5 and -14). The rule it replaces covered four directories by
// prefix (internal/auth, api, adminapi, store), so a package outside them (a worker, the hub, the
// console, a new one) could compare a security column with time.Now() and nothing failed. Now the
// rule is the other way round: a read of the clock is refused in EVERY non-test file of the module
// unless the declaration is here, so a new package starts refused. A key is a site ("file::Func" or
// "file::Type.Method", sites_test.go; primitives-r18-23: the list was keyed by file, so another function
// of a listed file that compared a stored stamp with the clock kept the count of the file and passed). A
// site stays only while it holds exactly this many reads (a new read in a listed declaration fails too),
// and an entry with no read left is stale.
//
// The listed declarations read the clock for something that is not a window on a stored security stamp:
// the default of an injected clock (the component takes `now` and a test replaces it), a length
// measured between two readings of the same machine, or a test helper. A reason that stops being
// true is a defect of the entry.
func wallClockAllowed() map[string]wallUse {
	const injected = "the default of an injected clock (`now`, `Now`): the component decides its windows on the function it is given and a test replaces it; it reads no stored security stamp"
	return map[string]wallUse{
		"internal/admincli/admincli.go::Env.withDefaults":  {1, injected},
		"internal/afterwork/afterwork.go::New":             {1, injected},
		"internal/cachex/loader.go::New":                   {1, injected + " (the TTL and pause of a cache)"},
		"internal/ratelimit/limiter.go::New":               {1, injected + " (the bucket refill of the limiter, which stamps its own keys)"},
		"internal/sms/router.go::NewRouter":                {1, injected + " (the breaker pause)"},
		"internal/sms/router.go::Router.try":               {1, "a length: the time left of the caller's deadline"},
		"internal/worker/adminjobs/adminjobs.go::New":      {1, injected + " (the retry backoff of a job)"},
		"internal/worker/smssend/worker.go::New":           {1, injected},
		"internal/worker/smssend/worker.go::Worker.claim":  {1, "a length: the reading before the claim, plus the lease the database reports, is the end of the send budget (a database length, never a stamp compared with the clock)"},
		"internal/worker/smssend/worker.go::Worker.send":   {1, "a length: the reading before the claim, plus the lease the database reports, is the end of the send budget (a database length, never a stamp compared with the clock)"},
		"internal/httpx/floor.go::sanitizedWriter.Write":   {1, "a length: the spacing of the log lines of a recovered write error, measured between two readings of one machine"},
		"internal/httpx/pipeline.go::API.serveHeavy":       {2, "a length: the start of the body and the start of the answer of a heavy request, from which the earned deadlines of the connection are counted (6.5 property 3; no stored stamp)"},
		"internal/migrate/migrate.go::WaitReady":           {2, "a length: the retry deadline of the migrate start against a database that is not up yet"},
		"internal/authtest/oracle/oracle.go::Fire":         {2, "a length: the duration of one request, the timing floor's measurement of the oracle test (a test harness)"},
		"internal/testpg/testpg.go::Cluster.StartPostgres": {2, "a length: the wait for a container to accept connections (a test harness)"},
		"internal/testpg/wiring.go::Wiring.Stop":           {2, "a length: how long the container took to stop, measured between two readings of one machine (a test harness)"},
		"internal/testvalkey/testvalkey.go::Server.Resume": {2, "a length: the wait for a container to accept connections (a test harness)"},
	}
}

// wallClockProblems reports reads of the machine's clock outside the allow list.
func wallClockProblems(fset *token.FileSet, files []file) []string {
	return wallClockProblemsWith(fset, files, wallClockAllowed())
}

func wallClockProblemsWith(fset *token.FileSet, files []file, allowed map[string]wallUse) []string {
	var out []string
	seen := map[string]bool{} // the files that import time and were read
	counts := map[string]int{}
	first := map[string]token.Pos{}
	for _, f := range files {
		// internal/appclock is the one package that is the application clock.
		if f.test || strings.HasPrefix(f.path, "internal/appclock/") {
			continue
		}
		// Every name the file gives package time is judged (localNames, round 18, primitives-r18-6):
		// the loop kept the last one, so `import ("time"; _ "time")` made the name "_" and the whole
		// file was skipped.
		allNames := localNames(f.ast, "time")
		if hasDot(allNames) {
			// Under a dot import a member is a bare identifier, which no selector judges.
			out = append(out, fmt.Sprintf("%s: dot-imports time; use the package name so each member is judged", f.path))
		}
		timeNames := usableNames(allNames)
		if len(timeNames) == 0 {
			continue
		}
		seen[f.path] = true
		walkSites(f.path, f.ast, func(site string, n ast.Node) {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || timeSafe[sel.Sel.Name] {
				return
			}
			if id, ok := sel.X.(*ast.Ident); ok && slices.Contains(timeNames, id.Name) && id.Obj == nil {
				if site == "" {
					site = f.path + "::" // a read outside every function
				}
				if counts[site] == 0 {
					first[site] = sel.Pos()
				}
				counts[site]++
			}
		})
	}
	for site, reads := range counts {
		switch want, listed := allowed[site]; {
		case !listed:
			out = append(out, fmt.Sprintf("%s:%d: time.* reads the machine's clock (%d times) in %s; use internal/appclock, or list the declaration in wallClockAllowed with the reason it decides no window on a stored stamp", pathOfSite(site), fset.Position(first[site]).Line, reads, site))
		case want.n != reads:
			out = append(out, fmt.Sprintf("%s reads the machine's clock %d times and wallClockAllowed lists %d; a new read is a new judgement", site, reads, want.n))
		}
	}
	for site, u := range allowed {
		if u.why == "" || u.n < 1 {
			out = append(out, fmt.Sprintf("wallClockAllowed lists %s with no reason or no count", site))
		}
		switch path := pathOfSite(site); {
		case !seen[path]:
			out = append(out, fmt.Sprintf("wallClockAllowed lists %s, which is not a non-test file of the module that imports time", site))
		case counts[site] == 0:
			out = append(out, fmt.Sprintf("%s is on the list of declarations that read the machine's clock and reads it no more; take it off", site))
		}
	}
	sort.Strings(out)
	return out
}

// pathOfSite is the file of a site ("file::Func").
func pathOfSite(site string) string {
	p, _, _ := strings.Cut(site, "::")
	return p
}

// clockFiles is every non-test Go file the machine-clock rule judges: the module and shared/. shared/
// is a separate module that parseRepo leaves out, but Panel imports it and the Node repository copies
// it, so a helper there that compares a stored expiry with time.Now() runs inside the Panel process
// (round 16 fix gate, primitives-r16-20). The files are parsed into one file set.
func clockFiles(t *testing.T) (*token.FileSet, []file) {
	t.Helper()
	fset, files := parseRepo(t)
	return fset, append(files, parseSharedTreeInto(t, fset, parser.ParseComments)...)
}

func TestClockRule(t *testing.T) {
	reg, err := clockrule.Load()
	if err != nil {
		t.Fatal(err)
	}
	fset, files := clockFiles(t)
	for _, p := range clockProblems(fset, files, reg) {
		t.Error(p)
	}
	for _, p := range wallClockProblems(fset, files) {
		t.Error(p)
	}
}

// TestClockRuleReadsShared holds the second half of that: the files the rule is given include
// shared/, and a read of the machine's clock in a file of it is refused like any other.
func TestClockRuleReadsShared(t *testing.T) {
	fset, files := clockFiles(t)
	n := 0
	for _, f := range files {
		if strings.HasPrefix(f.path, "shared/") {
			n++
		}
	}
	if n < 10 {
		t.Fatalf("%d files of shared/ reach the clock rule; the walk is wrong", n)
	}
	src := `package p
import "time"
func Expired(t time.Time) bool { return time.Now().After(t) }
`
	af, err := parser.ParseFile(fset, "shared/quarantine/x.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	if got := wallClockProblems(fset, append(files, file{path: "shared/quarantine/x.go", ast: af})); len(got) != 1 {
		t.Errorf("a clock read in shared/: %d problems %v, want 1", len(got), got)
	}
}

// TestClockRuleCanFail plants code that breaks each part of the rule and expects
// the lint to say so. A lint that cannot fail proves nothing.
func TestClockRuleCanFail(t *testing.T) {
	reg, err := clockrule.Parse([]byte(`
tables:
  sessions: {idle_expires_at: app, reauth_at: app, last_seen_at: app, revoked_at: stamp}
  admin_sessions: {totp_verified_at: app, revoked_at: stamp}
  users: {password_expires_at: db, enforce_lift_at: app, last_login_at: stamp, totp_pending_at: db}
  invites: {expires_at: db}
read: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	const header = "package p\n"
	sql := []struct {
		name, src string
		want      int
	}{
		{"app column stamped by now()", "func f() { db.Exec(ctx, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() WHERE id = $1`) }", 1},
		{"app column compared with now() in a join", "func f() { db.Exec(ctx, `SELECT 1 FROM ctrlz.sessions s WHERE s.idle_expires_at > pg_catalog.now()`) }", 1},
		{"app column next to a clock keyword", "func f() { db.Exec(ctx, `UPDATE ctrlz.sessions SET idle_expires_at = $2, last_seen_at = CURRENT_TIMESTAMP WHERE id = $1`) }", 2},
		{"app column by a clock string", "func f() { db.Exec(ctx, `UPDATE ctrlz.sessions SET reauth_at = 'now'::timestamptz WHERE id = $1`) }", 1},
		{"app column set from a parameter is the rule", "func f() { db.Exec(ctx, `UPDATE ctrlz.admin_sessions SET totp_verified_at = $2::timestamptz WHERE id = $1`) }", 0},
		{"a stamp column with now() is fine", "func f() { db.Exec(ctx, `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = $1`) }", 0},
		{"db column selected", "func f() { db.QueryRow(ctx, `SELECT password_expires_at FROM ctrlz.users WHERE id = $1`) }", 1},
		{"db column selected through RETURNING", "func f() { db.QueryRow(ctx, `UPDATE ctrlz.users SET totp_pending_at = now() WHERE id = $1 RETURNING totp_pending_at`) }", 1},
		{"db column selected through a star", "func f() { db.QueryRow(ctx, `SELECT * FROM ctrlz.invites WHERE id = $1`) }", 1},
		{"db column decided in SQL is fine", "func f() { db.QueryRow(ctx, `SELECT COALESCE(password_expires_at <= now(), false) FROM ctrlz.users WHERE id = $1`) }", 0},
		{"db column in a CTE returning is not Go-bound", "func f() { db.QueryRow(ctx, `WITH r AS (UPDATE ctrlz.users SET last_login_at = now() RETURNING password_expires_at) SELECT count(*) FROM r`) }", 0},
		{"db column compared with a parameter", "func f() { db.Exec(ctx, `SELECT 1 FROM ctrlz.invites WHERE expires_at > $1`) }", 1},
		{"db column compared with a cast parameter on the left", "func f() { db.Exec(ctx, `SELECT 1 FROM ctrlz.invites WHERE $1::timestamptz < expires_at`) }", 1},
		{"db column written from a parameter", "func f() { db.Exec(ctx, `UPDATE ctrlz.invites SET expires_at = $2 WHERE id = $1`) }", 1},
		{"db column inserted from a parameter", "func f() { db.Exec(ctx, `INSERT INTO ctrlz.invites (token_hash, expires_at) VALUES ($1, $2)`) }", 1},
		{"db column written from the clock and a parameter is fine", "func f() { db.Exec(ctx, `INSERT INTO ctrlz.invites (token_hash, expires_at) VALUES ($1, now() + make_interval(secs => $2))`) }", 0},
	}
	for _, c := range sql {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "internal/store/x.go", header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := clockProblems(fset, []file{{path: "internal/store/x.go", ast: af}, filler(t, fset)}, reg)
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}

	wall := []struct {
		name, path, src string
		want            int
	}{
		{"time.Now in the api", "internal/api/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }", 1},
		{"time.Since in the store", "internal/store/x.go", "import \"time\"\nfunc f(t time.Time) time.Duration { return time.Since(t) }", 1},
		{"time.Now as a value", "internal/auth/login/x.go", "import \"time\"\nvar now = time.Now", 1},
		{"an aliased import", "internal/adminapi/x.go", "import tm \"time\"\nfunc f() tm.Time { return tm.Now() }", 1},
		{"a blank import beside the name", "internal/worker/x.go", "import \"time\"\nimport _ \"time\"\nfunc f(s time.Time) bool { return time.Now().After(s) }", 1},
		{"two aliases of time", "internal/worker/x.go", "import a \"time\"\nimport b \"time\"\nfunc f(s a.Time) bool { return a.Now().After(s) }\nvar _ = b.Second", 1},
		{"a read through the second alias", "internal/worker/x.go", "import a \"time\"\nimport b \"time\"\nfunc f(s a.Time) bool { return b.Now().After(s) }", 1},
		{"internal/clock is the place for it", "internal/appclock/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }", 0},
		{"time.Unix is not a read of the clock", "internal/api/y.go", "import \"time\"\nfunc f() time.Time { return time.Unix(0, 0) }", 0},
		// Round 16 (primitives-r16-5, -14): every package is judged, not four directories.
		{"a worker reads the clock", "internal/worker/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }", 1},
		{"the hub reads the clock", "internal/hub/x.go", "import \"time\"\nfunc f(t time.Time) bool { return time.Now().Before(t) }", 1},
		{"a command reads the clock", "cmd/ctrlz/x.go", "import \"time\"\nfunc f(t time.Time) time.Duration { return time.Until(t) }", 1},
		{"a package nobody has written yet", "internal/newthing/x.go", "import \"time\"\nvar clock = time.Now", 1},
		{"a tool reads the clock", "tools/x/main.go", "import \"time\"\nfunc f() { _ = time.Now() }", 1},
		{"a member nobody classified", "internal/hub/x.go", "import \"time\"\nfunc f() { _ = time.Frobnicate() }", 1},
		{"a dot import of time", "internal/hub/x.go", "import . \"time\"\nfunc f() Time { return Now() }", 1},
		{"a local variable called time is not the package", "internal/hub/x.go", "type clk struct{ Now func() int }\nfunc f(time clk) int { return time.Now() }", 0},
		{"a parameter called time next to the import is not the package", "internal/hub/x.go", `import "time"
func f(d time.Duration, time struct{ Now func() int }) int { _ = d; return time.Now() }`, 0},
		{"durations, parsing and timers are not reads", "internal/hub/x.go", "import \"time\"\nfunc f() { _ = time.Second * 3; _, _ = time.Parse(time.RFC3339, \"\"); _ = time.NewTimer(time.Minute); time.Sleep(time.Millisecond) }", 0},
		{"a listed file with its count", "internal/listed/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }", 0},
		{"a listed file with one more read", "internal/listed/x.go", "import \"time\"\nfunc f() (time.Time, time.Duration) { t := time.Now(); return t, time.Since(t) }", 1},
		{"a listed file with one read fewer", "internal/listed2/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }", 1},
		{"a listed file that no longer reads", "internal/listed/x.go", "import \"time\"\nfunc f() time.Duration { return time.Second }", 1},
		// primitives-r18-23: the exception is a declaration, not a file.
		{"another function of a listed file", "internal/listed/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }\nfunc g() time.Time { return time.Now() }", 1},
		{"a method of a listed file", "internal/listed/x.go", "import \"time\"\ntype T struct{}\nfunc (T) f() time.Time { return time.Now() }", 2},
		{"a read at package level of a listed file", "internal/listed/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }\nvar boot = time.Now()", 1},
	}
	listed := map[string]wallUse{"internal/listed/x.go::f": {1, "the default of an injected clock"}, "internal/listed2/x.go::f": {2, "two"}}
	for _, c := range wall {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := wallClockProblemsWith(fset, []file{{path: c.path, ast: af}}, listed)
		// Entries of the list whose file was not part of this run are reported as stale; they are not
		// what the case asks about.
		var own []string
		for _, p := range got {
			if !strings.HasPrefix(p, "wallClockAllowed lists") {
				own = append(own, p)
			}
		}
		if len(own) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(own), own, c.want)
		}
		// Each stale and miscounted case says its own thing, so a clause that is deleted while another
		// one still reports the file is noticed (primitives-r16-19).
		if sub, ok := map[string]string{
			"a listed file that no longer reads":       "reads it no more",
			"another function of a listed file":        "time.* reads the machine's clock",
			"a read at package level of a listed file": "time.* reads the machine's clock",
			"a listed file with one more read":         "a new read is a new judgement",
			"a listed file with one read fewer":        "a new read is a new judgement",
			"a dot import of time":                     "dot-imports time",
			"a package nobody has written yet":         "time.* reads the machine's clock",
		}[c.name]; ok && (len(own) != 1 || !strings.Contains(own[0], sub)) {
			t.Errorf("%s: %v, want a problem containing %q", c.name, own, sub)
		}
	}
	// An entry with no reason or no count, and an entry for a file that does not exist.
	if got := wallClockProblemsWith(token.NewFileSet(), nil, map[string]wallUse{"internal/gone/x.go": {1, "gone"}, "internal/bare/x.go": {0, ""}}); len(got) != 3 {
		t.Errorf("stale and bare entries: %d problems %v, want 3", len(got), got)
	}
}

// TestTimeMembersAreAllClassified reads the real package time: every exported member is either one
// that does not read the machine's clock (timeSafe) or one that does (timeClockReaders), and both
// lists name only members that exist. A member a later Go release adds is a failure here until a
// person decides which it is, and until then the wall-clock rule refuses a file that uses it.
func TestTimeMembersAreAllClassified(t *testing.T) {
	pkg, err := stdlibImporter().Import("time")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, name := range pkg.Scope().Names() {
		if !token.IsExported(name) {
			continue
		}
		declared[name] = true
		if !timeSafe[name] && !timeClockReaders[name] {
			t.Errorf("time.%s is in neither timeSafe nor timeClockReaders; decide whether it reads the machine's clock", name)
		}
		if timeSafe[name] && timeClockReaders[name] {
			t.Errorf("time.%s is on both lists", name)
		}
	}
	for name := range timeSafe {
		if !declared[name] {
			t.Errorf("timeSafe lists time.%s, which the package does not declare", name)
		}
	}
	for name := range timeClockReaders {
		if !declared[name] {
			t.Errorf("timeClockReaders lists time.%s, which the package does not declare", name)
		}
	}
}
