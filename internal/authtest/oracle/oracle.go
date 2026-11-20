// Package oracle is the harness of the known-or-unknown rule (P1 auth review
// round 5, rules.md topic 4): whether a phone or a username has an account may
// change only the sealed SMS payload and the final session or ticket. It never
// selects a status, a body, a header, a cookie, a counter write or refund, a
// gate acquisition, or a number of Argon2 or scoring runs.
//
// The package holds what both services' oracle tests share: how a request is
// fired and reduced to an Observation, how two Observations are compared, the
// declared exception list, the registered fault states, and the walk over the
// x-ctrlz-auth none operations of the OpenAPI documents. It is imported from test
// files only, like authtest.
//
// Why a harness and not more per-route assertions: every earlier round wrote the
// known and the unknown branch separately and asserted sameness by hand on the
// dimension the author thought of (a 429 after a spent scope, a second Argon2
// run, a worker refund, a busy gate). Each fix left the next dimension open. A
// comparison of everything an outside observer or the shared counters can see,
// under every fault, leaves no dimension to forget.
package oracle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"time"
)

// States are the registered fault states. A test must give every one of them an
// action (an explicit no-op with a reason when the state cannot touch its
// service), so a state added here and handled nowhere fails the test.
const (
	StateNone             = "none"              // everything works; the worker delivers
	StateGateHeld         = "gate_held"         // every Argon2 and scoring slot is taken
	StateScopeSpent       = "scope_spent"       // every throttle and SMS counter the subject touched is over its limit
	StateTemplateUnmapped = "template_unmapped" // no gateway maps any template
	StateProvider404      = "provider_404"      // the gateway answers 404 to every call
	StateProviderFlapping = "provider_flapping" // the gateway fails, but another user's success keeps the breaker shut
	StateDatabaseDown     = "database_down"     // Postgres is stopped
	StateWorkerFailing    = "worker_failing"    // the worker cannot open the sealed payload

	// The next four end the subject's real row by each way a row can end unsent or refused
	// (sms-r5-1, sms-r5-2, sms-r5-7). A refund that depends on how a row ended shows up here
	// as a counter a decoy does not share.
	StateRecipientRefused   = "recipient_refused"     // the gateway answers that the number is not a valid recipient
	StateBlacklisted        = "blacklisted"           // the gateway answers that the number is on the telecom blacklist
	StateBreakerOpensMidRow = "breaker_opens_mid_row" // the breakers open after the request was accepted and before the worker ends the row (a failed probe after a pause lapses is the same)
	StateWorkerDown         = "worker_down"           // no worker runs; the row expires unsent and the sweep ends it

	// The hold of a refused login (0043, 0046, 0048) is a state only a real delivery can place: a decoy
	// never reaches a gateway. It feeds the public flag after ONE refused send, where the breaker needs
	// three, so it is registered on its own (sms-r15-5): a change that, for example, refunded per-phone
	// keys on a held ending, or moved the hold into a counter, would otherwise pass unseen.
	StateProviderRefusedLogin = "provider_refused_login" // the gateway answers that its login (key or password) is refused

	// A real OTP request takes the row lock of the one global counter and queues behind every other real
	// send; a decoy that skipped the row waited for nobody (tenant-r16-11). The state holds that row in a
	// second session, so a request that touches it waits for the lock timeout and answers 503: a phone with
	// an account and one without must wait for the same thing. A difference of TIME is not a declared
	// exception: the exception list names things, and this state has none.
	StateGlobalCounterHeld = "global_counter_held" // another session holds the row lock of the global SMS counter
)

// AllStates is the registry, in the order the tests run them.
func AllStates() []string {
	return []string{
		StateNone, StateGateHeld, StateScopeSpent, StateTemplateUnmapped,
		StateProvider404, StateProviderFlapping, StateWorkerFailing,
		StateRecipientRefused, StateBlacklisted, StateProviderRefusedLogin, StateBreakerOpensMidRow, StateWorkerDown,
		StateGlobalCounterHeld, StateDatabaseDown,
	}
}

// Request is one HTTP request to a service under test.
type Request struct {
	Method  string
	Path    string // relative to /api/v1
	Body    any    // nil, string, []byte or a value to marshal as JSON
	Header  map[string]string
	Cookies map[string]string
}

// Raw is a response as the wire shows it.
type Raw struct {
	Status int
	Header http.Header
	Body   []byte
	Dur    time.Duration
}

// Fire sends r to h as a client at ip, on host.
func Fire(h http.Handler, host, ip string, r Request) (Raw, error) {
	var rd io.Reader
	switch b := r.Body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return Raw{}, err
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(r.Method, "/api/v1"+r.Path, rd)
	req.Host = host
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "oracle-test")
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range r.Header {
		req.Header.Set(k, v)
	}
	for k, v := range r.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(w, req)
	return Raw{Status: w.Code, Header: w.Header(), Body: w.Body.Bytes(), Dur: time.Since(start)}, nil
}

// Tally is what one counter scope holds: how many rows it has, the sum of their
// counts and, for the SMS global scope, the money.
type Tally struct {
	Rows int64 `json:"rows"`
	Sum  int64 `json:"sum"`
	Cost int64 `json:"cost"` // units of 1e-4
}

// Sub is t - o, the movement between two snapshots.
func (t Tally) Sub(o Tally) Tally { return Tally{t.Rows - o.Rows, t.Sum - o.Sum, t.Cost - o.Cost} }

// Zero says the scope did not move.
func (t Tally) Zero() bool { return t == Tally{} }

// Meters are the costs the request is not allowed to vary with the account.
type Meters struct {
	Argon2   uint64 // password hashes and verifications actually computed
	Scorings uint64 // calls that reached a scoring gate
	Gates    uint64 // calls that reached an Argon2 or scoring gate, refused ones included
	// Pool is how many times the request asked the database pool for a connection before its
	// answer was returned, the floor included (tenant-r13-2). Each ask is a wait under a busy
	// pool, and the floor hides only a wait of the same size for everyone, so a branch that asks
	// once more for a phone with an account tells it from one without by time. Compared with no
	// exception: nothing the account chooses may happen in front of the answer.
	Pool uint64
	// PoolAfter is how many times the work the request left for after its floor asked the pool
	// (the failed-login trail row). It is compared too, and the only exception is the one the
	// spec declares for the row itself: written after the answer, so no wait of it is in the
	// answer's time.
	PoolAfter uint64
}

// Sub is m - o.
func (m Meters) Sub(o Meters) Meters {
	return Meters{m.Argon2 - o.Argon2, m.Scorings - o.Scorings, m.Gates - o.Gates, m.Pool - o.Pool, m.PoolAfter - o.PoolAfter}
}

// Obs is everything the rule says the account may not change.
type Obs struct {
	Status   int
	Body     string
	Header   []string
	Cookies  []string
	SMS      map[string]Tally // sms_counters movement by scope, after the worker drained
	Throttle map[string]Tally // auth_throttle movement by scope
	Gateways map[string]Tally // breaker and hold movement (failures, open, held, blocked, public_sms_available), after the worker drained
	Meters   Meters
	Dur      time.Duration
}

var (
	reUUID  = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reToken = regexp.MustCompile(`[A-Za-z0-9_-]{22,}`)
	// How long a window has left depends on when it was opened, not on the account.
	reRetry = regexp.MustCompile(`"retry_after_s":[0-9]+`)
	reReqID = regexp.MustCompile(`"request_id":"[0-9a-f]+"`)
	reTime  = regexp.MustCompile(`\d{4}-\d\d-\d\dT[\d:.]+(Z|[+-]\d\d:\d\d)`)
)

// NormalizeBody removes what is random or clock-bound in a body and nothing
// else: identifiers, tokens and instants. A field the account decides survives
// the pass and shows up in the comparison.
func NormalizeBody(b []byte) string {
	s := string(b)
	s = reRetry.ReplaceAllString(s, `"retry_after_s":"<n>"`)
	s = reReqID.ReplaceAllString(s, `"request_id":"<id>"`)
	s = reUUID.ReplaceAllString(s, "<uuid>")
	s = reTime.ReplaceAllString(s, "<time>")
	s = reToken.ReplaceAllString(s, "<token>")
	return s
}

// volatile headers differ between two requests for reasons that say nothing about
// the account: the instant, and ids made per request. Their presence is still
// compared.
func volatile(name string) bool {
	switch name {
	case "Date", "X-Request-Id", "Retry-After", "Content-Length":
		return true
	}
	return false
}

// Observe reduces a response to the parts of an Obs the wire carries.
func Observe(r Raw) Obs {
	o := Obs{Status: r.Status, Body: NormalizeBody(r.Body), Dur: r.Dur}
	var names []string
	for k := range r.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if k == "Set-Cookie" {
			continue
		}
		v := strings.Join(r.Header[k], ",")
		if volatile(k) {
			v = "<volatile>"
		} else {
			v = NormalizeBody([]byte(v))
		}
		o.Header = append(o.Header, k+": "+v)
	}
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		// The value is the sealed marker or token and always differs. What the
		// browser acts on is the name and the attributes.
		o.Cookies = append(o.Cookies, fmt.Sprintf("%s|path=%s|domain=%s|secure=%t|httponly=%t|samesite=%d|maxage=%d|empty=%t",
			c.Name, c.Path, c.Domain, c.Secure, c.HttpOnly, c.SameSite, c.MaxAge, c.Value == ""))
	}
	sort.Strings(o.Cookies)
	return o
}

// Difference is one dimension on which two observations of a known and an
// unknown subject differ.
type Difference struct {
	Dim    string // status, body, header, cookies, sms.<scope>, throttle.<scope>, gateways.<failures|open|held|blocked|public_sms_available>, argon2, scorings, gates, pool, pool.after_floor
	Detail string
}

// Compare lists every dimension on which known and unknown differ. The timing
// is not compared here: wall clocks are noisy, so the floor is asserted on its
// own by the caller (each answer lasted at least the floor).
func Compare(known, unknown Obs) []Difference {
	var d []Difference
	add := func(dim, format string, args ...any) { d = append(d, Difference{dim, fmt.Sprintf(format, args...)}) }
	if known.Status != unknown.Status {
		add("status", "%d vs %d", known.Status, unknown.Status)
	}
	if known.Body != unknown.Body {
		add("body", "%s vs %s", clip(known.Body), clip(unknown.Body))
	}
	if !equalStrings(known.Header, unknown.Header) {
		add("header", "%q vs %q", known.Header, unknown.Header)
	}
	if !equalStrings(known.Cookies, unknown.Cookies) {
		add("cookies", "%q vs %q", known.Cookies, unknown.Cookies)
	}
	compareTallies(&d, "sms.", known.SMS, unknown.SMS)
	compareTallies(&d, "throttle.", known.Throttle, unknown.Throttle)
	compareTallies(&d, "gateways.", known.Gateways, unknown.Gateways)
	if known.Meters.Argon2 != unknown.Meters.Argon2 {
		add("argon2", "%d vs %d runs", known.Meters.Argon2, unknown.Meters.Argon2)
	}
	if known.Meters.Scorings != unknown.Meters.Scorings {
		add("scorings", "%d vs %d", known.Meters.Scorings, unknown.Meters.Scorings)
	}
	if known.Meters.Gates != unknown.Meters.Gates {
		add("gates", "%d vs %d acquisitions", known.Meters.Gates, unknown.Meters.Gates)
	}
	if known.Meters.Pool != unknown.Meters.Pool {
		add("pool", "%d vs %d acquisitions before the answer", known.Meters.Pool, unknown.Meters.Pool)
	}
	if known.Meters.PoolAfter != unknown.Meters.PoolAfter {
		add("pool.after_floor", "%d vs %d acquisitions after the answer", known.Meters.PoolAfter, unknown.Meters.PoolAfter)
	}
	return d
}

func compareTallies(d *[]Difference, prefix string, a, b map[string]Tally) {
	scopes := map[string]bool{}
	for k := range a {
		scopes[k] = true
	}
	for k := range b {
		scopes[k] = true
	}
	var names []string
	for k := range scopes {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if a[k] != b[k] {
			*d = append(*d, Difference{prefix + k, fmt.Sprintf("%+v vs %+v", a[k], b[k])})
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func clip(s string) string {
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

// Exception is one declared place where the account may change an observation.
// Every entry names the spec section that accepts it; the oracle test fails for
// an entry no run used, so the list cannot go stale.
type Exception struct {
	Op    string // operationId or variant name ("*" for any)
	State string // a registered state, or "*"
	// Subject is the known variant the entry covers ("*" for any).
	Subject string
	// Dim is a Difference.Dim, or a prefix ending in "." such as "sms.".
	Dim  string
	Spec string // where the spec records and accepts it
	used bool
}

func (e *Exception) covers(op, state, subject, dim string) bool {
	match := func(pat, v string) bool { return pat == "*" || pat == v }
	if !match(e.Op, op) || !match(e.State, state) || !match(e.Subject, subject) {
		return false
	}
	if strings.HasSuffix(e.Dim, ".") {
		return strings.HasPrefix(dim, e.Dim)
	}
	return e.Dim == dim
}

// Exceptions is the declared list.
type Exceptions []*Exception

// Unexplained returns the differences no entry covers and marks the entries
// that explained something.
func (x Exceptions) Unexplained(op, state, subject string, diffs []Difference) []Difference {
	var out []Difference
	for _, d := range diffs {
		covered := false
		for _, e := range x {
			if e.covers(op, state, subject, d.Dim) {
				e.used, covered = true, true
			}
		}
		if !covered {
			out = append(out, d)
		}
	}
	return out
}

// Stale lists the entries no comparison needed.
func (x Exceptions) Stale() []string {
	var out []string
	for _, e := range x {
		if !e.used {
			out = append(out, fmt.Sprintf("%s/%s/%s/%s (%s)", e.Op, e.State, e.Subject, e.Dim, e.Spec))
		}
	}
	return out
}

// StaleFor is Stale for the entries of one state ("*" entries included). A test
// that runs one state per database can only judge the entries that state could
// have used.
func (x Exceptions) StaleFor(state string) []string {
	var out []string
	for _, e := range x {
		if !e.used && (e.State == state || e.State == "*") {
			out = append(out, fmt.Sprintf("%s/%s/%s/%s (%s)", e.Op, e.State, e.Subject, e.Dim, e.Spec))
		}
	}
	return out
}
