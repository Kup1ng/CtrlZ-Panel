// Package isolation is the two-tenant harness of rule isolation-success-coverage (spec 16.5
// and 18.1). A refusal proves nothing about isolation: a call that the database or the
// handler turns away before it writes leaves every digest as it was whether or not the
// tenant predicate is there. So the harness only accepts a case in which B's call
// SUCCEEDS while tenant A holds the very same state, and then asks two questions: did
// B's own rows change (the call really wrote), and did A's rows stay exactly as they were.
//
// The package holds the part that does not depend on the service under test: the
// completeness check (an operation or function with no fixture fails, and so does a
// fixture for something that no longer exists), the status check (the call is 2xx), the
// digest check, the same-state check and the leak check. The services bring their own
// fixtures and their own digests through Hooks.
package isolation

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Who names a tenant of the harness.
type Who int

// The two tenants. A holds the state B's call must not reach.
const (
	A Who = iota
	B
)

func (w Who) String() string {
	if w == A {
		return "A"
	}
	return "B"
}

// Effect says what a successful call does, and the harness checks the claim in both
// directions, so a label cannot hide a call that writes (or one that does not).
type Effect int

const (
	// Changes: the call writes rows B owns. B's digest must differ afterwards.
	Changes Effect = iota + 1
	// Shows: the call stores nothing (a read, or a sealed ceremony that keeps no row). B's
	// digest must be what it was. A fixture for a method other than GET names the reason.
	Shows
	// Elsewhere: the call writes rows no existing tenant owns (a new tenant, an invite, a
	// console setting). Neither digest may move, and Proof must show the write happened,
	// so a call that wrote nothing does not pass as one that wrote somewhere else.
	Elsewhere
)

func (e Effect) String() string {
	switch e {
	case Changes:
		return "Changes"
	case Shows:
		return "Shows"
	case Elsewhere:
		return "Elsewhere"
	}
	return "unset"
}

// Result is what a call answered.
type Result struct {
	Status int
	Body   []byte
	// Cookies is the Set-Cookie header, for the leak check.
	Cookies string
	// Set is the same header as the separate lines, for a check that reads a cookie.
	Set []string
}

// Fixture is one operation's success case.
type Fixture struct {
	Effect Effect
	// Status is the answer the call must give: a 2xx.
	Status int
	// Reason is required for Shows on a method other than GET, and for Elsewhere: why the
	// caller's own rows do not move.
	Reason string
	// Sees lists strings that only B's answer holds. For a read it is the proof that the call
	// reached B's data and not nothing.
	Sees func() []string
	// Arrange puts one tenant in the state the call acts on. It runs for A and then for B,
	// after both were reset to the same baseline, and A must end in the state B ends in:
	// the harness compares the shapes of the two and fails when they differ.
	Arrange func(w Who)
	// Call is B's call. It must use what Arrange(B) made.
	Call func() Result
	// Cross is the other half of "B's session on A's id" (spec 18.1, round 5, tenant-r5-5 and
	// -11): B's own session, or credentials, with the id or the session-bound ticket of A,
	// which Arrange(A) made. It must be refused with CrossStatus and must leave every row of
	// both tenants as it was. A success fixture alone cannot see a handler that looks a row
	// up by a client-chosen id without the tenant and user predicate when row level security
	// is not the layer in force: B's call on B's own id answers the same with or without the
	// predicate. Required for every operation whose Op says it takes an id.
	Cross func() Result
	// CrossAt is one more Cross call for each location of the operation that takes a row id beyond the first
	// (Op.Locations, sorted): the call names that location with A's id and every other one with B's own. An
	// operation with two id-bearing fields (a path id and a body challenge, say) is not covered by one call that
	// puts A's id in one of them, because a handler that drops the tenant predicate for the other passes it
	// (round 16, tenant-r16-13). Each call is judged like Cross, with the same CrossStatus.
	CrossAt map[string]func() Result
	// CrossStatus is the refusal Cross must get: a 4xx, 404 for an id that is not B's.
	CrossStatus int
	// CrossMay names the tables of A that the refused call may still change, with CrossReason.
	// It is for a one-time ceremony ticket: a challenge dies with its first answer whoever gave
	// it (spec 7.1), so a request that holds the ticket and is refused for being the wrong user
	// has spent it. The ticket is a 256 bit secret only its owner holds; the harness still
	// requires every other table of A to stay as it was.
	// CrossBMay names the tables of B's own that the refused call may write: the record of B's own
	// failed attempt (an audit row, the counter of its tries). It never holds a table of A. A needs
	// a CrossReason like CrossMay, and the harness still requires every other table of B to stay.
	CrossBMay   []string
	CrossMay    []string
	CrossReason string
	// Proof is required for Elsewhere: it reports an error when the write is not there.
	Proof func() error
}

// Op is one operation of an OpenAPI document.
type Op struct {
	ID, Method string
	// Takes says the operation names a row of the caller by an id the client chooses: a path
	// parameter, a query parameter, a request body property or a ticket that belongs to a session's user (empty for none). The harness
	// demands a Cross call for it. A ticket a caller holds with no session is a bearer proof,
	// whoever holds it is its owner, and is not listed.
	Takes string
	// Locations lists every place the operation takes a row id, sorted, as "path:id", "query:name", "header:name",
	// "cookie:name" or "body:a.b" (an array item adds "[]", a map value "{}"). It is read from the schema of the document (a uuid, or a name that says
	// id), so a field with another name is listed too. Cross covers the first; CrossAt must hold the others.
	Locations []string
}

// Hooks are what the service under test brings.
type Hooks struct {
	// Reset returns one tenant to the baseline: no sessions, no second factors, no pending
	// changes, the rows of the seed.
	Reset func(w Who)
	// Digest is a fingerprint of every row the tenant owns in the tables the service writes,
	// one entry per table, so a failure names the table.
	Digest func(w Who) map[string]string
	// Shape is what "the same state" means: row counts and flags, equal for A and B when
	// the fixture treated them alike.
	Shape func(w Who) string
	// Leaks are strings of A that must not appear in B's answer.
	Leaks func() []string
	// ACookie is a token of A that must not be set on B's answer.
	ACookie func() string
	// Before and After are optional. Before reads, for B, something the call may change (the
	// credential generation of the user, say) and After judges the call against it: it gets the
	// operation id and the answer and returns what is wrong. They hold a property of every
	// operation at once, so a new route is covered by being in the fixtures.
	Before func(w Who) any
	After  func(id string, w Who, before any, r Result) []string
}

// Complete says what is wrong with the set of fixtures before any of them runs: an
// operation with none, a fixture for an operation that is not in the document, and a
// fixture that cannot prove anything (no effect, a status that is not a success, no
// Arrange or Call, Elsewhere without a Proof, Shows on a method other than GET with no
// reason). It is a function and not part of Run so that a test can show each of them fails.
func Complete(ops []Op, fixtures map[string]Fixture) []string {
	var out []string
	known := map[string]Op{}
	for _, op := range ops {
		known[op.ID] = op
		if _, ok := fixtures[op.ID]; !ok {
			out = append(out, fmt.Sprintf("operation %s has no two-tenant success fixture", op.ID))
		}
	}
	ids := make([]string, 0, len(fixtures))
	for id := range fixtures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fx := fixtures[id]
		op, ok := known[id]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("a fixture exists for %s, which is not in the document", id))
		case fx.Effect == 0:
			out = append(out, fmt.Sprintf("%s: the fixture names no effect", id))
		case fx.Status < 200 || fx.Status > 299:
			out = append(out, fmt.Sprintf("%s: the fixture expects %d, which is not a success", id, fx.Status))
		case fx.Arrange == nil || fx.Call == nil:
			out = append(out, fmt.Sprintf("%s: the fixture has no Arrange or no Call", id))
		case fx.Effect == Elsewhere && (fx.Proof == nil || fx.Reason == ""):
			out = append(out, fmt.Sprintf("%s: Elsewhere needs a Proof and a Reason", id))
		case fx.Effect == Shows && op.Method != http.MethodGet && fx.Reason == "":
			out = append(out, fmt.Sprintf("%s: Shows on a %s needs a Reason", id, op.Method))
		case op.Takes != "" && fx.Cross == nil:
			out = append(out, fmt.Sprintf("%s: it takes %s chosen by the client and its fixture has no Cross call (B's session on A's)", id, op.Takes))
		case len(op.Locations) > 1 && missingCrossAt(op, fx) != "":
			out = append(out, fmt.Sprintf("%s: it takes a row id in %d places and its fixture has no Cross call for %s", id, len(op.Locations), missingCrossAt(op, fx)))
		case len(fx.CrossAt) > 0 && unknownCrossAt(op, fx) != "":
			out = append(out, fmt.Sprintf("%s: CrossAt names %s, which is not a place the operation takes an id (the document moved)", id, unknownCrossAt(op, fx)))
		case (len(fx.CrossMay) > 0 || len(fx.CrossBMay) > 0) && fx.CrossReason == "":
			out = append(out, fmt.Sprintf("%s: CrossMay and CrossBMay need a CrossReason", id))
		case fx.Cross != nil && (fx.CrossStatus < 400 || fx.CrossStatus > 499):
			out = append(out, fmt.Sprintf("%s: the Cross call expects %d, which is not a refusal of the client", id, fx.CrossStatus))
		}
	}
	return out
}

// missingCrossAt names the first location after the first that has no CrossAt call.
func missingCrossAt(op Op, fx Fixture) string {
	for _, loc := range op.Locations[1:] {
		if fx.CrossAt[loc] == nil {
			return loc
		}
	}
	return ""
}

// unknownCrossAt names a CrossAt key that is not a location after the first.
func unknownCrossAt(op Op, fx Fixture) string {
	for k := range fx.CrossAt {
		if len(op.Locations) < 2 || !slices.Contains(op.Locations[1:], k) {
			return k
		}
	}
	return ""
}

// Run checks the fixtures against the operations and then runs every fixture as a
// subtest. ops comes from the OpenAPI document, so a new route without a fixture fails here.
func Run(t *testing.T, ops []Op, fixtures map[string]Fixture, h Hooks) {
	t.Helper()
	if problems := Complete(ops, fixtures); len(problems) > 0 {
		for _, p := range problems {
			t.Error(p)
		}
		return
	}
	ids := make([]string, 0, len(fixtures))
	for id := range fixtures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fx := fixtures[id]
		t.Run(id, func(t *testing.T) {
			for _, p := range judge(id, fx, h) {
				t.Error(p)
			}
		})
	}
}

// Judge runs one fixture and returns what is wrong with it. It resets both tenants, arranges
// them, checks they are in the same state, makes B's call and compares the digests.
func Judge(fx Fixture, h Hooks) []string { return judge("", fx, h) }

func judge(id string, fx Fixture, h Hooks) []string {
	var out []string
	h.Reset(A)
	h.Reset(B)
	fx.Arrange(A)
	fx.Arrange(B)
	if a, b := h.Shape(A), h.Shape(B); a != b {
		return []string{fmt.Sprintf("A is not in the same state as B before the call, so the case proves nothing:\nA: %s\nB: %s", a, b)}
	}
	a0, b0 := h.Digest(A), h.Digest(B)
	crosses := []func() Result{}
	if fx.Cross != nil {
		crosses = append(crosses, fx.Cross)
		keys := make([]string, 0, len(fx.CrossAt))
		for k := range fx.CrossAt {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			crosses = append(crosses, fx.CrossAt[k])
		}
	}
	for _, cross := range crosses {
		rc := cross()
		if rc.Status != fx.CrossStatus {
			return []string{fmt.Sprintf("B's call on A's id answered %d %q, want %d", rc.Status, truncate(rc.Body), fx.CrossStatus)}
		}
		if tbl := diffExcept(a0, h.Digest(A), fx.CrossMay); tbl != "" {
			out = append(out, fmt.Sprintf("A's rows in %s changed by B's call on A's id", tbl))
		}
		if tbl := diffExcept(b0, h.Digest(B), fx.CrossBMay); tbl != "" {
			out = append(out, fmt.Sprintf("B's rows in %s changed by a refused call on A's id", tbl))
		}
		for _, leak := range h.Leaks() {
			if leak != "" && strings.Contains(string(rc.Body), leak) {
				out = append(out, fmt.Sprintf("the refusal of B's call on A's id holds %q, which is A's", leak))
			}
		}
		if len(out) > 0 {
			return out
		}
		// What the refused call was allowed to change (CrossMay) is the new baseline.
		a0, b0 = h.Digest(A), h.Digest(B)
	}
	var before any
	if h.Before != nil {
		before = h.Before(B)
	}
	r := fx.Call()
	if r.Status != fx.Status {
		return []string{fmt.Sprintf("B's call answered %d %q, want %d: a refusal proves nothing about isolation", r.Status, truncate(r.Body), fx.Status)}
	}
	a1, b1 := h.Digest(A), h.Digest(B)
	if tbl := diff(a0, a1); tbl != "" {
		out = append(out, fmt.Sprintf("A's rows in %s changed by B's call", tbl))
	}
	switch fx.Effect {
	case Changes:
		if diff(b0, b1) == "" {
			out = append(out, "B's own rows did not change: the call wrote nothing, so the case proves nothing")
		}
	case Shows:
		if tbl := diff(b0, b1); tbl != "" {
			out = append(out, fmt.Sprintf("B's rows in %s changed by a call labelled Shows (%s): label it Changes", tbl, fx.Reason))
		}
	case Elsewhere:
		if tbl := diff(b0, b1); tbl != "" {
			out = append(out, fmt.Sprintf("B's rows in %s changed by a call labelled Elsewhere (%s)", tbl, fx.Reason))
		}
		if err := fx.Proof(); err != nil {
			out = append(out, fmt.Sprintf("the write the fixture claims is not there: %v", err))
		}
	}
	if fx.Sees != nil {
		for _, s := range fx.Sees() {
			if !strings.Contains(string(r.Body), s) {
				out = append(out, fmt.Sprintf("B's answer lacks %q, so it did not reach B's data", s))
			}
		}
	}
	for _, leak := range h.Leaks() {
		if leak != "" && strings.Contains(string(r.Body), leak) {
			out = append(out, fmt.Sprintf("B's answer holds %q, which is A's", leak))
		}
	}
	if c := h.ACookie(); c != "" && strings.Contains(r.Cookies, c) {
		out = append(out, "A's token came back on B's answer")
	}
	if h.After != nil {
		out = append(out, h.After(id, B, before, r)...)
	}
	return out
}

// diffExcept is diff over the tables not in skip.
func diffExcept(before, after map[string]string, skip []string) string {
	b, a := map[string]string{}, map[string]string{}
	for k, v := range before {
		if !slices.Contains(skip, k) {
			b[k] = v
		}
	}
	for k, v := range after {
		if !slices.Contains(skip, k) {
			a[k] = v
		}
	}
	return diff(b, a)
}

func diff(before, after map[string]string) string {
	var tbls []string
	for tbl, d := range before {
		if after[tbl] != d {
			tbls = append(tbls, tbl)
		}
	}
	for tbl := range after {
		if _, ok := before[tbl]; !ok {
			tbls = append(tbls, tbl)
		}
	}
	sort.Strings(tbls)
	return strings.Join(tbls, ", ")
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return fmt.Sprintf("%s...", b[:200])
	}
	return string(b)
}
