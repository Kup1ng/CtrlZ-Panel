package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// POST /feedback (docs/specs/p3-endpoints.md 9.2, 11.5, T-125; review round 1 of D6, p3-D6-r1-1 and -9).

// A message is stored as the tenant's own row, the two kinds are the only ones, the body has its bound, and the 21st message of a
// day is 429 whatever session sends it; the other tenant's day is its own, and the budget is back the next day.
func TestFeedbackIsStoredBoundedAndLimitedPerTenantPerDay(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := f.makeSession(A.Tenant, A.User)
	count := func(tenant any) int {
		return f.count(`SELECT count(*) FROM ctrlz.feedback_items WHERE tenant_id = $1`, tenant)
	}

	a.post("/feedback", map[string]any{"kind": "feature", "body": "please add a dark theme"}).want(201, "")
	if n := count(A.Tenant); n != 1 {
		t.Fatalf("%d rows after one message", n)
	}
	var kind, body, status string
	f.env.Scan(t, `SELECT kind, body, status FROM ctrlz.feedback_items WHERE tenant_id = $1`, []any{A.Tenant}, &kind, &body, &status)
	if kind != "feature" || body != "please add a dark theme" || status != "new" {
		t.Errorf("row %q %q %q", kind, body, status)
	}

	// The bounds: a kind the route does not send, a blank body and one past 4000 characters are 422 and store nothing, and 4000 pass.
	for name, in := range map[string]map[string]any{
		"a kind of the statistics screens": {"kind": "false_positive", "body": "x"},
		"no kind":                          {"body": "x"},
		"a blank body":                     {"kind": "contact", "body": "   "},
		"an empty body":                    {"kind": "contact", "body": ""},
		"4001 characters":                  {"kind": "contact", "body": strings.Repeat("a", 4001)},
		"a member of another tenant":       {"kind": "contact", "body": "x", "tenant_id": B.Tenant.String()},
	} {
		got := a.post("/feedback", in)
		if got.Code != 422 && got.Code != 400 {
			t.Errorf("%s: %d %s", name, got.Code, got.Body)
		}
	}
	if n := count(A.Tenant); n != 1 {
		t.Fatalf("a refused body stored a row: %d", n)
	}
	a.post("/feedback", map[string]any{"kind": "contact", "body": strings.Repeat("ب", 4000)}).want(201, "")

	// 20 a day for the tenant: two are sent, eighteen more pass, the 21st is 429, also from another session of the same tenant.
	for i := 0; i < 18; i++ {
		f.ck.add(2 * time.Second)
		a.post("/feedback", map[string]any{"kind": "contact", "body": "again"}).want(201, "")
	}
	f.ck.add(2 * time.Second)
	a.post("/feedback", map[string]any{"kind": "contact", "body": "too many"}).want(429, "rate_limited")
	f.makeSession(A.Tenant, A.User).post("/feedback", map[string]any{"kind": "contact", "body": "other session"}).want(429, "rate_limited")
	if n := count(A.Tenant); n != 20 {
		t.Errorf("%d rows for the tenant, want exactly the 20 the day allows", n)
	}

	// Tenant B has a day of its own, and writes its own row only.
	b := f.makeSession(B.Tenant, B.User)
	b.post("/feedback", map[string]any{"kind": "feature", "body": "from b"}).want(201, "")
	if n := count(B.Tenant); n != 1 {
		t.Errorf("tenant B holds %d rows", n)
	}

	// The next day the budget is back.
	f.ck.add(25 * time.Hour)
	f.makeSession(A.Tenant, A.User).post("/feedback", map[string]any{"kind": "contact", "body": "next day"}).want(201, "")
}

// A message of several lines is stored as it was written (p3-D6-r2-1 and -10): a Persian request in two paragraphs with the direction
// marks and the half-space, one that ends in a line break, and CR LF from a browser, which is stored as LF. A control character and
// a bidi override are still refused, and nothing is stored for them.
func TestFeedbackTakesAMessageOfSeveralLines(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	stored := func() []string {
		// The bodies come back as one JSON array in the order of the ids (uuidv7), so no separator has to be chosen.
		var raw string
		f.env.Scan(t, `SELECT coalesce(json_agg(body ORDER BY id), '[]'::json)::text FROM ctrlz.feedback_items WHERE tenant_id = $1`, []any{A.Tenant}, &raw)
		var out []string
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	two := "سلام\u200f\n\nلطفاً حالت تاریک را به پنل اضافه کنید، نیم\u200cفاصله هم درست باشد.\n"
	a.post("/feedback", map[string]any{"kind": "feature", "body": two}).want(201, "")
	f.ck.add(2 * time.Second)
	a.post("/feedback", map[string]any{"kind": "contact", "body": "line one\r\nline two\rline three"}).want(201, "")
	got := stored()
	if len(got) != 2 || got[0] != two || got[1] != "line one\nline two\nline three" {
		t.Fatalf("stored %q", got)
	}
	for name, body := range map[string]string{"NUL": "a\x00b", "an override": "a\u202eb", "a leading new line": "\nhello"} {
		f.ck.add(2 * time.Second)
		if r := a.post("/feedback", map[string]any{"kind": "contact", "body": body}); r.Code != 400 {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	if n := len(stored()); n != 2 {
		t.Errorf("%d rows after the refused ones", n)
	}
}
