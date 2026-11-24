package httpx

import (
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

func bulkValidator(t *testing.T) (*Validator, []apispec.Operation) {
	t.Helper()
	v, err := NewValidator(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	ops, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	return v, ops
}

// Every route that is gated by its body has a bounded count of values, or the scan would not cover it.
func TestEveryGatedBodyHasAValueBudget(t *testing.T) {
	v, ops := bulkValidator(t)
	n := 0
	for _, op := range ops {
		if op.MaxBody <= BulkThreshold {
			continue
		}
		n++
		if b := v.budgets[op.Key()]; b == unbounded || b <= 0 {
			t.Errorf("%s has no value budget (%d)", op.Key(), b)
		}
	}
	if n < 5 {
		t.Fatalf("only %d gated routes found", n)
	}
}

func checkBody(t *testing.T, v *Validator, op apispec.Operation, body string) *Error {
	t.Helper()
	r := httptest.NewRequest(op.Method, "/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return v.Check(r, op.Key())
}

func opByID(t *testing.T, ops []apispec.Operation, id string) apispec.Operation {
	t.Helper()
	for _, o := range ops {
		if o.ID == id {
			return o
		}
	}
	t.Fatalf("no operation %s", id)
	return apispec.Operation{}
}

// A body of small values has twenty times its bytes in the tree of the request check; the count of its values is held
// to what the schema allows before the tree is built (p2-B3-r6-4). The legal maximum still passes the count.
func TestAHostileValueCountIsRefusedBeforeTheTreeIsBuilt(t *testing.T) {
	v, ops := bulkValidator(t)
	imp := opByID(t, ops, "importProfile")
	bat := opByID(t, ops, "batchRules")
	cre := opByID(t, ops, "createRules")
	if b := v.budgets[bat.Key()]; !withinValues([]byte(`{"op":"delete","ids":[`+strings.Repeat(`"1",`, 9999)+`"1"]}`), b) {
		t.Errorf("10,000 ids, the most the schema allows, are over the budget %d", b)
	}
	// The budget is an upper bound for the whole document, with room for its other members; maxItems is still the
	// schema's to enforce, and a count well above the budget never reaches it.
	if b := v.budgets[bat.Key()]; withinValues([]byte(`{"op":"delete","ids":[`+strings.Repeat(`"1",`, 10200)+`"1"]}`), b) {
		t.Errorf("10,201 ids are within the budget %d", b)
	}
	if b := v.budgets[cre.Key()]; !withinValues([]byte(`{"patterns":[`+strings.Repeat(`"a.example",`, 999)+`"a.example"],"action":"block","comment":"c"}`), b) {
		t.Errorf("1,000 patterns are over the budget %d", b)
	}
	// The hostile shapes: unknown members and known arrays filled with empty values, at the size of the limit.
	empties := strings.TrimSuffix(strings.Repeat("{},", 2<<20), ",")
	for name, c := range map[string]struct {
		op   apispec.Operation
		body string
	}{
		"import with an unknown array": {imp, `{"document":"AA==","x":[` + empties + `]}`},
		"create with patterns of {}":   {cre, `{"patterns":[` + empties[:1<<20] + `],"action":"block"}`},
		"batch with deep arrays":       {bat, `{"op":"copy","x":` + strings.Repeat("[", 500000) + strings.Repeat("]", 500000) + `}`},
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		e := checkBody(t, v, c.op, c.body)
		runtime.ReadMemStats(&after)
		if e == nil || e.Status != 400 {
			t.Errorf("%s: %v, want 400", name, e)
		}
		// The scan allocates nothing and no tree is built: the check holds the copy of the body and no more.
		if got, max := after.TotalAlloc-before.TotalAlloc, uint64(4*len(c.body))+(1<<20); got > max {
			t.Errorf("%s: %d bytes allocated for a body of %d, a tree was built", name, got, len(c.body))
		}
	}
}

func TestWithinValuesCountsEveryKindOfValue(t *testing.T) {
	for _, c := range []struct {
		raw string
		n   int64
		ok  bool
	}{
		{`{}`, 1, true}, {`{}`, 0, false},
		{`{"a":1}`, 3, true}, {`{"a":1}`, 2, false},
		{`[1,2,3]`, 4, true}, {`[1,2,3]`, 3, false},
		{`["a\"b","c"]`, 3, true}, {`["a\"b","c"]`, 2, false},
		{`["a\\","c"]`, 3, true},
		{`[true,false,null,-1.5e3]`, 5, true}, {`[true,false,null,-1.5e3]`, 4, false},
		{"{ \"a\" :\n [ ] }", 3, true}, {"{ \"a\" :\n [ ] }", 2, false},
	} {
		if got := withinValues([]byte(c.raw), c.n); got != c.ok {
			t.Errorf("%q within %d: %v, want %v", c.raw, c.n, got, c.ok)
		}
	}
}
