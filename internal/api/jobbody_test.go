package api

import (
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
)

// storedResult is what JobFinish stores for n items: the wire form of a result (p2-B3-r13-3).
func storedResult(t *testing.T, n int) ([]byte, gen.BatchResult) {
	t.Helper()
	r := profiles.ResultJSON{Created: n, Items: make([]profiles.ResultItem, 0, n)}
	want := gen.BatchResult{Created: n, Items: make([]gen.BatchItem, 0, n)}
	for i := 0; i < n; i++ {
		id := uuid.New()
		r.Items = append(r.Items, profiles.ResultItem{Index: i, Outcome: "created", ID: &id})
		oid := openapi_types.UUID(id)
		want.Items = append(want.Items, gen.BatchItem{Index: i, Outcome: gen.BatchItemOutcome("created"), Id: &oid})
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b, want
}

// The stored result goes into the answer as it is, and the answer decodes to what the generated type encoded before.
func TestJobBodyCarriesTheStoredResultAsItIs(t *testing.T) {
	raw, want := storedResult(t, 50)
	head := gen.Job{Id: openapi_types.UUID(uuid.New()), Kind: gen.JobKind("rules_batch"), State: gen.JobState("done"), Progress: 50, Total: 50}
	body, err := jobBody(head, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), string(raw)) {
		t.Fatalf("the stored result is not in the answer as it is")
	}
	var got gen.Job
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Result == nil || !reflect.DeepEqual(*got.Result, want) {
		t.Fatalf("the result decodes to %+v, want %+v", got.Result, want)
	}
	head.Result = &want
	old, _ := json.Marshal(head)
	var a, b map[string]any
	_ = json.Unmarshal(old, &a)
	_ = json.Unmarshal(body, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("the answer differs from the one the generated encoder gave")
	}
	// A job with no result has none, and the answer is still one JSON object.
	none, err := jobBody(head2(), nil)
	if err != nil || !json.Valid(none) || strings.Contains(string(none), `"result"`) {
		t.Fatalf("a job with no result: %s %v", none, err)
	}
}

func head2() gen.Job {
	return gen.Job{Id: openapi_types.UUID(uuid.New()), Kind: gen.JobKind("import"), State: gen.JobState("running"), Total: 3}
}

// A result of 10,000 items is not decoded: the answer costs about the size of the result once, where decoding it into 10,000
// items and encoding it again held about five times that (p2-B3-r13-3).
func TestJobBodyOfTenThousandItemsAllocatesAboutOneCopy(t *testing.T) {
	raw, _ := storedResult(t, 10000)
	head := head2()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	body, err := jobBody(head, raw)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	alloc := int64(after.TotalAlloc - before.TotalAlloc)
	if limit := int64(len(raw)) * 3 / 2; alloc > limit {
		t.Fatalf("the answer of %d bytes allocated %d bytes, more than %d", len(body), alloc, limit)
	}
}
