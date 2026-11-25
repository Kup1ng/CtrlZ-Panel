package httpx

import (
	"context"
	"io"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
)

// blockingReader gives a few bytes and then calls hook (which looks at the heap) before it ends the body, the way a
// client that declared 6 MiB and has sent only a little holds its connection open.
type blockingReader struct {
	sent bool
	hook func()
}

func (b *blockingReader) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, `{"a":1}`), nil
	}
	b.hook()
	return 0, io.EOF
}

// While a body is being read, what ReadBody holds follows the bytes that have arrived and not the Content-Length the
// client declared: a declared 6 MiB with 7 bytes sent holds a chunk (p2-B3-r7-1).
func TestReadBodyHoldsWhatHasArrivedNotWhatWasDeclared(t *testing.T) {
	var held uint64
	var m0, m1 runtime.MemStats
	r := httptest.NewRequest("POST", "/", &blockingReader{hook: func() {
		runtime.ReadMemStats(&m1)
		held = m1.TotalAlloc - m0.TotalAlloc
	}})
	r.ContentLength = 6 << 20
	runtime.ReadMemStats(&m0)
	raw, e := ReadBody(r)
	if e != nil || string(raw) != `{"a":1}` {
		t.Fatalf("read %q, refusal %v", raw, e)
	}
	if held > 256<<10 {
		t.Fatalf("a body of 7 bytes that declared 6 MiB had allocated %d KiB when it was read", held>>10)
	}
}

// The document without its rules, and each rule, are held to the values the schema allows before a tree is built of them:
// a file of 75,000 folders of {"a":0}, of 150,000 empty ones, or with one unknown member of 200,000 values used to build a
// tree of 30 to 60 MiB for a body of under a megabyte (p2-B3-r7-3).
func TestCheckDocumentBoundsTheWorkOfEveryShape(t *testing.T) {
	v, err := NewValidator(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	const head = `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x",`
	rep := func(one string, n int) string { return "[" + strings.TrimSuffix(strings.Repeat(one+",", n), ",") + "]" }
	cases := []struct {
		name, doc string
		pointer   string
		budget    uint64
	}{
		{"folders a0", head + `"folders":` + rep(`{"a":0}`, 75000) + `,"rules":[]}`, "/folders", 12 << 20},
		{"folders empty", head + `"folders":` + rep(`{}`, 150000) + `,"rules":[]}`, "/folders", 12 << 20},
		{"services empty", head + `"services":` + rep(`{}`, 150000) + `,"rules":[]}`, "/services", 12 << 20},
		{"filters empty", head + `"filters":` + rep(`{}`, 150000) + `,"rules":[]}`, "/filters", 12 << 20},
		{"unknown member", head + `"zz":` + rep(`0`, 200000) + `,"rules":[]}`, "", 12 << 20},
		{"unknown member in a rule", head + `"rules":[{"pattern":"a.example","action":"block","zz":` + rep(`0`, 200000) + `}]}`, "/rules/0", 12 << 20},
	}
	for _, c := range cases {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		got, err := v.CheckDocument(context.Background(), "ProfileDocument", []byte(c.doc))
		runtime.ReadMemStats(&m1)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		found := false
		for _, p := range got {
			if p.Pointer == c.pointer && p.Code == "exceeded" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no exceeded at %q in %+v", c.name, c.pointer, got)
		}
		if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > c.budget {
			t.Errorf("%s: the check allocated %d MiB for a body of %d KiB, the bound is %d MiB", c.name, alloc>>20, len(c.doc)>>10, c.budget>>20)
		}
	}
	// What a legal document of the most values still passes the budget: 500 folders, 5,000 services and 1,000 filters.
	legal := head + `"folders":` + rep(`{"ref":"f","name":"n","kind":"standard"}`, 500) + `,"services":` + rep(`{"slug":"a","action":"block"}`, 5000) +
		`,"filters":` + rep(`{"id":"a"}`, 1000) + `,"rules":` + rep(`{"pattern":"a.example","action":"block"}`, 10000) + `}`
	if got, err := v.CheckDocument(context.Background(), "ProfileDocument", []byte(legal)); err != nil || len(got) != 0 {
		t.Errorf("a document at every maximum: %+v, %v", got, err)
	}
}
