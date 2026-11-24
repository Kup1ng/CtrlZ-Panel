package httpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
)

// fakeConn is a connection with a clock the test moves: each Read or Write moves it by step and fails with a timeout when it
// is past the deadline the code under test last set, as the real connection would. Nothing sleeps.
type fakeConn struct {
	now      time.Time
	deadline time.Time
	step     time.Duration
	chunk    int // bytes a read gives, or a write takes
	left     int // bytes of the body still to give (reads)
	sets     []time.Time
	// stepAt, when set, gives the time each call takes (by the number of calls so far) instead of step.
	stepAt func(i int) time.Duration
	calls  int
}

var errTimeout = errors.New("i/o timeout")

func (c *fakeConn) setDeadline(t time.Time) { c.deadline = t; c.sets = append(c.sets, t) }

func (c *fakeConn) pass() error {
	d := c.step
	if c.stepAt != nil {
		d = c.stepAt(c.calls)
	}
	c.calls++
	c.now = c.now.Add(d)
	if !c.deadline.IsZero() && c.now.After(c.deadline) {
		return errTimeout
	}
	return nil
}

func (c *fakeConn) Read(p []byte) (int, error) {
	if err := c.pass(); err != nil {
		return 0, err
	}
	if c.left == 0 {
		return 0, io.EOF
	}
	n := min(c.chunk, len(p), c.left)
	c.left -= n
	return n, nil
}

func (c *fakeConn) Write(p []byte) (int, error) {
	if err := c.pass(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// TestAnEarnedDeadline: the read deadline of a heavy body is the start plus 15 s plus a second for each 32 KiB received (6.5
// property 3). A body stalled at its first byte is cut at 15 s, 6 MiB at 33 KiB/s passes, and a byte every two seconds is
// cut at 15 s: it earns nothing. At the model before it the last was cut at a window of 10 s, and 6 MiB needed 0.6 Mbit/s
// and was cut at 90 s.
func TestAnEarnedDeadline(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	spool := func() *spoolFile {
		sp, err := newSpool(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sp.close)
		return sp
	}

	t.Run("stalled at the first byte", func(t *testing.T) {
		// The first read gives its byte at once; the sender is then silent for an hour.
		c := &fakeConn{now: start, chunk: 1, left: 2}
		c.stepAt = func(i int) time.Duration {
			if i == 0 {
				return 0
			}
			return time.Hour
		}
		got, err := copyIn(spool(), c, start, c.setDeadline)
		if !errors.Is(err, errTimeout) || got != 1 {
			t.Fatalf("a body stalled at byte 1: %d bytes, %v", got, err)
		}
		if last := c.sets[len(c.sets)-1]; !last.Equal(start.Add(15 * time.Second)) {
			t.Fatalf("the deadline at byte 1 is the start plus %v, want 15 s", last.Sub(start))
		}
	})

	t.Run("6 MiB at 33 KiB a second passes", func(t *testing.T) {
		c := &fakeConn{now: start, chunk: spoolChunk, left: 6 << 20, step: time.Second * 32 / 33}
		got, err := copyIn(spool(), c, start, c.setDeadline)
		if err != nil || got != 6<<20 {
			t.Fatalf("a body of 6 MiB at 33 KiB/s: %d bytes, %v", got, err)
		}
		if took := c.now.Sub(start); took < 180*time.Second || took > 207*time.Second {
			t.Fatalf("the body took %v, the test means to run it at the edge of the longest legal time", took)
		}
	})

	t.Run("a byte every two seconds earns nothing", func(t *testing.T) {
		c := &fakeConn{now: start, chunk: 1, left: 1 << 20, step: 2 * time.Second}
		got, err := copyIn(spool(), c, start, c.setDeadline)
		if !errors.Is(err, errTimeout) {
			t.Fatalf("a trickle ended with %v after %d bytes, want a timeout", err, got)
		}
		if cut := c.now.Sub(start); cut < 15*time.Second || cut > 17*time.Second {
			t.Fatalf("the trickle was cut at %v, want 15 s", cut)
		}
	})

	t.Run("an answer earns 30 s plus a second for each 32 KiB", func(t *testing.T) {
		sp := spool()
		if _, err := sp.write(bytes.Repeat([]byte("x"), 6<<20)); err != nil {
			t.Fatal(err)
		}
		c := &fakeConn{now: start, chunk: spoolChunk, step: time.Second * 32 / 33}
		if err := copyOut(c, sp, 6<<20, start, c.setDeadline); err != nil {
			t.Fatalf("an answer of 6 MiB to a reader of 33 KiB/s: %v", err)
		}
		stalled := &fakeConn{now: start, step: 31 * time.Second}
		if err := copyOut(stalled, sp, 1<<20, start, stalled.setDeadline); !errors.Is(err, errTimeout) {
			t.Fatalf("a reader that takes a chunk every 31 s was not cut: %v", err)
		}
	})
}

// The spool file is private: its name is gone as soon as it is open where the system allows it, and it is removed when it is
// closed where it is not (6.5 property 11).
func TestASpoolFileLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	sp, err := newSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if es, _ := os.ReadDir(dir); len(es) != 0 {
			t.Fatalf("the name of an open spool file is still in the directory: %d entries", len(es))
		}
	}
	if st, err := sp.f.Stat(); err != nil || st.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		t.Fatalf("the spool file mode is %v, %v", st.Mode(), err)
	}
	sp.close()
	if es, _ := os.ReadDir(dir); len(es) != 0 {
		t.Fatalf("%d entries are left in the spool directory after close", len(es))
	}
}

// readAll gives back exactly the bytes written, and reset empties the file for the answer.
func TestTheSpoolReadsBackAndResets(t *testing.T) {
	sp, err := newSpool(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer sp.close()
	if _, err := sp.write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	b, err := sp.readAll(11)
	if err != nil || string(b) != "hello world" {
		t.Fatalf("%q %v", b, err)
	}
	if err := sp.reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := sp.write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if st, _ := sp.f.Stat(); st.Size() != 2 {
		t.Fatalf("the file holds %d bytes after the reset and a write of 2", st.Size())
	}
}

// heavyCheck runs CheckHeavy of rules:batch on a body, with the route's profile id in place, and reports the answer and the
// bytes allocated.
func heavyCheck(t *testing.T, v *Validator, op string, path string, body string) (*Error, uint64) {
	t.Helper()
	r := httptest.NewRequest("POST", "/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "k")
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", "00000000-0000-4000-8000-000000000001")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	e := v.CheckHeavy(r, op, []byte(body))
	runtime.ReadMemStats(&m1)
	return e, m1.TotalAlloc - m0.TotalAlloc
}

const batchKey = "POST /profiles/{id}/rules:batch"

// TestAHostileNumberOrNestingIsRefusedBeforeAnyDecode: a number of 900,000 digits, a number written 1e-999999, and a body
// nested 100,000 deep are 400 on the raw bytes: nothing is decoded, and the schema engine never makes a big.Rat of them
// (6.5 property 6). At the pipeline before this model both reached the decoder.
func TestAHostileNumberOrNestingIsRefusedBeforeAnyDecode(t *testing.T) {
	v, err := NewValidator(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"900,000 digits":     `{"op":"delete","ids":[],"n":` + strings.Repeat("9", 900000) + `}`,
		"an exponent":        `{"op":"delete","ids":[],"n":1e-999999}`,
		"a fraction":         `{"op":"delete","ids":[],"n":0.` + strings.Repeat("0", 900000) + `1}`,
		"nested 100,000":     `{"op":"delete","ids":[],"x":` + strings.Repeat("[", 100000) + strings.Repeat("]", 100000) + `}`,
		"33 members":         `{"op":"delete","ids":[]` + strings.Repeat(`,"k":1`, 33) + `}`,
		"11 digits":          `{"op":"delete","ids":[],"n":12345678901}`,
		"a negative literal": `{"op":"delete","ids":[],"n":-0.5}`,
	} {
		e, alloc := heavyCheck(t, v, batchKey, "", body)
		if e == nil || e.Status != 400 {
			t.Errorf("%s: %v, want 400", name, e)
		}
		if alloc > 1<<20 {
			t.Errorf("%s: %d bytes were allocated for a body of %d bytes, a tree was built", name, alloc, len(body))
		}
	}
	// A legal body passes the same check.
	ok := `{"op":"delete","ids":["00000000-0000-4000-8000-000000000001"]}`
	if e, _ := heavyCheck(t, v, batchKey, "", ok); e != nil {
		t.Errorf("a legal body: %v", e)
	}
}

func TestScanShape(t *testing.T) {
	h := heavyShape()
	for _, c := range []struct {
		raw string
		s   shape
		ok  bool
	}{
		{`{"a":[1,2,3]}`, h, true},
		{`{"a":-12}`, h, true},
		{`{"a":12345678901}`, h, false},
		{`{"a":1.5}`, h, false},
		{`{"a":1e3}`, h, false},
		{`{"a":-}`, h, false},
		{`{"a":true,"b":null,"c":"1e3 1.5 - 99999999999"}`, h, true}, // text and literals are not numbers
		{`[[[[[[[[1]]]]]]]]`, h, true},                               // eight deep
		{`[[[[[[[[[1]]]]]]]]]`, h, false},                            // nine
		{`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}`, h, true},
		{`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":1}}}}}}}}}`, h, false},
		{`{` + strings.TrimSuffix(strings.Repeat(`"k":1,`, 32), ",") + `}`, h, true},
		{`{` + strings.TrimSuffix(strings.Repeat(`"k":1,`, 33), ",") + `}`, h, false},
		{`[{"a":1,"b":2},{"a":1,"b":2}]`, shape{values: -1, members: 2}, true}, // members are counted for each object
		{`{"a":1,"b":2,"c":3}`, shape{values: -1, members: 2}, false},
		{`{"a":"x,y\"z"}`, h, true},
	} {
		if got := scanShape([]byte(c.raw), c.s); got != c.ok {
			t.Errorf("%.60q: %v, want %v", c.raw, got, c.ok)
		}
	}
}

// TestAHeavyOperationHoldsLessThanItsWeight: the checks of a heavy operation, at their worst legal and worst hostile shapes,
// add less live heap than the weight the operation is queued for (6.5 property 8), with the collector limited the way the api
// container limits it. It holds what runs without Postgres: the check of the body and the encoding of an export. The
// database part of an Import is the same document in a transaction, which the Postgres flow tests run.
func TestAHeavyOperationHoldsLessThanItsWeight(t *testing.T) {
	v, err := NewValidator(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	type shapeCase struct {
		name   string
		weight int64
		run    func()
	}
	check := func(op, body string) func() {
		return func() {
			r := httptest.NewRequest("POST", "/x", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "k")
			rc := chi.NewRouteContext()
			rc.URLParams.Add("id", "00000000-0000-4000-8000-000000000001")
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
			_ = v.CheckHeavy(r, op, []byte(body))
		}
	}
	// 5.5 million control characters in the document member: the check once built several strings of four times that.
	garbage := `{"document":"` + strings.Repeat("\x7f", 5500000) + `"}`
	ids := `{"op":"delete","ids":[` + strings.TrimSuffix(strings.Repeat(`"a",`, 10000), ",") + `]}`
	cases := []shapeCase{
		{"a document of 5.5 million 0x7f", 48 << 20, check("POST /profiles:import", garbage)},
		{"10,000 ids of one character", 16 << 20, check(batchKey, ids)},
	}
	// The largest export there can be: 10,000 rules, 5,000 services, 500 folders and 1,000 filters, every string at its longest.
	var exported counter
	cases = append(cases, shapeCase{"an export of 10,000 rules with the longest pattern, comment and target", 32 << 20, func() {
		if err := longestProfile().EncodeTo(&exported); err != nil {
			t.Error(err)
		}
	}})
	for _, c := range cases {
		base, peakLive := measureHeap(c.weight, c.run)
		t.Logf("%s: base %d MiB, live peak %d MiB of %d", c.name, base>>20, (peakLive-min(peakLive, base))>>20, c.weight>>20)
		if peakLive > base && peakLive-base > uint64(c.weight) {
			t.Errorf("%s: the heap it added reached %d MiB live, its weight is %d MiB", c.name, (peakLive-base)>>20, c.weight>>20)
		}
	}
}

// measureHeap runs fn and returns the heap before it and the highest live heap the collector found while it ran, with the
// collector's soft limit set 25 percent above the weight, so that a request that needs more than its weight forces cycles
// that find it live.
func measureHeap(weight int64, fn func()) (base, peakLive uint64) {
	sample := func() (objects, live uint64) {
		s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/gc/heap/live:bytes"}}
		metrics.Read(s)
		return s[0].Value.Uint64(), s[1].Value.Uint64()
	}
	runtime.GC()
	runtime.GC()
	b0, _ := sample()
	old := debug.SetMemoryLimit(int64(b0) + weight + weight/4)
	defer debug.SetMemoryLimit(old)
	runtime.GC()
	runtime.GC()
	base, _ = sample()
	stop, done := make(chan struct{}), make(chan uint64)
	go func() {
		var pl uint64
		for {
			select {
			case <-stop:
				done <- pl
				return
			default:
			}
			_, l := sample()
			pl = max(pl, l)
			time.Sleep(100 * time.Microsecond)
		}
	}()
	fn()
	close(stop)
	return base, <-done
}

// counter counts the bytes written to it.
type counter struct{ n int64 }

func (c *counter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// longestProfile is the profile with the most the schema allows, every string at its longest, as an export holds it.
func longestProfile() profiles.Document {
	long := func(n int, c string) string { return strings.Repeat(c, n) }
	target := &profiles.DocTarget{Kind: "location", Location: &profiles.DocLoc{Country: "US", City: long(64, "c"), Label: long(64, "l")},
		IPv4: "255.255.255.255", IPv6: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Host: long(253, "h")}
	d := profiles.Document{Format: profiles.DocFormat, Version: profiles.DocVersion, Name: long(64, "n"), Kind: "custom"}
	for i := 0; i < 1000; i++ {
		d.Filters = append(d.Filters, profiles.DocFilter{ID: long(32, "f"), Mode: long(16, "m")})
	}
	for i := 0; i < 5000; i++ {
		d.Services = append(d.Services, profiles.DocService{Slug: long(32, "s"), Action: "redirect", Target: target})
	}
	for i := 0; i < 500; i++ {
		d.Folders = append(d.Folders, profiles.DocFolder{Ref: long(32, "r"), Name: long(64, "n"), Kind: "standard", Action: "redirect", Target: target})
	}
	for i := 0; i < 10000; i++ {
		d.Rules = append(d.Rules, profiles.DocRule{Pattern: long(260, "p"), Folder: long(32, "f"), Action: "redirect", Target: target,
			ExpiresAt: "2030-01-01T00:00:00.000000000+00:00", Comment: long(64, "c")})
	}
	return d
}

// TestTheLargestExportFitsTheSpool: an answer above admission.AnswerBytes is a 500, so the largest export there can be stays
// below it (6.5 property 11).
func TestTheLargestExportFitsTheSpool(t *testing.T) {
	var n counter
	if err := longestProfile().EncodeTo(&n); err != nil {
		t.Fatal(err)
	}
	t.Logf("the largest export is %d bytes of %d", n.n, admission.AnswerBytes)
	if n.n >= admission.AnswerBytes {
		t.Fatalf("the largest export is %d bytes, the spool takes %d", n.n, admission.AnswerBytes)
	}
}
