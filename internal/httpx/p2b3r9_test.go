package httpx_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// Round 9 of package B3: the refusals of a heavy request after its body step, over a real http.Server whose WriteTimeout is
// shorter than the wait that comes before them. A recorder has no write deadline and a fake reader does not cancel the request
// context, so the tests of the earlier rounds could not see either (p2-B3-r9-1, r9-5).

// realServer serves the rig over a real connection with the server's own deadlines as app.go sets them, only shorter.
func realServer(t *testing.T, rig *heavyRig, writeTimeout time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(rig.h)
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func realImport(t *testing.T, srv *httptest.Server, cookie, key string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+importPath, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.ContentLength = 6 << 20
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	req.AddCookie(&http.Cookie{Name: "sid", Value: cookie})
	return req
}

// TestAQueueRefusalReachesAClientPastTheServersWriteTimeout: the 503 server_busy that ends the queue wait is written after
// the server's WriteTimeout has passed, and the client still gets its status and Retry-After (6.5 property 3: the server's
// WriteTimeout does not apply to a heavy request).
func TestAQueueRefusalReachesAClientPastTheServersWriteTimeout(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{QueueWait: 500 * time.Millisecond})
	hold, err := rig.adm.Acquire(t.Context(), admission.Pool)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	srv := realServer(t, rig, 150*time.Millisecond)
	resp, err := http.DefaultClient.Do(realImport(t, srv, "t1-a", "k-late", strings.NewReader(bodyHead+strings.Repeat("A", 6<<20-len(bodyHead+bodyTail))+bodyTail)))
	if err != nil {
		t.Fatalf("the refusal never reached the client: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b), `"server_busy"`) || resp.Header.Get("Retry-After") != "5" {
		t.Fatalf("%d %s Retry-After %q", resp.StatusCode, b, resp.Header.Get("Retry-After"))
	}
}

// slowBody sends head at once and then nothing until it is closed: a client whose uplink stalled in the middle of its file.
func slowBody() (*io.PipeReader, *io.PipeWriter) {
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write([]byte(bodyHead)) }()
	return pr, pw
}

// TestAStalledBodyIsBadRequestOnARealServer: a body cut by its read deadline is 400 and not the bare 499 that the cancelled
// request context made of it, and the 400 is delivered although it comes after the server's WriteTimeout (6.5 property 3).
// Its day token stays spent.
func TestAStalledBodyIsBadRequestOnARealServer(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{ReadBase: 300 * time.Millisecond})
	srv := realServer(t, rig, 100*time.Millisecond)
	pr, pw := slowBody()
	defer pw.Close()
	resp, err := http.DefaultClient.Do(realImport(t, srv, "t1-a", "k-stall", pr))
	if err != nil {
		t.Fatalf("the refusal of a stalled body never reached the client: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("a stalled body: %d %s, want 400", resp.StatusCode, b)
	}
	if got := rig.remainingDay(t, "t1"); got != 199 {
		t.Fatalf("%d tokens left, want 199: a cut body keeps its token spent", got)
	}
	// The place is given back when the handler returns, a moment after the client has its answer: wait for that.
	testwait.Until(t, 10*time.Second, "the place of a cut body to be given back", func() bool {
		places, pool := rig.adm.Held()
		return places == 0 && pool == 0
	})
}

// TestAnUploadHasTheWeightOfAnExportWhateverItsBody: an Upload merges into the whole profile, so a body of a few bytes is
// queued for 32 MiB, and one above 1 MiB for 48 (p2-B3-r9-6). The three weights are read through the pool: a request holding
// 17 MiB of it leaves only 31 MiB, which the small Upload cannot take.
func TestAnUploadHasTheWeightOfAnExportWhateverItsBody(t *testing.T) {
	for _, c := range []struct {
		size int
		want int64
	}{{len(bodyHead + bodyTail), admission.WeightExport}, {2 << 20, admission.WeightLarge}} {
		rig := newHeavyRig(t, admission.Config{})
		var took int64
		rig.handler = func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			took = admission.Pool - rig.adm.Free()
			w.WriteHeader(http.StatusOK)
		}
		body := bodyHead + strings.Repeat("A", max(0, c.size-len(bodyHead+bodyTail))) + bodyTail
		req := httptest.NewRequest("POST", "/api/v1/profiles/00000000-0000-4000-8000-000000000001/folders/00000000-0000-4000-8000-000000000002:upload", strings.NewReader(body))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "k-up")
		req.AddCookie(&http.Cookie{Name: "sid", Value: "t1-a"})
		w := serve(rig.h, req)
		if w.Code != http.StatusOK {
			t.Fatalf("size %d: %d %s", c.size, w.Code, w.Body)
		}
		if took != c.want {
			t.Errorf("an upload of %d bytes held %d MiB of the pool, want %d", c.size, took>>20, c.want>>20)
		}
	}
}

// slowReader is the connection of a client that does not read: its Write waits for the release, and counts the bytes it was
// given. It stands for a socket whose buffers are full, which a recorder never is.
type slowReader struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *slowReader) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.ResponseRecorder.Write(p)
}

func newSlowReader() *slowReader {
	return &slowReader{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
}

func jobGet(cookie string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1/jobs/00000000-0000-4000-8000-000000000001", nil)
	r.Host = host
	r.AddCookie(&http.Cookie{Name: "sid", Value: cookie})
	return r
}

// bigAnswer is what an ordinary handler of a big answer does: one write of the whole encoded buffer, as the generated
// visitors do.
func bigAnswer(size int, returned *sync.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", size)))
		if returned != nil {
			returned.Store(r.Header.Get("Cookie"), true)
		}
	}
}

// TestABigAnswerIsSpilledAndNoMemoryWaitsForTheClient: an ordinary answer above 64 KiB is written to a file, so the handler
// has returned (its buffer is free) while the client has not read a byte, and the room it takes is disk, counted for the
// tenant until the client has read it all (p2-B3-r10-1, r10-2, r10-3). The same handler gives a small answer straight to the
// connection with nothing counted.
func TestABigAnswerIsSpilledAndNoMemoryWaitsForTheClient(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	returned := &sync.Map{}
	rig.ordinary = bigAnswer(300<<10, returned)
	w := newSlowReader()
	done := make(chan struct{})
	go func() { rig.h.ServeHTTP(w, jobGet("t1-a")); close(done) }()
	<-w.entered
	if _, ok := returned.Load("sid=t1-a"); !ok {
		t.Fatal("the handler is still inside its write while the client has not read: its buffer is held for the client")
	}
	if got := rig.adm.AnswersHeld(); got != 300<<10 {
		t.Fatalf("%d bytes counted while the client has not read, want 300 KiB", got)
	}
	close(w.release)
	<-done
	if w.Code != http.StatusOK || w.Body.Len() != 300<<10 || w.Header().Get("Content-Length") != "307200" {
		t.Fatalf("the spilled answer: %d, %d bytes, length %q", w.Code, w.Body.Len(), w.Header().Get("Content-Length"))
	}
	if got := rig.adm.AnswersHeld(); got != 0 {
		t.Fatalf("%d bytes still counted after the answer was sent", got)
	}

	rig.ordinary = bigAnswer(4<<10, nil)
	small := newSlowReader()
	close(small.release)
	rig.h.ServeHTTP(small, jobGet("t1-a"))
	if small.Body.Len() != 4<<10 || rig.adm.AnswersHeld() != 0 {
		t.Fatalf("a small answer: %d bytes, %d counted", small.Body.Len(), rig.adm.AnswersHeld())
	}
}

// TestSpilledAnswersAreBoundedPerTenant: a tenant whose readers do not read gets 503 server_busy when its share is used,
// and another tenant is served, which needs as many tenants as there are places to refuse (p2-B3-r10-1, r10-3). With the
// pool of 16 MiB of round 9 four tenants were enough.
func TestSpilledAnswersAreBoundedPerTenant(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{AnswerTenant: 3 << 20, AnswerPool: 8 << 20})
	rig.ordinary = bigAnswer(2<<20, nil)
	var held []*slowReader
	var wg sync.WaitGroup
	for _, c := range []string{"t1-a", "t2-a", "t3-a"} {
		w := newSlowReader()
		held = append(held, w)
		wg.Add(1)
		go func() { defer wg.Done(); rig.h.ServeHTTP(w, jobGet(c)) }()
		<-w.entered
	}
	// t1 has 2 of its 3 MiB: a second answer of 2 MiB is its own refusal, with the body of a refusal and no part of the answer.
	r := serve(rig.h, jobGet("t1-b"))
	if r.Code != http.StatusServiceUnavailable || !strings.Contains(r.Body.String(), "server_busy") || r.Body.Len() > 1<<10 {
		t.Fatalf("a tenant above its share: %d %d bytes", r.Code, r.Body.Len())
	}
	// Three tenants hold 6 of the 8 MiB: a fourth tenant of 2 MiB still fits, so no tenant but t1 was refused.
	if r := serve(rig.h, jobGet("t4-a")); r.Code != http.StatusOK || r.Body.Len() != 2<<20 {
		t.Fatalf("another tenant while the pool has room: %d", r.Code)
	}
	for _, w := range held {
		close(w.release)
	}
	wg.Wait()
	if got := rig.adm.AnswersHeld(); got != 0 {
		t.Fatalf("%d bytes still counted after every client read", got)
	}
}

// TestAReservedAnswerIsNotCountedTwice: a rule create reserves the room of its answer before it writes, since the rules are
// committed when the answer is sent and a refusal then would lose it; the spill uses the reservation (p2-B3-r10-3).
func TestAReservedAnswerIsNotCountedTwice(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	var during int64
	rig.ordinary = func(w http.ResponseWriter, r *http.Request) {
		if e := httpx.HoldAnswer(r.Context(), 400<<10); e != nil {
			httpx.Write(w, r, e)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(strings.Repeat("x", 300<<10)))
		during = rig.adm.AnswersHeld()
	}
	w := serve(rig.h, jobGet("t1-a"))
	if w.Code != http.StatusCreated || w.Body.Len() != 300<<10 {
		t.Fatalf("%d %d bytes", w.Code, w.Body.Len())
	}
	if during != 400<<10 {
		t.Fatalf("%d bytes counted for a reserved answer, want the 400 KiB reserved", during)
	}
	if rig.adm.AnswersHeld() != 0 {
		t.Fatal("bytes left counted")
	}
	// A reservation that the tenant's share cannot take is refused before the handler writes anything.
	rig.ordinary = func(w http.ResponseWriter, r *http.Request) {
		if e := httpx.HoldAnswer(r.Context(), 1<<30); e != nil {
			httpx.Write(w, r, e)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	if w := serve(rig.h, jobGet("t1-a")); w.Code != http.StatusNoContent {
		t.Fatalf("a reservation above the share is taken as the share: %d", w.Code)
	}
}

// TestAStatusWithoutABodyReachesTheClient: the writer defers the status to the first write, so a handler that writes none
// (204) must still have its status sent when it returns.
func TestAStatusWithoutABodyReachesTheClient(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	rig.ordinary = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	if w := serve(rig.h, jobGet("t1-a")); w.Code != http.StatusNoContent {
		t.Fatalf("%d", w.Code)
	}
}

// TestARefusedSpillIsTheSameErrorTheClientGets: the error a handler's write returns when the tenant has no room for a spilled
// answer maps to 503 server_busy through FromError, the status finish sends, and not to the 500 internal that the log of
// API.fail would then show for a refusal that is the tenant's own share (p2-B3-r12-3). A size above the cap stays a real 500.
func TestARefusedSpillIsTheSameErrorTheClientGets(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{AnswerTenant: 3 << 20, AnswerPool: 8 << 20})
	rig.ordinary = bigAnswer(2<<20, nil)
	w := newSlowReader()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); rig.h.ServeHTTP(w, jobGet("t1-a")) }()
	<-w.entered

	var got *httpx.Error
	rig.ordinary = func(rw http.ResponseWriter, r *http.Request) {
		_, err := rw.Write([]byte(strings.Repeat("x", 2<<20)))
		got = httpx.FromError(err)
		httpx.Write(rw, r, got)
	}
	r := serve(rig.h, jobGet("t1-b"))
	if got == nil || got.Status != http.StatusServiceUnavailable || got.Code != httpx.CodeServerBusy {
		t.Fatalf("the handler's write error maps to %+v, want 503 server_busy", got)
	}
	if r.Code != http.StatusServiceUnavailable || !strings.Contains(r.Body.String(), "server_busy") {
		t.Fatalf("the client got %d", r.Code)
	}
	close(w.release)
	wg.Wait()

	rig.ordinary = func(rw http.ResponseWriter, r *http.Request) {
		_, err := rw.Write([]byte(strings.Repeat("x", int(admission.AnswerBytes)+1)))
		got = httpx.FromError(err)
		httpx.Write(rw, r, got)
	}
	_ = serve(rig.h, jobGet("t2-a"))
	if got == nil || got.Status != http.StatusInternalServerError {
		t.Fatalf("an answer above the cap maps to %+v, want 500", got)
	}
}
