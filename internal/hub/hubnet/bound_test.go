package hubnet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// h2Server serves root over HTTP/2 the way the hub's listener does for the parts the root handler reads:
// a rawConn on the connection (the per-connection count and, for node, the admitted node id) and the
// peer certificates a node connection carries. The client has a stream window of one byte, which is the
// zero window of an attacker as far as a response of more than a byte goes: it never gives credit unless
// it reads.
//
// ended gets a value when the stream of a request is over, which for HTTP/2 is when its context is
// cancelled: the end of the handler is not it, since the answer is written after the handler returns.
func h2Server(t *testing.T, root *Root, node uuid.UUID) (srv *httptest.Server, c *http.Client, ended <-chan struct{}) {
	t.Helper()
	done := make(chan struct{}, 64)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if node != uuid.Nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: time.Now().Add(time.Hour)}}}
		}
		ctx := r.Context()
		go func() { <-ctx.Done(); done <- struct{}{} }()
		root.ServeHTTP(w, r)
	}))
	ts.EnableHTTP2 = true
	ts.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connKey{}, &rawConn{src: netip.MustParseAddr("127.0.0.1"), node: node})
	}
	ts.StartTLS()
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close() })
	c = ts.Client()
	c.Transport.(*http.Transport).HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerStream: 1}
	return ts, c, done
}

// A request that is not a node's call has a deadline, and a peer that gives no window loses its stream
// at it (W3-r2-5): the answer, however small, is written after the handler returns, and without a
// deadline it waits for ever.
func TestAnonymousAnswerToAPeerWithNoWindowEnds(t *testing.T) {
	root := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.NotFoundHandler())
	root.AnonTimeout = 300 * time.Millisecond
	ts, c, ended := h2Server(t, root, uuid.Nil)
	resp, err := c.Get(ts.URL + "/nothing-here")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() // never read: the client gives no window credit
	testwait.Receive(t, ended, 10*time.Second, "the stream of an answer nobody reads to be ended by the server")
}

// A connection holds at most MaxRequestsPerConn requests in progress, and the ones past that are ended
// at once (W3-r2-5): the final write of an answer counts as in progress.
func TestAnonymousRequestsPerConnectionAreCapped(t *testing.T) {
	root := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.NotFoundHandler())
	root.AnonTimeout = time.Minute
	ts, c, _ := h2Server(t, root, uuid.Nil)
	for i := 0; i < MaxRequestsPerConn; i++ {
		resp, err := c.Get(ts.URL + "/nothing-here")
		if err != nil {
			t.Fatalf("request %d of %d refused: %v", i+1, MaxRequestsPerConn, err)
		}
		defer resp.Body.Close()
	}
	done := make(chan error, 1)
	go func() {
		resp, err := c.Get(ts.URL + "/nothing-here")
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a request past the cap was answered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request past the cap was held instead of ended")
	}
}

// The abort function of a node's call ends the HTTP stream under a handler that is blocked in a write
// to a peer with no window, which a cancelled context does not (W3-r2-7).
func TestAbortEndsAStreamBlockedInAWrite(t *testing.T) {
	node := uuid.New()
	abort := make(chan func(), 1)
	werr := make(chan error, 1)
	root := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		abort <- AbortFrom(r.Context())
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 64<<10)
		for {
			if _, err := w.Write(buf); err != nil {
				werr <- err
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				werr <- err
				return
			}
		}
	}))
	ts, c, _ := h2Server(t, root, node)
	pr, pw := io.Pipe()
	defer pw.Close()
	stop := make(chan struct{})
	defer close(stop)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ctrlz.hub.v1.NodeHub/Control", pr)
	req.Header.Set("Content-Type", "application/grpc")
	go func() {
		if resp, err := c.Do(req); err == nil {
			defer resp.Body.Close()
			<-stop
		}
	}()
	var f func()
	select {
	case f = <-abort:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not start")
	}
	// Blocked: the peer gave no window, so the write does not return on its own.
	if err, ended := testwait.TryReceive(werr, 300*time.Millisecond); ended {
		t.Fatalf("the write ended before the abort: %v", err)
	}
	f()
	select {
	case <-werr:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler is still blocked in its write after the abort")
	}
	f() // once the handler is gone it does nothing, and does not panic
}

// A server-streaming call has one request message, read whole under the cap before gRPC sees it, like a
// unary one (W3-r2-6); Control and the uploads keep a live body.
func TestServerStreamingBodyIsReadWhole(t *testing.T) {
	for m, one := range map[string]bool{"RenewCert": true, "FetchEntries": true, "FetchBlob": true, "GetSnapshot": true, "FetchBundle": true, "Control": false, "UploadLogs": false} {
		if oneRequest(m) != one {
			t.Errorf("oneRequest(%s) = %v", m, !one)
		}
	}
	var read int
	h := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		read = int(n)
	}))
	node := uuid.New()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, nodeReq("/ctrlz.hub.v1.NodeHub/FetchBlob", node, strings.NewReader(strings.Repeat("x", UnaryBodyBytes+1))))
	if w.Header().Get("Grpc-Status") != "3" || read != 0 {
		t.Fatalf("an oversized transfer request: status %q, read %d", w.Header().Get("Grpc-Status"), read)
	}
	h.ServeHTTP(httptest.NewRecorder(), nodeReq("/ctrlz.hub.v1.NodeHub/FetchBlob", node, strings.NewReader(strings.Repeat("x", 100))))
	if read != 100 {
		t.Fatalf("a small transfer request: read %d", read)
	}
}

// What a live body has read and the handler has not taken is bounded, however small the reads are
// (W3-r2-6): one byte per read pins a buffer of 16 KiB in grpc-go, and the reader waits instead.
func TestLiveBodyUnreadBudget(t *testing.T) {
	var reads atomic.Int64
	var consume func(any)
	started := make(chan struct{})
	h := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		consume = func(m any) { Consumed(r.Context(), m) }
		close(started)
		buf := make([]byte, 1)
		for {
			if _, err := r.Body.Read(buf); err != nil {
				return
			}
			reads.Add(1)
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	req := nodeReq("/ctrlz.hub.v1.NodeHub/Control", uuid.New(), iotest.OneByteReader(strings.NewReader(strings.Repeat("x", 1<<20))))
	req = req.WithContext(context.WithValue(ctx, connKey{}, req.Context().Value(connKey{})))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); h.ServeHTTP(httptest.NewRecorder(), req) }()
	<-started
	stable := func() int64 {
		last := int64(-1)
		for i := 0; i < 50; i++ {
			time.Sleep(20 * time.Millisecond)
			if n := reads.Load(); n == last {
				return n
			} else {
				last = n
			}
		}
		t.Fatal("the reader never stopped: the unread budget is not enforced")
		return 0
	}
	before := stable()
	if before < 1 || before > minUnreadReads+1 {
		t.Fatalf("the reader stopped after %d reads, want about %d", before, minUnreadReads)
	}
	// The handler takes an empty message out (five bytes with the gRPC prefix): reads resume.
	consume(&hubv1.NodeMessage{})
	testwait.Until(t, 5*time.Second, "the reader to go on after a message was taken out", func() bool { return reads.Load() > before })
	after := stable()
	if after <= before {
		t.Fatalf("taking a message out did not let the reader go on: %d then %d", before, after)
	}
	cancel()
	wg.Wait()
}

func TestGauge(t *testing.T) {
	g := newGauge()
	for i := 0; i < minUnreadReads-1; i++ {
		g.read(1)
	}
	if g.full() {
		t.Fatal("full below the allowance of reads")
	}
	g.read(1)
	if !g.full() {
		t.Fatal("not full at the allowance of reads")
	}
	g.consume(1)
	if g.full() {
		t.Fatal("still full after a read was taken out")
	}
	// Dense reads: bytes, not reads, are the bound.
	d := newGauge()
	for i := 0; i < MaxUnreadBytes/(16<<10); i++ {
		if d.full() {
			t.Fatalf("full after %d dense reads", i)
		}
		d.read(16 << 10)
	}
	if !d.full() {
		t.Fatal("not full at the byte budget")
	}
	d.consume(-1)
	if d.full() || d.pending != 0 || len(d.reads) != 0 {
		t.Fatal("consume(-1) left something behind")
	}
}
