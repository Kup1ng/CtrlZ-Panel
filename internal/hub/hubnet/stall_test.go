package hubnet

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/http2"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// A request that has the NodeHub path on a node's connection but is not a gRPC call is not what
// serveNodeHub handles, so it is bounded like every other request: it counts against the connection's
// cap of requests in progress (W3-r3-1, W3-r3-4). The cap is the observable, since the peer's missing
// window keeps each answer in progress.
func TestNonGRPCNodeHubPathOnANodeConnectionIsBounded(t *testing.T) {
	root := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.NotFoundHandler())
	root.AnonTimeout = time.Minute
	ts, c, _ := h2Server(t, root, uuid.New())
	get := func() error {
		resp, err := c.Get(ts.URL + "/ctrlz.hub.v1.NodeHub/x")
		if err == nil {
			defer resp.Body.Close()
		}
		return err
	}
	for i := 0; i < MaxRequestsPerConn; i++ {
		resp, err := c.Get(ts.URL + "/ctrlz.hub.v1.NodeHub/x")
		if err != nil {
			t.Fatalf("request %d of %d refused: %v", i+1, MaxRequestsPerConn, err)
		}
		defer resp.Body.Close()
	}
	done := make(chan error, 1)
	go func() { done <- get() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a non-gRPC NodeHub request past the cap was answered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a non-gRPC NodeHub request past the cap was held instead of ended")
	}
}

// A write deadline on HTTP/2 only queues a RST_STREAM behind the frame being written, so a peer that
// stops reading its socket and keeps the connection alive with PINGs leaves every deadline void unless
// the connection itself has a write timeout (W3-r3-3). The client here never reads a byte; the handler is
// a download that would fill any buffer, and it must be released.
func TestPeerThatStopsReadingTheSocketLosesItsHandler(t *testing.T) {
	released := make(chan struct{})
	started := make(chan struct{})
	ts := httptest.NewUnstartedServer(nil)
	NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(released)
		close(started)
		buf := make([]byte, 256<<10)
		rc := http.NewResponseController(w)
		for {
			if _, err := w.Write(buf); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}), ts.Config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts.Config.ConnContext = nil // the listener's raw connection is not part of this test
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	raw, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.(*net.TCPConn).SetReadBuffer(4096)
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(conn, nil)
	// Flow control must not be what blocks the server: only the socket is.
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1<<31 - 1}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteWindowUpdate(0, 1<<31-1-65535); err != nil {
		t.Fatal(err)
	}
	var hdr []byte
	for _, kv := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/x"}, {":authority", "hub"}} {
		hdr = appendLiteral(hdr, kv[0], kv[1])
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hdr, EndStream: true, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	testwait.Receive(t, started, 10*time.Second, "the handler to start")

	// The peer stays alive: a PING every two seconds, so the keepalive never gives up on it.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			time.Sleep(2 * time.Second) // the pause between two pings of a loop that tests stop
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_ = fr.WritePing(false, [8]byte{})
		}
	}()
	testwait.Receive(t, released, 3*WriteByteTimeout, "the handler of a peer that reads nothing to be released")
}

// appendLiteral writes one header as a literal field without indexing, new name: no HPACK state is needed.
func appendLiteral(b []byte, name, value string) []byte {
	b = append(b, 0x00, byte(len(name)))
	b = append(b, name...)
	b = append(b, byte(len(value)))
	return append(b, value...)
}
