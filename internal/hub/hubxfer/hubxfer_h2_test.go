package hubxfer_test

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubxfer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// fetchServer is the one door of NodeHub this test serves.
type fetchServer struct {
	hubv1.UnimplementedNodeHubServer
	svc *hubxfer.Service
}

func (f fetchServer) FetchEntries(req *hubv1.FetchEntriesRequest, srv grpc.ServerStreamingServer[hubv1.StoredEntry]) error {
	return f.svc.FetchEntries(req, srv)
}

// H-r3-3: the hub serves NodeHub through grpc's ServeHTTP, where a write that waits for a window keeps the stream, the slots it
// counts and the entries in flight until the peer goes away, and neither a returning handler nor a cancelled context ends it (the
// one entry here is accepted by the transport, so the handler returns at once and the answer's write is what hangs). A node that
// keeps its connection alive and gives its stream no window must lose the stream at FetchHold, with the share. The
// client here is a bare HTTP/2 peer: it answers settings and pings and never opens a window.
func TestAStreamWithNoWindowIsEndedAtTheHoldDeadline(t *testing.T) {
	w := newWorld(t)
	w.bounds[w.a] = 1
	w.log.rows = []store.LogRow{entry(1)}
	w.log.rows[0].Payload = bytes.Repeat([]byte("p"), 1<<20) // far above any buffer on the way: the write must wait for the window
	svc := withTimes(w, 10*time.Second, 300*time.Millisecond)

	gs := grpc.NewServer()
	hubv1.RegisterNodeHubServer(gs, fetchServer{svc: svc})
	served := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		defer close(served)
		ctx, ended := hubnet.WithEnded(hubnet.WithIdentity(r.Context(), hubnet.Identity{Node: true, NodeID: w.a}))
		defer ended() // what the root handler does once the call is over: the share is held until then
		// What hubnet.Root hands every NodeHub call (root.go endStream): a deadline in the past ends the HTTP/2 stream.
		ctx = hubnet.WithAbort(ctx, func() {
			rc := http.NewResponseController(rw)
			past := time.Unix(1, 0)
			_ = rc.SetReadDeadline(past)
			_ = rc.SetWriteDeadline(past)
		})
		gs.ServeHTTP(rw, r.WithContext(ctx))
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // a test server's own certificate
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fr := http2.NewFramer(conn, conn)
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	// SETTINGS_INITIAL_WINDOW_SIZE of zero: the server may send no byte of a response body on any stream.
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatal(err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, kv := range [][2]string{{":method", "POST"}, {":scheme", "https"}, {":path", "/ctrlz.hub.v1.NodeHub/FetchEntries"},
		{":authority", "hub.test"}, {"content-type", "application/grpc"}, {"te", "trailers"}} {
		if err := enc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	msg, err := proto.Marshal(&hubv1.FetchEntriesRequest{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte{0, 0, 0, 0, 0}, msg...)
	binary.BigEndian.PutUint32(body[1:5], uint32(len(msg)))
	if err := fr.WriteData(1, true, body); err != nil {
		t.Fatal(err)
	}
	// Keep the connection healthy the way a live node does: acknowledge settings and answer pings, grant no window.
	var wmu sync.Mutex
	go func() {
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			wmu.Lock()
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = fr.WriteSettingsAck()
				}
			case *http2.PingFrame:
				if !f.IsAck() {
					_ = fr.WritePing(true, f.Data)
				}
			}
			wmu.Unlock()
		}
	}()

	testwait.Receive(t, served, 10*time.Second, "the NodeHub call ends once its hold deadline has passed and the stream is ended")
	// The share and the node's slot went with it: the node's next call runs.
	st := &stream[hubv1.StoredEntry]{ctx: ctxOf(w.a)}
	if err := svc.FetchEntries(&hubv1.FetchEntriesRequest{Limit: 1}, st); err != nil || len(st.sent) != 1 {
		t.Fatalf("the node's next call: %v, %d entries", err, len(st.sent))
	}
}
