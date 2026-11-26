package hubctl_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
)

// failingWild fails for one zone and covers none other, so the other zone falls to the private CA.
type failingWild struct{ bad string }

func (f failingWild) Covering(_ context.Context, zone string) ([]byte, []byte, time.Time, bool, error) {
	if zone == f.bad {
		return nil, nil, time.Time{}, false, errors.New("the uploaded wildcard does not open")
	}
	return nil, nil, time.Time{}, false, nil
}

// lockedBuf is a log sink the stream's goroutine and the test can both touch.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// Through the stream (I-r3-1): when one zone of a node cannot be built, the node is sent the other zone's CertBundle and no
// bundle for the failed one. A CertBundle with no content is never sent, and the failure is logged.
func TestTheStreamSendsTheHealthyZonesBundleAndNoEmptyOne(t *testing.T) {
	zkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, err := hubpki.IssueZoneCA(zkey, []string{"dns.a.test", "dns.b.test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuf{}
	w := newWorld(t, free{}, func(c *hubctl.Config) {
		c.Certs = hubctl.NewCerts(zoneOnly{ca}, failingWild{bad: "dns.a.test"}, time.Now)
		c.Log = slog.New(slog.NewTextHandler(logs, nil))
	})
	n := newNode(t)
	w.active(n)
	w.st.mu.Lock()
	r := w.st.reads[n.id]
	r.DNSZone, r.PrevZone, r.PrevUntil = "dns.a.test", "dns.b.test", time.Now().Add(time.Hour)
	w.st.reads[n.id] = r
	w.st.mu.Unlock()
	done := w.open(n)
	n.in <- heartbeat(0)

	var bundles int
	deadline := time.After(500 * time.Millisecond)
loop:
	for {
		select {
		case m := <-n.out:
			if cb, ok := m.Body.(*hubv1.HubMessage_CertBundle); ok {
				bundles++
				if cb.CertBundle == nil || len(cb.CertBundle.ChainPem) == 0 {
					t.Fatal("an empty CertBundle was sent")
				}
			}
		case <-deadline:
			break loop
		}
	}
	if bundles != 1 {
		t.Fatalf("%d bundles sent, want the healthy zone's one", bundles)
	}
	if !strings.Contains(logs.String(), "cert bundle not built") {
		t.Fatalf("the failed zone was not logged: %q", logs.String())
	}
	n.cancel()
	<-done
}

// While the zone CA is not in force every private-CA zone says ErrNoZoneCA, which is expected and not logged. A zone that
// fails for another reason beside it must still be logged (I-r3-2, I-r3-4): the joined error matches ErrNoZoneCA for any
// member, so the log decision looks at each one.
func TestARealFailureIsLoggedBesideAZoneThatOnlyWaitsForItsCA(t *testing.T) {
	for name, tc := range map[string]struct {
		bad     string // the zone whose wildcard fails; "" means none
		wantLog bool
	}{
		"only the CA is missing":           {bad: "", wantLog: false},
		"a real failure beside the CA gap": {bad: "dns.a.test", wantLog: true},
	} {
		t.Run(name, func(t *testing.T) {
			logs := &lockedBuf{}
			w := newWorld(t, free{}, func(c *hubctl.Config) {
				c.Certs = hubctl.NewCerts(zoneOnly{nil}, failingWild{bad: tc.bad}, time.Now)
				c.Log = slog.New(slog.NewTextHandler(logs, nil))
			})
			n := newNode(t)
			w.active(n)
			w.st.mu.Lock()
			r := w.st.reads[n.id]
			r.DNSZone, r.PrevZone, r.PrevUntil = "dns.a.test", "dns.b.test", time.Now().Add(time.Hour)
			w.st.reads[n.id] = r
			w.st.mu.Unlock()
			done := w.open(n)
			n.in <- heartbeat(0)
			time.Sleep(300 * time.Millisecond) // several config passes (every 10 ms)
			if got := strings.Contains(logs.String(), "cert bundle not built"); got != tc.wantLog {
				t.Fatalf("logged %v, want %v: %q", got, tc.wantLog, logs.String())
			}
			n.cancel()
			<-done
		})
	}
}
