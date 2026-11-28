package hubtel

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// uploadSlots lets one stream of each upload method be open per node (5.2): a second is refused with RESOURCE_EXHAUSTED, so
// a node cannot hold the hub's goroutines by opening streams it does not use.
type uploadSlots struct {
	mu   sync.Mutex
	open map[string]bool
}

func newUploadSlots() *uploadSlots { return &uploadSlots{open: make(map[string]bool)} }

func (u *uploadSlots) take(node uuid.UUID, method string) (release func(), ok bool) {
	k := node.String() + "/" + method
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.open[k] {
		return nil, false
	}
	u.open[k] = true
	var once sync.Once
	return func() { once.Do(func() { u.mu.Lock(); delete(u.open, k); u.mu.Unlock() }) }, true
}

// OpenUploads is the number of upload streams open, for tests.
func (t *Telemetry) OpenUploads() int {
	t.uploads.mu.Lock()
	defer t.uploads.mu.Unlock()
	return len(t.uploads.open)
}

// serveUpload is the loop of one upload stream: the one writer of its Acks, reading until the node ends it or sends nothing
// for UploadIdle. A batch that fails validation is dropped, counted and acknowledged (it can never succeed, so the node
// must not resend it for good); a stream is never torn down for one bad item (SC 3.5).
func serveUpload[M any](ctx context.Context, t *Telemetry, method string, recv func() (*M, error), send func(*telemetryv1.Ack) error,
	handle func(node uuid.UUID, m *M) *telemetryv1.Ack) error {
	id := hubnet.IdentityFrom(ctx)
	if !id.Node {
		return status.Error(codes.Unauthenticated, "certificate not accepted")
	}
	release, ok := t.uploads.take(id.NodeID, method)
	if !ok {
		return status.Error(codes.ResourceExhausted, "an upload stream of this kind is already open")
	}
	defer release()
	type got struct {
		m   *M
		err error
	}
	in := make(chan got)
	stop := make(chan struct{})
	defer close(stop)
	// The reader is a goroutine of its own so an idle stream can end while a Recv is blocked; gRPC ends the Recv when this
	// handler returns.
	safego.Go(t.cfg.Log, unitUpload, func() {
		for {
			m, err := recv()
			select {
			case in <- got{m, err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	})
	idle := time.NewTimer(UploadIdle)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-idle.C:
			return nil
		case g := <-in:
			if g.err != nil {
				return nil
			}
			idle.Reset(UploadIdle)
			if a := handle(id.NodeID, g.m); a != nil {
				if err := send(a); err != nil {
					return nil
				}
			}
		}
	}
}

// ReportActivity is the NodeHub method of 5.4: the node's ActivityBatches in, one Ack each out.
func (t *Telemetry) ReportActivity(s grpc.BidiStreamingServer[telemetryv1.ActivityBatch, telemetryv1.Ack]) error {
	return serveUpload(s.Context(), t, "activity", s.Recv, s.Send, func(node uuid.UUID, b *telemetryv1.ActivityBatch) *telemetryv1.Ack {
		if err := wire.ValidateTelemetryMessage(b, t.cfg.Now().Unix()); err != nil {
			t.dropBatchInvalid.add()
		} else {
			t.acceptActivity(node, b)
		}
		return &telemetryv1.Ack{BatchId: b.BatchId, Durable: true}
	})
}

// UploadCounters is the NodeHub method for the free DNS counters (5.2a, SC 12). Only the free part is taken until P5: the
// counters items are dropped and counted. A batch the node already sent, by id or by bucket, adds nothing and is still
// acknowledged, so a resend after a lost Ack counts once.
func (t *Telemetry) UploadCounters(s grpc.BidiStreamingServer[telemetryv1.CountersBatch, telemetryv1.Ack]) error {
	return serveUpload(s.Context(), t, "counters", s.Recv, s.Send, func(node uuid.UUID, b *telemetryv1.CountersBatch) *telemetryv1.Ack {
		ack := &telemetryv1.Ack{BatchId: b.BatchId, Durable: true}
		if !t.counts.Allow(node.String()) {
			t.dropCountersRate.add()
			return nil // not acknowledged: the node resends it after its own pause
		}
		if err := wire.ValidateTelemetryMessage(b, t.cfg.Now().Unix()); err != nil {
			if !errors.Is(err, wire.ErrFreePartInvalid) {
				t.dropBatchInvalid.add()
				return ack
			}
			// The counters are judged fine; only the free part is bad: drop it, count it, handle the rest (5.2a).
			t.dropCountersPart.add()
			b.Free = nil
		}
		if len(b.Counters) > 0 {
			t.dropCountersItems.add()
		}
		if len(b.Free) == 0 {
			return ack
		}
		items := make([]store.HubFreeItem, 0, len(b.Free))
		for _, f := range b.Free {
			items = append(items, store.HubFreeItem{
				Protocol: protocolName(f.Protocol), Outcome: outcomeName(f.Outcome), RCode: int(f.Rcode), Count: f.Count,
			})
		}
		wctx, cancel := context.WithTimeout(s.Context(), writeTimeout)
		defer cancel()
		applied, err := t.cfg.Store.HubFreeCounters(wctx, node, b.BatchId, b.BucketStart, items)
		if err != nil {
			return nil // the node resends the same batch
		}
		if applied {
			t.wroteFree.add()
		}
		return ack
	})
}

// UploadLogs is refused until P5.
func (t *Telemetry) UploadLogs(grpc.BidiStreamingServer[telemetryv1.LogBatch, telemetryv1.Ack]) error {
	return status.Error(codes.Unimplemented, "UploadLogs is not available")
}

// outcomeName is the stored text of a free outcome: its enum name in lower case without the prefix.
func outcomeName(o telemetryv1.FreeOutcome) string {
	return strings.ToLower(strings.TrimPrefix(o.String(), "FREE_OUTCOME_"))
}
