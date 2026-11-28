package hubnet

import (
	"context"
	"sync"

	"google.golang.org/protobuf/proto"
)

// The unread budget of a live request body (W3-r2-6). grpc-go under ServeHTTP reads the body in a loop of
// its own, into a pooled buffer of 16 KiB per Read, and queues each buffer whole however few bytes
// arrived, with no bound. A peer that sends one byte per DATA frame therefore costs 16 KiB a byte, and a
// peer whose handler is slow costs whatever it can send. The gauge bounds what has been read from the
// body and not yet taken out of the queue by a handler's RecvMsg: Read waits while the budget is spent,
// which withholds the HTTP/2 window credit and stalls the sender at its own connection.
const (
	// MaxUnreadBytes is the bytes a stream may have read and not consumed. It must stay at least twice
	// the largest message the NodeHub server accepts (the default of 4 MiB today), so that a handler
	// that is half way through the largest message always has the rest of it in the queue.
	MaxUnreadBytes = 8 << 20
	// minUnreadReads and unreadReadSize bound the number of reads in the queue, each of which pins a
	// buffer of 16 KiB: a queue may hold 32 reads of any size plus one per 8 KiB it carries, so the memory
	// it pins is at most 512 KiB and twice the bytes it carries.
	minUnreadReads = 32
	unreadReadSize = 8 << 10
)

// gauge counts one stream's unread body, as a queue of the sizes of the reads that filled it.
type gauge struct {
	mu      sync.Mutex
	reads   []int
	pending int
	wake    wakeup
}

// wakeup is a channel of its own type: a struct that holds a mutex and a channel reads to the cache lint
// as a hand-written cache, which a byte budget is not.
type wakeup chan struct{}

func newGauge() *gauge { return &gauge{wake: make(wakeup, 1)} }

// full says whether the next read has to wait.
func (g *gauge) full() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pending >= MaxUnreadBytes || len(g.reads) >= minUnreadReads+g.pending/unreadReadSize
}

// wait blocks until the budget has room or ctx ends.
func (g *gauge) wait(ctx context.Context) error {
	for g.full() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-g.wake:
		}
	}
	return nil
}

func (g *gauge) read(n int) {
	if n <= 0 {
		return
	}
	g.mu.Lock()
	g.reads = append(g.reads, n)
	g.pending += n
	g.mu.Unlock()
}

// consume takes n bytes off the front of the queue; a negative n takes everything.
func (g *gauge) consume(n int) {
	g.mu.Lock()
	if n < 0 || n > g.pending {
		n = g.pending
	}
	g.pending -= n
	i := 0
	for i < len(g.reads) && n > 0 {
		if g.reads[i] <= n {
			n -= g.reads[i]
			i++
			continue
		}
		g.reads[i] -= n
		n = 0
	}
	g.reads = append(g.reads[:0], g.reads[i:]...)
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

type gaugeKey struct{}

func withGauge(ctx context.Context, g *gauge) context.Context {
	return context.WithValue(ctx, gaugeKey{}, g)
}

// Consumed tells the request's gauge that a handler took message m out of the stream. The size it
// subtracts is the wire size of m (the five-byte gRPC prefix and the encoding), which is exact for a
// message a conforming peer encoded; a message that is longer on the wire (non-minimal varints) leaves
// the difference counted, which only ever costs the peer that wrote it, since the stream stalls and
// the peer's window is not credited. A value that is not a proto message takes everything off.
func Consumed(ctx context.Context, m any) {
	g, _ := ctx.Value(gaugeKey{}).(*gauge)
	if g == nil {
		return
	}
	pm, ok := m.(proto.Message)
	if !ok {
		g.consume(-1)
		return
	}
	g.consume(5 + proto.Size(pm))
}
