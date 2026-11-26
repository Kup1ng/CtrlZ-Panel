package hubctl

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubroll"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The poll times of p4-nodes 5.5 and 5.7 (control pool).
const (
	LogEvery   = 500 * time.Millisecond
	OrderEvery = 5 * time.Second
	FreeEvery  = time.Second
	// readTimeout bounds one poll statement: the control pool has two connections for the config builds, the free
	// switch and this poll, so one that hangs must not hold them (5.7).
	readTimeout = 2 * time.Second
	pollPage    = 500
)

// FeedStore is what the feed reads on the control pool.
type FeedStore interface {
	HubLogHeads(ctx context.Context, after uint64, limit int) ([]store.HubLogHead, error)
	HubLogLatest(ctx context.Context) (store.HubLogHead, bool, error)
	HubMembership(ctx context.Context) (store.HubMembership, error)
	HubFreeDNS(ctx context.Context) (bool, uint64, error)
}

// Feed turns what the database says into what the hub keeps in memory: the entries the compiler wrote (so the rollout
// can walk them), the order of the nodes, and the free DNS switch.
type Feed struct {
	St   FeedStore
	Roll *hubroll.Roll
	Log  *slog.Logger
	// OnEntry is told every new entry head after the roll has it: the revocation scan of 5.5 attaches here, so the log is
	// read once by the hub and not once per consumer.
	OnEntry []func(store.HubLogHead)
	// Before is told each new entry head before the roll hears of it, and may refuse it: the log view of 5.5 reads the entry and queues its
	// Revocations there, so they are ahead of any HeadNotice for it on every stream. An error stops the poll at that entry and it is
	// tried again at the next poll. live is false for the head read at start, whose Revocations are not sent (a restart loses them).
	Before func(ctx context.Context, h store.HubLogHead, live bool) error
	// OnFreeOff is told each new version read with the switch off (5.2a, Turning it off fast).
	OnFreeOff func(version uint64)

	mu      sync.Mutex
	last    uint64
	started bool
	freeOff bool
	freeVer uint64
	freeOK  bool
}

// Start reads the head and the order once. A hub restart begins every cursor at the release point, so the entries that
// exist now are released and only later ones are walked (6.4). It fails when the database cannot be read, and the hub does
// not serve a log it has not seen.
func (f *Feed) Start(ctx context.Context) error {
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	h, found, err := f.St.HubLogLatest(rctx)
	if err != nil {
		return err
	}
	if found {
		if f.Before != nil {
			if err := f.Before(ctx, h, false); err != nil {
				return err
			}
		}
		f.Roll.Written(h.Seq, "policy")
		f.mu.Lock()
		f.last = h.Seq
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.started = true
	f.mu.Unlock()
	f.order(ctx)
	f.PollFree(ctx)
	return nil
}

// PollLog reads the entries after the last one seen and gives them to the roll and the observers.
func (f *Feed) PollLog(ctx context.Context) {
	f.mu.Lock()
	after, started := f.last, f.started
	f.mu.Unlock()
	if !started {
		return
	}
	for {
		rctx, cancel := context.WithTimeout(ctx, readTimeout)
		rows, err := f.St.HubLogHeads(rctx, after, pollPage)
		cancel()
		if err != nil {
			if f.Log != nil {
				f.Log.Warn("log poll failed")
			}
			return
		}
		for _, h := range rows {
			if f.Before != nil {
				if err := f.Before(ctx, h, true); err != nil {
					if f.Log != nil {
						f.Log.Warn("log view could not read an entry")
					}
					f.mu.Lock()
					f.last = after
					f.mu.Unlock()
					return
				}
			}
			f.Roll.Written(h.Seq, h.Class)
			for _, fn := range f.OnEntry {
				fn(h)
			}
			after = h.Seq
		}
		f.mu.Lock()
		f.last = after
		f.mu.Unlock()
		if len(rows) < pollPage {
			return
		}
	}
}

func (f *Feed) order(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	m, err := f.St.HubMembership(rctx)
	if err != nil {
		return
	}
	f.Roll.SetOrder(hubroll.Order(m))
}

// PollFree reads the free DNS switch once.
func (f *Feed) PollFree(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	enabled, ver, err := f.St.HubFreeDNS(rctx)
	if err != nil {
		return // the last read stands: a lost read can only leave the floor where it was
	}
	f.mu.Lock()
	prevOff, prevVer, prevOK := f.freeOff, f.freeVer, f.freeOK
	f.freeOff, f.freeVer, f.freeOK = !enabled, ver, true
	f.mu.Unlock()
	if !enabled && prevOK && (!prevOff || prevVer != ver) && f.OnFreeOff != nil {
		f.OnFreeOff(ver)
	}
}

// FreeOff is the version of the switch while it is off, found false while it is on or not yet read.
func (f *Feed) FreeOff() (version uint64, off bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.freeVer, f.freeOff && f.freeOK
}

// Run polls until ctx ends: the log every 500 ms, the order every 5 s and the free switch every second. Each runs in its
// own goroutine, so a slow read of one never delays another's tick.
func (f *Feed) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, l := range []struct {
		every time.Duration
		fn    func(context.Context)
	}{{LogEvery, f.PollLog}, {OrderEvery, f.order}, {FreeEvery, f.PollFree}} {
		wg.Add(1)
		safego.Go(f.Log, unitCtl, func() {
			defer wg.Done()
			t := time.NewTicker(l.every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					func() {
						defer safego.Keep(f.Log, unitCtl)
						l.fn(ctx)
					}()
				}
			}
		})
	}
	wg.Wait()
}
