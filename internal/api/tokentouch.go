package api

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// tokenToucher writes last_used_at of API tokens (P3 6.3 step 7) for the requests that pass the token's gates.
//
// It is best effort and sits outside the handler's transaction (store.Store.TouchAPIToken, review round 1 of D5, p3-D5-r1-5):
// a failure is dropped, since a token request is never refused for want of this write, and a row another transaction holds is
// skipped, never waited for. The in-process memory below only spares the database a transaction per request: one attempt per
// token per TokenTouchEvery. The conditional UPDATE decides again, so a second process or a restart can at worst write once more.
type tokenToucher struct {
	db *store.Store

	mu   sync.Mutex
	last map[uuid.UUID]time.Time
}

func newTokenToucher(db *store.Store) *tokenToucher {
	return &tokenToucher{db: db, last: map[uuid.UUID]time.Time{}}
}

// touchSweepAbove is the size of the memory past which an attempt first drops the entries that have run out: a deleted or
// revoked token is never seen again, so its entry would otherwise stay for the life of the process.
const touchSweepAbove = 1024

// touch records the use of the token at at. nil is a toucher that does nothing (a test with no store).
func (t *tokenToucher) touch(ctx context.Context, tenant, id uuid.UUID, at time.Time) {
	if t == nil || t.db == nil {
		return
	}
	t.mu.Lock()
	if prev, ok := t.last[id]; ok {
		// A clock that moved back is a reason to try again, not to wait for it to catch up.
		if d := at.Sub(prev); d >= 0 && d < store.TokenTouchEvery {
			t.mu.Unlock()
			return
		}
	}
	t.last[id] = at
	if len(t.last) > touchSweepAbove {
		for k, v := range t.last {
			if at.Sub(v) >= store.TokenTouchEvery {
				delete(t.last, k)
			}
		}
	}
	t.mu.Unlock()

	if err := t.db.TouchAPIToken(ctx, tenant, id, at); err != nil {
		// Forget the attempt, so the next request tries again.
		t.mu.Lock()
		if t.last[id].Equal(at) {
			delete(t.last, id)
		}
		t.mu.Unlock()
	}
}
