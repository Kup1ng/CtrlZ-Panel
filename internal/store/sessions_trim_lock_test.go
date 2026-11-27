package store_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// TestSessionsTrimWaitsForTheUserLock proves, without any timing, that two logins of one account trim one
// after the other. The "sessions.per_user" driver of TestCapsRaceHarness races eight logins and counts the
// result, but it only sees a trim that skips the user row lock when the trims happen to overlap: on a loaded
// runner they ran one after another, each counted the commit of the one before, the cap held without the
// lock, and the mutant that removes the lock survived (GitHub run of the round 25 merge). That is a flake of
// the proof, not of the product.
//
// Here the first login trims and then stays open, holding the lock. The second login inserts its own session
// (a FOR KEY SHARE on the user row, which the NO KEY UPDATE of the lock does not block) and trims. With the
// lock the second trim is parked until the first commits and then counts it, so the account ends exactly at
// the cap. Without the lock the second trim finishes at once, blind to the first login's uncommitted row, and
// the account ends over the cap. The test waits on the condition (the second call is parked on a lock, or it
// is finished), never on the clock.
func TestSessionsTrimWaitsForTheUserLock(t *testing.T) {
	e := newRaceEnv(t)
	live := func(user uuid.UUID) int {
		return e.count(t, `SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL`, user)
	}
	insert := func(tx store.Tx, user uuid.UUID, label string) error {
		now := time.Now()
		id, err := tx.SessionCreate(store.NewSession{UserID: user, TokenHash: []byte(label), IdleExpiresAt: now.Add(time.Hour),
			AbsoluteExpiresAt: now.Add(2 * time.Hour), AuthMethod: "password", At: now})
		if err != nil {
			return err
		}
		_, err = tx.RefreshCreate(store.NewRefresh{SessionID: id, UserID: user, FamilyID: uuid.New(), TokenHash: []byte("r-" + label), ExpiresAt: now.Add(time.Hour)})
		return err
	}
	// One below the cap: the first login lands on the cap and trims nothing, so a second login that did not
	// see it would also trim nothing.
	for i := live(e.A.User); i < caps.MaxSessions-1; i++ {
		if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			return insert(tx, e.A.User, fmt.Sprintf("fill-%d", i))
		}); err != nil {
			t.Fatalf("filling: %v", err)
		}
	}
	if n := live(e.A.User); n != caps.MaxSessions-1 {
		t.Fatalf("the account holds %d live sessions before the logins, want %d", n, caps.MaxSessions-1)
	}
	// Tenant B has sessions of its own, which no trim of A may touch.
	for i := 0; i < 3; i++ {
		if err := e.tenant.WithTenant(e.ctx, e.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			return insert(tx, e.B.User, fmt.Sprintf("b-%d", i))
		}); err != nil {
			t.Fatalf("tenant B: %v", err)
		}
	}
	bLive := live(e.B.User)

	var wg sync.WaitGroup
	firstTrimmed, release, secondDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	signalTrimmed := sync.OnceFunc(func() { close(firstTrimmed) })
	releaseFirst := sync.OnceFunc(func() { close(release) })
	// A failed assertion ends the test through Goexit; the first login must not stay parked on its release.
	defer releaseFirst()

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer signalTrimmed() // a failure before the trim must not leave the test waiting for it
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if err := insert(tx, e.A.User, "first"); err != nil {
				return err
			}
			if _, err := tx.SessionsTrim(e.A.User, caps.MaxSessions, time.Now()); err != nil {
				return err
			}
			signalTrimmed()
			<-release
			return nil
		})
		if err != nil {
			t.Errorf("first login: %v", err)
		}
	}()
	testwait.Receive(t, firstTrimmed, 30*time.Second, "the first login to trim and hold its transaction")

	go func() {
		defer wg.Done()
		defer close(secondDone)
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if err := insert(tx, e.A.User, "second"); err != nil {
				return err
			}
			_, err := tx.SessionsTrim(e.A.User, caps.MaxSessions, time.Now())
			return err
		})
		if err != nil {
			t.Errorf("second login: %v", err)
		}
	}()
	testwait.Until(t, 30*time.Second, "the second login to park on a lock or to finish", func() bool {
		select {
		case <-secondDone:
			return true
		default:
		}
		return e.count(t, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`) > 0
	})
	select {
	case <-secondDone:
		t.Error("the second login finished its trim while the first held the user row lock: the trim does not take the lock, so two logins trim blind to each other")
	default:
	}
	releaseFirst()
	wg.Wait()

	if n := live(e.A.User); n != caps.MaxSessions {
		t.Errorf("the account holds %d live sessions after two logins, want exactly the cap %d", n, caps.MaxSessions)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.refresh_tokens r JOIN ctrlz.sessions s ON s.id = r.session_id
		WHERE s.user_id = $1 AND s.revoked_at IS NOT NULL AND r.revoked_at IS NULL`, e.A.User); n != 0 {
		t.Errorf("%d refresh tokens of ended sessions are still live", n)
	}
	if n := live(e.B.User); n != bLive {
		t.Errorf("tenant B holds %d live sessions, had %d: a trim of A touched B", n, bLive)
	}
}
