package store_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestAPendingPairIsNotReplacedByAnotherPut is db-r19-2. The console confirms by a hint the stager
// chooses, so a second PUT that replaced the owner's pending pair under an equal hint would be promoted
// by the confirmation the owner typed for their own. The second stage must change nothing and say so;
// the console's discard frees the gateway, and a confirmation then promotes the pair that was staged
// last and nothing else.
func TestAPendingPairIsNotReplacedByAnotherPut(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleAdmin)
	owner, thief := []byte("sealed-owner"), []byte("sealed-thief")
	super := f.superConn(t)
	pending := func(id uuid.UUID) []byte {
		t.Helper()
		var ct []byte
		if err := super.QueryRow(f.ctx, `SELECT credentials_pending_ct FROM ctrlz.sms_gateways WHERE id = $1`, id).Scan(&ct); err != nil {
			t.Fatal(err)
		}
		return ct
	}
	var id uuid.UUID
	f.global(t, s, func(g store.GlobalTx) {
		var err error
		if id, err = g.SMSGatewayEnsure(uuid.New(), "sms_ir"); err != nil {
			t.Fatal(err)
		}
	})
	f.global(t, s, func(g store.GlobalTx) {
		if ok, err := g.SMSGatewayStageCredentials(id, owner, "7731"); err != nil || !ok {
			t.Fatalf("the first stage: %v %v", ok, err)
		}
	})
	f.global(t, s, func(g store.GlobalTx) {
		if ok, err := g.SMSGatewayStageCredentials(id, thief, "7731"); err != nil || ok {
			t.Fatalf("a second stage over a pending pair: ok %v, err %v", ok, err)
		}
	})
	f.global(t, s, func(g store.GlobalTx) {
		if got := pending(id); !bytes.Equal(got, owner) {
			t.Fatal("a second stage replaced the owner's pending pair")
		}
		if _, ok, err := g.SMSGatewayDiscardPending("melipayamak"); err != nil || ok {
			t.Fatalf("a discard of a gateway with nothing pending: ok %v err %v", ok, err)
		}
		if _, ok, err := g.SMSGatewayDiscardPending("sms_ir"); err != nil || !ok {
			t.Fatalf("discard: ok %v err %v", ok, err)
		}
	})
	f.global(t, s, func(g store.GlobalTx) {
		if got := pending(id); got != nil {
			t.Fatal("discard left the pair")
		}
		if _, ok, _ := g.SMSGatewayConfirmCredentials("sms_ir", "7731", store.SMSCredentialsFingerprint(owner)); ok {
			t.Fatal("a confirmation promoted a discarded pair")
		}
		if ok, err := g.SMSGatewayStageCredentials(id, thief, "7731"); err != nil || !ok {
			t.Fatalf("a stage after the discard: %v %v", ok, err)
		}
	})
}

// TestTwoStagesAtOnceLeaveExactlyOneWinner is db-r20-1. The guard is one statement
// (`... AND credentials_pending_ct IS NULL`): under Read Committed the second writer waits on the row
// lock and re-reads the predicate once the first commits. A guard later split into a read and a write
// would let both through, and the sequential test above cannot see that. The first stager holds its
// transaction open after staging, the second starts while the row is locked, and only then does the
// first commit: the second must find the pair pending and change nothing.
func TestTwoStagesAtOnceLeaveExactlyOneWinner(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleAdmin)
	var id uuid.UUID
	f.global(t, s, func(g store.GlobalTx) {
		var err error
		if id, err = g.SMSGatewayEnsure(uuid.New(), "sms_ir"); err != nil {
			t.Fatal(err)
		}
	})

	staged, release := make(chan struct{}), make(chan struct{})
	first := make(chan bool, 1)
	go func() {
		var ok bool
		err := s.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			var err error
			if ok, err = g.SMSGatewayStageCredentials(id, []byte("sealed-first"), "1111"); err != nil {
				return err
			}
			close(staged)
			<-release
			return nil
		})
		if err != nil {
			t.Error(err)
		}
		first <- ok
	}()
	<-staged
	second := make(chan bool, 1)
	go func() {
		var ok bool
		err := s.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			var err error
			ok, err = g.SMSGatewayStageCredentials(id, []byte("sealed-second"), "2222")
			return err
		})
		if err != nil {
			t.Error(err)
		}
		second <- ok
	}()
	// The second statement is blocked on the first's row lock; give it time to get there so that the
	// order under test (a write that waited, then re-read the predicate) is the one that runs.
	select {
	case <-second:
		t.Fatal("the second stage did not wait for the first transaction's row lock")
	case <-time.After(1 * time.Second):
	}
	close(release)
	if ok := <-first; !ok {
		t.Fatal("the first stage was refused")
	}
	if ok := <-second; ok {
		t.Fatal("both of two concurrent stages reported that they staged")
	}
	var ct []byte
	var hint string
	if err := f.superConn(t).QueryRow(f.ctx, `SELECT credentials_pending_ct, pending_hint FROM ctrlz.sms_gateways WHERE id = $1`, id).Scan(&ct, &hint); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, []byte("sealed-first")) || hint != "1111" {
		t.Fatal("the pending pair is not the first stager's")
	}
}
