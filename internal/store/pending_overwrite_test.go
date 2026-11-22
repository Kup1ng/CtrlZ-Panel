package store_test

import (
	"bytes"
	"testing"

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
		if _, ok, _ := g.SMSGatewayConfirmCredentials("sms_ir", "7731"); ok {
			t.Fatal("a confirmation promoted a discarded pair")
		}
		if ok, err := g.SMSGatewayStageCredentials(id, thief, "7731"); err != nil || !ok {
			t.Fatalf("a stage after the discard: %v %v", ok, err)
		}
	})
}
