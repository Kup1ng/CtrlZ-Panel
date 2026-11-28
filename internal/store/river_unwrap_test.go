package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/riverpoll"
)

// fakeTx is a pgx.Tx that is never called: only its identity matters to UnwrapTx. The test lives here and not in
// internal/riverpoll because only the store may import pgx (lint TestPgxOnlyWhereItBelongs).
type fakeTx struct{ pgx.Tx }

// River's Driver.UnwrapTx asserts its own concrete executor type, so a wrapped executor must be unwrapped first: this is the
// panic the review of round 1 (RN-r1-3) named, and it holds for a transaction that was wrapped twice by Begin as well. The
// last two checks go through riverpoll.Driver, the driver River is given, which must do the unwrapping itself.
func TestUnwrapGivesRiverItsOwnExecutor(t *testing.T) {
	river := riverpgxv5.New(nil)
	tx := &fakeTx{}
	own := river.UnwrapExecutor(tx)

	wrapped := riverpoll.ExecutorTx(own)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("River's UnwrapTx took a wrapped executor: the premise of riverpoll.Unwrap no longer holds")
			}
		}()
		river.UnwrapTx(wrapped)
	}()

	if got := river.UnwrapTx(riverpoll.Unwrap(wrapped)); got != pgx.Tx(tx) {
		t.Fatalf("UnwrapTx of an unwrapped executor returned another transaction: %v", got)
	}
	if got := river.UnwrapTx(riverpoll.Unwrap(own)); got != pgx.Tx(tx) {
		t.Fatalf("Unwrap changed an executor that was not wrapped: %v", got)
	}

	drv := riverpoll.NewDriver[pgx.Tx](river)
	if got := drv.UnwrapTx(drv.UnwrapExecutor(tx)); got != pgx.Tx(tx) {
		t.Fatalf("the poll driver did not give back the transaction it wrapped: %v", got)
	}
	if drv.SupportsListener() || drv.SupportsListenNotify() {
		t.Fatal("the poll driver says it can listen or notify")
	}
}
