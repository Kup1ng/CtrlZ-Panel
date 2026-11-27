package riverpoll_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/riverpoll"
)

// fakeTx is a pgx.Tx that is never called: only its identity matters to UnwrapTx.
type fakeTx struct{ pgx.Tx }

// River's Driver.UnwrapTx asserts its own concrete executor type, so a wrapped executor must be unwrapped first: this is the
// panic the review of round 1 (RN-r1-3) named, and it holds for a transaction that was wrapped twice by Begin as well.
func TestUnwrapGivesRiverItsOwnExecutor(t *testing.T) {
	driver := riverpgxv5.New(nil)
	tx := &fakeTx{}
	own := driver.UnwrapExecutor(tx)

	wrapped := riverpoll.ExecutorTx(own)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("River's UnwrapTx took a wrapped executor: the premise of riverpoll.Unwrap no longer holds")
			}
		}()
		driver.UnwrapTx(wrapped)
	}()

	if got := driver.UnwrapTx(riverpoll.Unwrap(wrapped)); got != pgx.Tx(tx) {
		t.Fatalf("UnwrapTx of an unwrapped executor returned another transaction: %v", got)
	}
	if got := driver.UnwrapTx(riverpoll.Unwrap(own)); got != pgx.Tx(tx) {
		t.Fatalf("Unwrap changed an executor that was not wrapped: %v", got)
	}
}
