package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestARequestHoldsOneConnectionWhateverContextItIsGiven is tenant-r18-8, the runtime half of rule 14. The
// context of a transaction carries a marker, so a call made with it is refused; but a closure built before the
// transaction, a method of a struct that holds a context, or a method value taken outside the callback reaches
// the pool with the OUTER context, which has no marker, while the transaction holds its connection. The request
// scope (store.WithRequestScope, put into the context by the pipeline) is shared by every context derived from
// the request, so the call is refused whatever context it carries. What is judged is the property: every
// single-statement call (read by reflection from the types, like the marker test beside it), WithTenant and
// WithGlobal, each with the outer context, from inside an open transaction.
func TestARequestHoldsOneConnectionWhateverContextItIsGiven(t *testing.T) {
	f := newFixture(t)
	cfg := f.db.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 4
	cfg.AcquireTimeout = 4 * time.Second
	s, err := store.Open(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)

	outer := store.WithRequestScope(f.ctx)
	if !store.InRequestScope(outer) || store.InRequestScope(f.ctx) {
		t.Fatal("WithRequestScope does not mark exactly the context it returns")
	}
	if store.WithRequestScope(outer) != outer {
		t.Error("a second WithRequestScope made a new scope: a count held by a transaction would be reset")
	}

	// call runs every method of a single-statement set with ctx and returns how many answered ErrNested.
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	errType := reflect.TypeOf((*error)(nil)).Elem()
	call := func(calls any, ctx context.Context) (refused, total int) {
		rv := reflect.ValueOf(calls)
		for i := 0; i < rv.NumMethod(); i++ {
			mt := rv.Method(i).Type()
			if mt.NumIn() == 0 || mt.In(0) != ctxType {
				continue
			}
			args := []reflect.Value{reflect.ValueOf(ctx)}
			for j := 1; j < mt.NumIn(); j++ {
				args = append(args, reflect.Zero(mt.In(j)))
			}
			var err error
			for _, o := range rv.Method(i).Call(args) {
				if o.Type() == errType && !o.IsNil() {
					err = o.Interface().(error)
				}
			}
			total++
			if errors.Is(err, store.ErrNested) {
				refused++
			}
		}
		return refused, total
	}

	if err := s.WithTenant(outer, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		// The outer context has no marker. Every single-statement call is still refused.
		if r, n := call(s.Auth(), outer); n < 20 || r != n {
			t.Errorf("with the outer context inside a transaction, %d of %d single-statement calls were refused", r, n)
		}
		// A second transaction on the outer context is refused as well, for both kinds.
		if err := s.WithTenant(outer, f.A.Tenant, store.TxOpts{}, func(store.Tx) error { return nil }); !errors.Is(err, store.ErrNested) {
			t.Errorf("WithTenant on the outer context inside a transaction = %v, want ErrNested", err)
		}
		if err := admin.WithGlobal(outer, store.TxOpts{}, func(store.GlobalTx) error { return nil }); err != nil {
			// A different store has a different pool, but the request is the same: it still holds a connection.
			if !errors.Is(err, store.ErrNested) {
				t.Errorf("WithGlobal on the outer context = %v, want ErrNested", err)
			}
		} else {
			t.Error("WithGlobal on the outer context inside a transaction of the same request ran")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The count is lowered when the transaction ends, however it ends: a commit, a returned error, a panic.
	// One read that does no harm stands for "the pool answers": the zero-argument calls above are safe only
	// while they are refused before any SQL.
	after := func(why string) {
		t.Helper()
		if _, err := s.Auth().PublicConfig(outer); err != nil {
			t.Errorf("after %s the outer context is still refused: %v", why, err)
		}
	}
	after("a commit")
	if err := s.WithTenant(outer, f.A.Tenant, store.TxOpts{}, func(store.Tx) error { return errors.New("later failure") }); err == nil {
		t.Fatal("the failing callback returned nil")
	}
	after("a rollback")
	func() {
		defer func() { _ = recover() }()
		_ = s.WithTenant(outer, f.A.Tenant, store.TxOpts{}, func(store.Tx) error { panic("boom") })
	}()
	after("a panic")
	// A refused nested call must not lower the count of the transaction it was refused in.
	if err := s.WithTenant(outer, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_ = s.WithTenant(outer, f.A.Tenant, store.TxOpts{}, func(store.Tx) error { return nil })
		if r, n := call(s.Auth(), outer); r != n {
			t.Errorf("after a refused nested transaction the request is no longer busy (%d of %d refused)", r, n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A context with no scope (a worker, the console) is not judged by the scope: two requests do not share one.
	other := store.WithRequestScope(f.ctx)
	if err := s.WithTenant(outer, f.A.Tenant, store.TxOpts{}, func(store.Tx) error {
		if _, err := s.Auth().PublicConfig(other); err != nil {
			t.Errorf("another request was refused for the connection of this one: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
