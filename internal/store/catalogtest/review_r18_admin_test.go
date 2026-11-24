package catalogtest_test

import (
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestTheKeyToolCanWriteTwoKindsOfAuditRowAndNothingElse is the fault test of admin-r18-6 and -7. The key
// tool's login (ctrlz_keytool) has no grant on audit_log, and its one road to the chain is the definer
// function: it refuses, with NULL and no row, an action that is not key.rekeyed or key.declared_lost, a key
// number outside 1 to 65535, a negative count, and it cannot be asked for another
// domain because the domain is not an argument. The table itself stays closed to the role.
func TestTheKeyToolCanWriteTwoKindsOfAuditRowAndNothingElse(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	conn := h.fresh()
	h.inTx(conn, "keytool", nil, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.audit_log (action, entry_hash) VALUES ('x', '\x00')`); err == nil {
			t.Fatal("the key tool can insert into audit_log")
		}
	})
	h.inTx(conn, "keytool", nil, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, `SELECT count(*) FROM ctrlz.audit_log`); err == nil {
			t.Fatal("the key tool can read audit_log")
		}
	})
	const call = `SELECT ctrlz_fn.keytool_audit_key_event($1, $2, $3, $4, $5)`
	for _, c := range []struct {
		name                                  string
		action                                string
		key, rewritten, changed, failedAmount int
		ok                                    bool
	}{
		{"a rekey", "key.rekeyed", 2, 3, 0, 0, true},
		{"a loss", "key.declared_lost", 2, 0, 0, 0, true},
		{"a login row", "admin.login", 2, 0, 0, 0, false},
		{"a rotation, which is the operator's note", "key.rotated", 2, 0, 0, 0, false},
		{"key number 0", "key.rekeyed", 0, 1, 0, 0, false},
		{"key number 65536", "key.rekeyed", 65536, 1, 0, 0, false},
		{"a negative count", "key.rekeyed", 2, -1, 0, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.inTx(conn, "keytool", nil, func(tx pgx.Tx) {
				var id *int64
				if err := tx.QueryRow(h.ctx, call, c.action, c.key, c.rewritten, c.changed, c.failedAmount).Scan(&id); err != nil {
					t.Fatal(err)
				}
				if (id != nil) != c.ok {
					t.Fatalf("returned %v, want a row: %v", id, c.ok)
				}
			})
		})
	}
}
