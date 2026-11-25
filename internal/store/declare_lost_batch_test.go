package store_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestTOTPDeclareLostBatches is db-r14-1 and db-r15-5. Every other test of the declare-lost path names
// one or two seeds, so the loop that cuts the list into calls and the function's refusal above its
// limit were never run: a loop that did not advance, or a total that dropped the last chunk, would
// have cleared part of a tenant that lost its key and told the operator it was done. 1100 users are
// one call and ONE record (db-r15-5; they were three records of 500, 500 and 100 when a call took
// 500); the same list in calls of 500 shows the loop, the sum and an accurate record per call; and
// the function itself is called with exactly 20000 (accepted) and 20001 (22023).
// one by one, and the function itself is called with exactly 1000 (accepted) and 1001 (22023).
func TestTOTPDeclareLostBatches(t *testing.T) {
	const users = 1100
	f := newFixture(t)
	keytool := f.db.Store(f.ctx, t, store.RoleKeytool)
	super := f.superConn(t)
	// v1 has one owner per tenant (users_one_owner_uq, D32 leaves members open). The scratch copy
	// drops the index to hold many users of one tenant, which is what a tenant with members will be.
	if _, err := super.Exec(f.ctx, "DROP INDEX ctrlz.users_one_owner_uq"); err != nil {
		t.Fatal(err)
	}
	// Header 'C' 'Z', format 1, key number 1, then eight bytes that make every seed distinct, so
	// the "still holds exactly this ciphertext" test of the function is exercised per row.
	if _, err := super.Exec(f.ctx, `
INSERT INTO ctrlz.users (tenant_id, id, phone_e164, password_hash, totp_secret_ct, totp_enabled_at, totp_last_step)
SELECT $1, uuidv7(), '+9891300' || pg_catalog.lpad(g::text, 5, '0'), 'argon2id$seed',
       '\x435a010001'::bytea || pg_catalog.int8send(g::bigint), now(), 4
FROM generate_series(1, $2::int) g`, f.A.Tenant, users-1); err != nil {
		t.Fatal(err)
	}
	// The fixture's own user of A, and B's, are sealed under key 1 as well.
	for _, u := range []uuid.UUID{f.A.User, f.B.User} {
		if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET totp_secret_ct = '\\x435a010001'::bytea || pg_catalog.int8send($2::bigint), totp_enabled_at = now(), totp_last_step = 4 WHERE id = $1",
			u, int64(1<<40)); err != nil {
			t.Fatal(err)
		}
	}
	var seeds []store.TOTPSecret
	rows, err := super.Query(f.ctx, "SELECT id, totp_secret_ct FROM ctrlz.users WHERE tenant_id = $1 ORDER BY id", f.A.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s store.TOTPSecret
		if err := rows.Scan(&s.User, &s.CT); err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, s)
	}
	rows.Close()
	if len(seeds) != users {
		t.Fatalf("planted %d seeds for tenant A, want %d", len(seeds), users)
	}

	var cleared int
	if err := keytool.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		n, err := tx.TOTPDeclareLost(1, seeds)
		cleared = n
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if cleared != users {
		t.Errorf("TOTPDeclareLost reported %d cleared users, want %d", cleared, users)
	}
	var left, enabledB int
	if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND (totp_enabled_at IS NOT NULL OR totp_secret_ct IS NOT NULL)", f.A.Tenant).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d users of tenant A still have a seed after the call", left)
	}
	// The other tenant's user holds a seed under the same key number and is not named.
	if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND totp_enabled_at IS NOT NULL AND totp_secret_ct IS NOT NULL", f.B.Tenant).Scan(&enabledB); err != nil {
		t.Fatal(err)
	}
	if enabledB != 1 {
		t.Errorf("tenant B has %d users with a seed, want its one", enabledB)
	}
	// One declaration is ONE record (db-r15-5): a single notice and a single audit row that says 1100.
	// Before, the caller cut the list into calls of 500 and each wrote its own, so the tenant saw three
	// warnings and an audit export of three events (500, 500, 100) that read as three smaller operations.
	trail := func(tenant uuid.UUID) (users []int, notices int) {
		t.Helper()
		got, err := super.Query(f.ctx, "SELECT (params->>'users')::int FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'totp.declared_lost' ORDER BY id", tenant)
		if err != nil {
			t.Fatal(err)
		}
		for got.Next() {
			var n int
			if err := got.Scan(&n); err != nil {
				t.Fatal(err)
			}
			users = append(users, n)
		}
		got.Close()
		if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'totp_lost'", tenant).Scan(&notices); err != nil {
			t.Fatal(err)
		}
		return users, notices
	}
	if users, notices := trail(f.A.Tenant); len(users) != 1 || users[0] != 1100 || notices != 1 {
		t.Errorf("1100 lost seeds left audit rows %v and %d notices, want one row of 1100 and one notice", users, notices)
	}
	if users, notices := trail(f.B.Tenant); len(users) != 0 || notices != 0 {
		t.Errorf("tenant B has declared-lost rows %v and %d notices", users, notices)
	}

	// A declaration larger than one call still cannot stop half way (the caller's one transaction), and
	// each call's record is accurate: with calls of 500 the same 1100 seeds leave 500, 500 and 100.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.users SET totp_enabled_at = now(), totp_last_step = 4,
	  totp_secret_ct = '\x435a010001'::bytea || pg_catalog.int8send(pg_catalog.hashtextextended(id::text, 0)) WHERE tenant_id = $1`, f.A.Tenant); err != nil {
		t.Fatal(err)
	}
	seeds = seeds[:0]
	rows, err = super.Query(f.ctx, "SELECT id, totp_secret_ct FROM ctrlz.users WHERE tenant_id = $1 ORDER BY id", f.A.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s store.TOTPSecret
		if err := rows.Scan(&s.User, &s.CT); err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, s)
	}
	rows.Close()
	if err := keytool.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		n, err := tx.DeclareLostIn(1, seeds, 500)
		cleared = n
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if cleared != users {
		t.Errorf("a declaration in calls of 500 cleared %d users, want %d", cleared, users)
	}
	if rowsOf, _ := trail(f.A.Tenant); len(rowsOf) != 4 || rowsOf[1] != 500 || rowsOf[2] != 500 || rowsOf[3] != 100 {
		t.Errorf("calls of 500 left audit rows %v, want the first record and then 500, 500, 100", rowsOf)
	}

	// The function's own limit: 20000 names are one call, 20001 are refused with 22023 before anything
	// is touched. They are ids no user has, so a refusal is the limit and not a data error.
	call := func(n int) error {
		ids := make([]uuid.UUID, n)
		cts := make([][]byte, n)
		for i := range ids {
			ids[i], cts[i] = uuid.New(), []byte{0x43, 0x5a, 1, 0, 1}
		}
		return keytool.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			var cleared int
			return tx.DB().QueryRow(tx.Context(), "SELECT ctrlz_fn.keytool_totp_declare_lost($1, $2, $3)", int32(1), ids, cts).Scan(&cleared)
		})
	}
	if err := call(20000); err != nil {
		t.Errorf("20000 seeds in one call: %v", err)
	}
	err = call(20001)
	// WithTenant sanitises the error: the text keeps the SQLSTATE and nothing else.
	if err == nil || !strings.Contains(err.Error(), "SQLSTATE 22023") {
		t.Errorf("20001 seeds in one call: %v, want SQLSTATE 22023", err)
	}
}
