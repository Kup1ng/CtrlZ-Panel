package admincli_test

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// TestDeclareLostKeepsTheAuditChainWhenAnotherRowCommitsDuringIt is admin-r22-1 and admin-r22-4. The
// declaration ran at REPEATABLE READ, so the head of the audit chain it read after taking the audit
// lock was the snapshot of its first statement, and a row another writer committed meanwhile gave the
// declaration's rows the same prev_hash: `audit verify` failed for ever. The test holds the gateway
// row so that the declaration waits inside its transaction, commits an unrelated audit row, and lets
// the declaration finish. The chain must still verify and hold no two rows with one prev_hash.
func TestDeclareLostKeepsTheAuditChainWhenAnotherRowCommitsDuringIt(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	plantUnopenable(t, r)

	conn, err := r.env.DB.Super(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(r.env.Ctx)
	if _, err := conn.Exec(r.env.Ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(r.env.Ctx, `SELECT 1 FROM ctrlz.sms_gateways WHERE provider = 'sms_ir' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var code int
	wg.Add(1)
	go func() {
		defer wg.Done()
		code = r.run("keys", "declare-lost", "sms_cred", "--key-number", "1", "--yes")
	}()
	testwait.Until(t, 60*time.Second, "the declaration to reach the discard", func() bool {
		return r.count(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`) != 0
	})

	// Another writer commits an admin audit row (a login, an acknowledgement) inside the declaration's window.
	if err := r.st.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := audit.Admin(g, time.Now(), uuid.Nil, netip.Addr{}, audit.KeyDeclaredLost{Domain: audit.KeyDomainOf("admin_totp"), KeyNumber: 7})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(r.env.Ctx, `COMMIT`); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if code != 0 {
		t.Fatalf("the declaration failed: exit %d %q", code, r.errb.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'sms.gateway_change'`); n != 1 {
		t.Fatalf("%d discard rows, want 1", n)
	}
	if n := r.count(`SELECT count(*) FROM (SELECT prev_hash FROM ctrlz.audit_log GROUP BY prev_hash HAVING count(*) > 1) d`); n != 0 {
		t.Fatalf("%d prev_hash values are shared by two rows: the chain forked", n)
	}
	if c := r.run("audit", "verify"); c != 0 {
		t.Fatalf("audit verify after the declaration: exit %d %q", c, r.errb.String())
	}
}
