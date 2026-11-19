package store_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestAFullNotifyQueueDoesNotStopACommit is db-r15-1 and db-r15-6. Postgres has one notification queue
// for the whole cluster and no privilege for LISTEN or NOTIFY. A login role that LISTENs and then sits
// inside a transaction keeps the queue from being emptied (the role timeouts do not help: a role can
// set them to 0 itself), a second role sends until the queue is full, and from then on every
// transaction that notified fails at COMMIT with 54000. auth_otp_issue notified for every accepted
// request and the admin outbox insert notified too, so no OTP could be issued and no admin message
// queued, for any tenant, until someone found the session.
//
// The test builds that state in a cluster of its own, with max_notify_queue_pages at its smallest so
// that the queue fills in a moment (the shared cluster cannot be restarted under the other tests),
// proves the premise (a plain pg_notify now fails at commit), and requires the two writes that used to
// notify to commit and leave their rows.
func TestAFullNotifyQueueDoesNotStopACommit(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: container tests skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	c, err := testpg.StartWithArgs(ctx, "-c", "max_notify_queue_pages=64")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Terminate(context.Background())
	db := c.NewDB(ctx, t)
	super, err := db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatal(err)
	}

	// The attacker: a listener stuck inside a transaction, and a sender.
	listener, err := db.Conn(ctx, "ctrlz_hub")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close(context.Background())
	for _, sql := range []string{"LISTEN ctrlz_zz_flood", "SET idle_in_transaction_session_timeout = 0", "BEGIN", "SELECT 1"} {
		if _, err := listener.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	sender, err := db.Conn(ctx, "ctrlz_compiler")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close(context.Background())
	full := false
	for i := 0; i < 5000 && !full; i++ {
		_, err := sender.Exec(ctx, `SELECT pg_catalog.pg_notify('ctrlz_zz_flood', pg_catalog.repeat('a', 7900))`)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "54000" {
			full = true
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if !full {
		t.Fatal("the notification queue never filled: the premise of the test is gone")
	}
	// The premise: a write that notifies now fails at commit, for a role with no part in the flood.
	probe, err := db.Conn(ctx, "ctrlz_tenant")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close(context.Background())
	if _, err := probe.Exec(ctx, `SELECT pg_catalog.pg_notify('ctrlz_sms', '')`); err == nil {
		t.Fatal("a notification was accepted by a full queue: the test proves nothing")
	}

	tenant := db.Store(ctx, t, store.RoleTenant)
	admin := db.Store(ctx, t, store.RoleAdmin)
	ip := netip.MustParseAddr("198.51.100.91")
	for i, ct := range [][]byte{[]byte("sealed"), nil} { // an account's challenge, then a decoy
		r, err := tenant.Auth().OTPIssue(ctx, "+98912111500"+string(rune('1'+i)), "login", []byte{1}, ct, ip, false)
		if err != nil || !r.Allowed {
			t.Fatalf("OTPIssue (real=%v) with a full notification queue: %+v %v", ct != nil, r, err)
		}
	}
	id := uuid.New()
	if err := admin.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		return g.SMSOutboxInsert(store.NewOutbox{ID: id, Kind: "test", Phone: "+989121115009", TemplateKey: "otp", Locale: "fa", ParamsCT: []byte("ct")})
	}); err != nil {
		t.Fatalf("SMSOutboxInsert with a full notification queue: %v", err)
	}
	var n int
	if err := super.QueryRow(ctx, `SELECT (SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 LIKE '+98912111500%') + (SELECT count(*) FROM ctrlz.sms_outbox WHERE id = $1)`, id).Scan(&n); err != nil || n != 3 {
		t.Errorf("the rows of the two writes: %d (%v), want 2 challenges and 1 outbox row", n, err)
	}
}
