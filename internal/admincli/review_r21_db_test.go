package admincli_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDeclareLostDoesNotDiscardAPairThatChangedAfterItWasJudged is db-r21-2. The declaration judges
// a pending pair stranded, and the discard names a provider and not the ciphertext it judged. Between
// the two, another console session discards that pair and a PUT stages a valid one. The test holds the
// gateway row, lets the declaration reach its discard, and swaps the pair under it; the declaration
// must then write nothing and leave the new pair, as a rerun will judge it.
func TestDeclareLostDoesNotDiscardAPairThatChangedAfterItWasJudged(t *testing.T) {
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

	// The declaration has read the pair and waits for the row the discard updates.
	deadline := time.Now().Add(60 * time.Second)
	for r.count(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the declaration never reached the discard")
		}
		time.Sleep(50 * time.Millisecond)
	}
	newer := []byte("a-valid-pair-staged-in-between")
	if _, err := conn.Exec(r.env.Ctx, `UPDATE ctrlz.sms_gateways SET credentials_pending_ct = $1, pending_hint = '4444' WHERE provider = 'sms_ir'`, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(r.env.Ctx, `COMMIT`); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if code == 0 || !strings.Contains(r.errb.String(), "run the command again") {
		t.Fatalf("the declaration went through over a pair it had not judged: exit %d, %q", code, r.errb.String())
	}
	var ct []byte
	r.env.Scan(t, `SELECT credentials_pending_ct FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &ct)
	if !bytes.Equal(ct, newer) {
		t.Fatal("the declaration discarded the pair that was staged after it judged the old one")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action IN ('sms.gateway_change', 'key.declared_lost')`); n != 0 {
		t.Fatalf("%d audit rows were written by a declaration that changed nothing", n)
	}
}
