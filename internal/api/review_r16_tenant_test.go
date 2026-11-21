package api

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Tests of the P1 auth review, round 16, area "HTTP spine and tenant API".

// TestADecoyWaitsOnTheGlobalCounterLikeARealRequest is tenant-r16-11, without the oracle's walk over every
// route. A real OTP request counts the one global row of the day and so takes its row lock; a decoy used to
// skip the row, so while another session held it a phone with an account waited and a phone without one was
// answered at once, and the wait told them apart. Both must now wait, then both are allowed once the row is
// free. The wait is ended by the test's own deadline, so no sleep decides anything.
func TestADecoyWaitsOnTheGlobalCounterLikeARealRequest(t *testing.T) {
	f := newFrig(t, frigOpts{})
	ctx := f.env.Ctx
	f.env.Exec(t, `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 0) ON CONFLICT (day, scope, key) DO NOTHING`)
	conn, err := f.env.DB.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	if tag, err := conn.Exec(ctx, `UPDATE ctrlz.sms_counters SET count = count WHERE scope = 'global' AND key = 'all'`); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("the global row was not locked: %v %v", tag, err)
	}
	// Two networks: the per-address caps are not what is under test.
	ips := map[string]netip.Addr{"real": netip.MustParseAddr("198.51.100.20"), "decoy": netip.MustParseAddr("203.0.113.20")}
	phones := map[string]string{"real": "+989121110001", "decoy": "+989121110002"}
	cts := map[string][]byte{"real": []byte("sealed"), "decoy": nil}
	for _, kind := range []string{"real", "decoy"} {
		c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		res, err := f.st.Auth().OTPIssue(c, phones[kind], "login", []byte{1}, cts[kind], ips[kind], false)
		cancel()
		if err == nil {
			t.Errorf("a %s request was answered (allowed=%v) while another session held the global counter row: it did not wait for it", kind, res.Allowed)
		}
	}
	if _, err := conn.Exec(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	// A call the client gave up on may still be running on the server (its cancel is a request, not a
	// guarantee); the later counts are read once none is, or they would include its work.
	deadline := time.Now().Add(15 * time.Second)
	for f.count(`SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND query LIKE '%auth_otp_issue%' AND pid <> pg_backend_pid()`) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("a blocked call never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Once the row is free a decoy is allowed and adds NOTHING to it, and a real request adds one.
	global := func() int {
		return f.count(`SELECT count FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all'`)
	}
	before := global()
	for _, c := range []struct {
		kind, phone, ip string
		ct              []byte
		add             int
	}{
		{"decoy", "+989121110012", "203.0.113.30", nil, 0},
		{"real", "+989121110011", "198.51.100.30", []byte("sealed"), 1},
	} {
		res, err := f.st.Auth().OTPIssue(ctx, c.phone, "login", []byte{1}, c.ct, netip.MustParseAddr(c.ip), false)
		if err != nil || !res.Allowed {
			t.Fatalf("a %s request once the row was free: %+v, %v", c.kind, res, err)
		}
		if got := global(); got != before+c.add {
			t.Errorf("after a %s request the global count is %d, want %d", c.kind, got, before+c.add)
		}
		before = global()
	}
}

// TestADecoyFloodDoesNotRefuseARealOTPRequest is tenant-r16-23. Since 0052 every OTP request, a decoy
// included, probes and locks the one global counter row until its own transaction ends, so the rate at
// which OTP requests are served, for every tenant, is the hand-off rate of that one row, shared with decoy
// traffic that adds nothing to the cap and so never meets the global cap. The cost is that of one short
// statement per request (the transaction is the call itself and ends with it), and the number of requests
// that can queue is bounded in front of it by the rate classes of the registry and the gate of the pool,
// not by this row. The test sends a flood of decoys from many networks at once together with real
// requests, and requires that none is refused and the real ones are served well inside lock_timeout: the
// hand-off is fast enough that a decoy flood does not turn into 503 for real senders. The bound is the
// proof; the flood is a count, not a speed.
func TestADecoyFloodDoesNotRefuseARealOTPRequest(t *testing.T) {
	f := newFrig(t, frigOpts{})
	ctx := f.env.Ctx
	const decoys, reals = 150, 5
	type result struct {
		kind    string
		allowed bool
		err     error
		took    time.Duration
	}
	out := make(chan result, decoys+reals)
	var wg sync.WaitGroup
	start := make(chan struct{})
	send := func(kind string, i int, ct []byte) {
		defer wg.Done()
		<-start
		// A network and a phone of its own for each, so the per-address caps are not what refuses.
		ip := netip.AddrFrom4([4]byte{198, byte(20 + i/200), byte(i % 200), 7})
		phone := fmt.Sprintf("+98912%07d", 2000000+i)
		begin := time.Now()
		res, err := f.st.Auth().OTPIssue(ctx, phone, "login", []byte{1}, ct, ip, false)
		out <- result{kind, res.Allowed, err, time.Since(begin)}
	}
	for i := 0; i < decoys; i++ {
		wg.Add(1)
		go send("decoy", i, nil)
	}
	for i := 0; i < reals; i++ {
		wg.Add(1)
		go send("real", decoys+i, []byte("sealed"))
	}
	close(start)
	wg.Wait()
	close(out)
	var slowest time.Duration
	for r := range out {
		if r.err != nil || !r.allowed {
			t.Errorf("a %s request in a flood of %d decoys: allowed=%v, %v", r.kind, decoys, r.allowed, r.err)
		}
		if r.kind == "real" && r.took > slowest {
			slowest = r.took
		}
	}
	// lock_timeout of the role is seconds; a real request queued behind decoys that each hold the row for one
	// short statement is served in a fraction of it.
	if slowest > 10*time.Second {
		t.Errorf("a real request waited %v behind %d decoys", slowest, decoys)
	}
	t.Logf("slowest real request behind %d decoys: %v", decoys, slowest)
}
