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

// TestADecoyWaitsOnTheGlobalCounterLikeARealRequest is tenant-r16-11, rebuilt for the sharded count
// (db-r18-2). A real OTP request counts one global row of the day and so takes its row lock; a decoy used to
// skip the row, so while another session held it a phone with an account waited and a phone without one
// was answered at once, and the wait told them apart. Since 0055 the count is sixteen shard rows, one chosen
// at random by every request, and every request first takes an advisory lock made of its phone. The test
// holds each of the two things a request can wait for, in a second session, and requires that a real
// request and a decoy both wait for it, and that both are allowed once it is free. The wait is ended by the
// test's own deadline, so no sleep decides anything.
func TestADecoyWaitsOnTheGlobalCounterLikeARealRequest(t *testing.T) {
	f := newFrig(t, frigOpts{})
	ctx := f.env.Ctx
	const today = "(now() AT TIME ZONE 'Asia/Tehran')::date"
	// Every shard row exists first (it does from the first request of a day), so a lock is a row lock and
	// not an uncommitted insert.
	f.env.Exec(t, `INSERT INTO ctrlz.sms_counters (day, scope, key, count)
SELECT `+today+`, 'global', k, 0 FROM unnest(ARRAY['all'] || ARRAY(SELECT 'all:' || n FROM generate_series(1, 15) n)) AS k
ON CONFLICT (day, scope, key) DO NOTHING`)
	ips := map[string]netip.Addr{"real": netip.MustParseAddr("198.51.100.20"), "decoy": netip.MustParseAddr("203.0.113.20")}
	cts := map[string][]byte{"real": []byte("sealed"), "decoy": nil}
	global := func() int {
		return f.count(`SELECT COALESCE(sum(count), 0) FROM ctrlz.sms_counters WHERE scope = 'global' AND (key = 'all' OR key LIKE 'all:%')`)
	}
	for i, c := range []struct {
		name string
		hold func(phone string) string
	}{
		{"every shard of the global count", func(string) string {
			return `UPDATE ctrlz.sms_counters SET count = count WHERE scope = 'global' AND (key = 'all' OR key LIKE 'all:%')`
		}},
		{"the phone's advisory lock", func(phone string) string {
			return `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.otp_issue:` + phone + `', 0))`
		}},
	} {
		name, hold := c.name, c.hold
		// Each case has phones and networks of its own: a decoy leaves a challenge row, and the cooldown of the
		// next case would refuse the same phone.
		phones := map[string]string{"real": fmt.Sprintf("+98912111%04d", 1000*i+1), "decoy": fmt.Sprintf("+98912111%04d", 1000*i+2)}
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{"real", "decoy"} {
				conn, err := f.env.DB.Super(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Exec(ctx, hold(phones[kind])); err != nil {
					t.Fatalf("%s was not held: %v", name, err)
				}
				// Two networks: the per-address caps are not what is under test.
				c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
				res, err := f.st.Auth().OTPIssue(c, phones[kind], "login", []byte{1}, cts[kind], ips[kind], false)
				cancel()
				if err == nil {
					t.Errorf("a %s request was answered (allowed=%v) while another session held %s: it did not wait for it", kind, res.Allowed, name)
				}
				if _, err := conn.Exec(ctx, `ROLLBACK`); err != nil {
					t.Fatal(err)
				}
				conn.Close(ctx)
				// A call the client gave up on may still be running on the server (its cancel is a request, not a
				// guarantee); the later counts are read once none is, or they would include its work.
				deadline := time.Now().Add(15 * time.Second)
				for f.count(`SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND query LIKE '%auth_otp_issue%' AND pid <> pg_backend_pid()`) > 0 {
					if time.Now().After(deadline) {
						t.Fatal("a blocked call never finished")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			// Once it is free a decoy is allowed and adds NOTHING to the count, and a real request adds one.
			before := global()
			for _, c := range []struct {
				kind, phone, ip string
				ct              []byte
				add             int
			}{
				{"decoy", fmt.Sprintf("+98912111%04d", 1000*i+12), fmt.Sprintf("203.0.113.%d", 30+i), nil, 0},
				{"real", fmt.Sprintf("+98912111%04d", 1000*i+11), fmt.Sprintf("198.51.100.%d", 30+i), []byte("sealed"), 1},
			} {
				res, err := f.st.Auth().OTPIssue(ctx, c.phone, "login", []byte{1}, c.ct, netip.MustParseAddr(c.ip), false)
				if err != nil || !res.Allowed {
					t.Fatalf("a %s request once %s was free: %+v, %v", c.kind, name, res, err)
				}
				if got := global(); got != before+c.add {
					t.Errorf("after a %s request the global count is %d, want %d", c.kind, got, before+c.add)
				}
				before = global()
			}
		})
	}
}

// TestADecoyFloodDoesNotRefuseARealOTPRequest is tenant-r16-23 and, since 0055, db-r18-2. From 0052 every OTP
// request, a decoy included, probed and locked the one global counter row until its own transaction ended, so
// the rate at which OTP requests were served, for every tenant, was the hand-off rate of that one row, shared
// with decoy traffic that adds nothing to the cap and so never meets the global cap. The count is sixteen
// shard rows now, one chosen at random by each request, and the only thing requests for different phones
// share is a shard. The cost is that of one short
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
