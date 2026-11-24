package lint_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// The cost of the keyspace sweep to the limiter on a host whose clock is slow (the diagnosis of the Valkey
// sweep, P1 auth review round 20). The old loop swept 2000 keys in one script, about 10,000 redis.call, and
// then slept a fixed two seconds: on a VM whose clock read traps (150 us a call) one batch held every client for
// one to two seconds, 53 to 94 percent of the limiter's calls ran past its 250 ms timeout, and the limiter,
// which marks the backend down for three seconds after a failed call, made the SMS classes (the ones that fail
// closed) answer 503 while a flood filled a zone to its budget. Nothing in the older tests looked at the
// limiter's side of a sweep, only at what the sweep deleted. This one does: it runs the real maintain.sh and
// sweep.lua over a full zone while a limiter-shaped load runs against the same server, and measures what the
// load saw and what the sweep spent.

// sweepSHA is the digest Valkey gives deploy/compose/valkey/sweep.lua, the name its batches carry in SLOWLOG.
func sweepSHA(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "sweep.lua"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(b) //nolint:gosec // the digest is the name Valkey gives a script
	return hex.EncodeToString(sum[:])
}

// slowEntry is one SLOWLOG entry of a sweep batch.
type slowEntry struct {
	id     int64
	at     int64 // unix seconds when it started
	micros int64
	cursor string
	batch  int
}

// sweepEntries reads the sweep's batches from SLOWLOG, oldest first. The server logs every command
// (slowlog-log-slower-than 0, set by the test), so a batch is never missing for being fast.
func sweepEntries(ctx context.Context, t *testing.T, c valkey.Client, sha string) []slowEntry {
	t.Helper()
	rows, err := c.Do(ctx, c.B().Arbitrary("SLOWLOG", "GET").Args("100000").Build()).ToArray()
	if err != nil {
		t.Fatalf("SLOWLOG GET: %v", err)
	}
	var out []slowEntry
	for _, row := range rows {
		f, err := row.ToArray()
		if err != nil || len(f) < 4 {
			continue
		}
		args, err := f[3].AsStrSlice()
		if err != nil || len(args) < 7 || !strings.EqualFold(args[0], "evalsha") || args[1] != sha {
			continue
		}
		id, _ := f[0].AsInt64()
		at, _ := f[1].AsInt64()
		us, _ := f[2].AsInt64()
		batch, _ := strconv.Atoi(args[6])
		out = append(out, slowEntry{id: id, at: at, micros: us, cursor: args[3], batch: batch})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// aliveAge is how old the loop's heartbeat is, measured inside the container so that the clock of the host
// is not part of it.
func aliveAge(name string) (int, error) {
	out, err := deploy.Docker(context.Background(), "exec", name, "sh", "-c", `echo $(( $(date +%s) - $(stat -c %Y /tmp/valkey-alive) ))`).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("%v: %s", err, out)
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// loadResult is what the limiter-shaped load saw.
type loadResult struct {
	slots, timeouts, missed, busy, other int
	firstOther                           string
	latencies                            []time.Duration // of the calls that came back
	timeoutAt                            []time.Duration // offsets from the start of the window
}

// runLoad drives EVALSHA of take.lua at `rate` calls per second in all, spread over the clients, for `window`,
// OPEN LOOP: each client has a slot every 1/(rate/clients) seconds whether or not its last call came back, a
// call that is not back within the limiter's own 250 ms (ratelimit.Config.Timeout) is a timeout, and a slot
// that passed while the client was still waiting is a missed slot and counts as a timeout as well, so a server
// that stalls for a second is not rewarded with fewer calls to fail. (A closed loop does exactly that: it asks
// less while the server is slow, which is how a load test reports a stall as a handful of slow calls.)
func runLoad(clients []valkey.Client, sha string, rate int, window time.Duration) loadResult {
	perClient := rate / len(clients)
	period := time.Second / time.Duration(perClient)
	total := int(window / period)
	var mu sync.Mutex
	var res loadResult
	var wg sync.WaitGroup
	start := time.Now()
	for w, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("ctrlz:rl:api:otp-send:load-%d", w)
			var timeouts, missed, busy, other int
			var firstOther string
			var lats, tAt []time.Duration
			next := 0
			for next < total {
				cur := int(time.Since(start) / period)
				if cur > next {
					missed += min(cur, total) - next
					next = cur
				}
				if next >= total {
					break
				}
				// Until the slot is due: a wait on a condition, every millisecond (testwait is the one place a test waits).
				slotAt := start.Add(time.Duration(next) * period)
				// The slot is at most one period away, so the wait cannot run out; if it does the slot is counted as missed.
				if !testwait.Holds(2*period, time.Millisecond, func() bool { return !time.Now().Before(slotAt) }) {
					missed++
					next++
					continue
				}
				cctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
				t0 := time.Now()
				err := c.Do(cctx, c.B().Evalsha().Sha1(sha).Numkeys(1).Key(key).Arg("100000", "3600000").Build()).Error()
				cancel()
				if err == nil {
					lats = append(lats, time.Since(t0))
				}
				switch {
				case err == nil:
				case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded"):
					timeouts++
					tAt = append(tAt, t0.Sub(start))
				case strings.Contains(err.Error(), "BUSY"):
					busy++
				default:
					other++
					if firstOther == "" {
						firstOther = err.Error()
					}
				}
				next++
			}
			mu.Lock()
			res.timeouts += timeouts
			res.latencies = append(res.latencies, lats...)
			res.timeoutAt = append(res.timeoutAt, tAt...)
			res.missed += missed
			res.busy += busy
			res.other += other
			if res.firstOther == "" {
				res.firstOther = firstOther
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	res.slots = total * len(clients)
	return res
}

// callCostScript is 10,000 PTTL of a key that does not exist: a redis.call that does nothing else, in a loop.
const callCostScript = "local n = 0 for i = 1, 10000 do n = n + redis.call('PTTL', 'ctrlz:cal') end return n"

// callCostMicros is what one redis.call costs inside a script on this host: 10,000 PTTL of a missing key in
// one EVAL, the median of three runs, divided by 10,000. It is the unit the bounds of the test are scaled by:
// about 1 us on an ordinary Linux host and about 150 on the Hyper-V host the suite runs on, where the clock
// read of a script traps. (The server and the host the test runs on are the same machine, so it is the cost of
// the very calls the sweep makes.)
func callCostMicros(ctx context.Context, t *testing.T, c valkey.Client) float64 {
	t.Helper()
	var runs []time.Duration
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		if err := c.Do(ctx, c.B().Eval().Script(callCostScript).Numkeys(0).Build()).Error(); err != nil {
			t.Fatalf("calibration script: %v", err)
		}
		runs = append(runs, time.Since(t0))
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i] < runs[j] })
	return float64(runs[1].Microseconds()) / 10000
}

// TestValkeySweepKeepsLimiterCallsOnTime fills one zone to over its key budget with keys written by the
// limiter's own script, runs the container's maintenance loop at its default interval, and drives the limiter's
// call rate against the same server for a minute. The sweep may cost the limiter no BUSY, almost no timeouts
// and a bounded share of the server's time, a batch may not be longer than the host's call cost allows, a heartbeat
// must stay fresh through a pass that lasts minutes, and the keys over the budget and a key of a foreign prefix
// must still go within two passes.
//
// Not the real start file: the server is the one the loop tests use (a user that may EVAL, which the
// calibration needs, and one that may write a key of another prefix, which a service user may not), started with
// the memory, append-only and busy settings of valkey.conf. maintain.sh, sweep.lua and the limiter's scripts
// are the files of the Compose file.
func TestValkeySweepKeepsLimiterCallsOnTime(t *testing.T) {
	const (
		fill     = 42000 // over the budget of 40,000 by 2,000
		rate     = 100
		clients  = 8
		window   = 60 * time.Second
		budget   = 40000
		foreign  = "ctrlz:rl:foreign:leftover"
		passCap  = 2
		aliveMax = 60
	)
	if maxKeys := luaConst(t, "sweep.lua", "MAX_KEYS"); maxKeys != budget {
		t.Fatalf("sweep.lua budget is %d, this test fills against %d", maxKeys, budget)
	}
	name, addr := maintainedValkeyEvery(t, "", false,
		"--maxmemory 64mb --maxmemory-policy noeviction --appendonly yes --appendfsync everysec --dir /data --busy-reply-threshold 2000", "")
	waitHealthy(t, name, maintMarker)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Minute)
	defer cancel()
	// A second server of the same make whose loop never sweeps anything (its interval is an hour and its keyspace
	// is empty), given the same load at the same time. The 5 percent the spec allows the limiter is what the
	// SWEEP costs it, and on this machine a window of a minute also holds stalls that have nothing to do with the
	// sweep (a VM shared with other runs, a port forward from Windows): the control is what those cost, and the
	// sweep is held to what it costs beyond that.
	ctlName, ctlAddr := maintainedValkeyEvery(t, "", false,
		"--maxmemory 64mb --maxmemory-policy noeviction --appendonly yes --appendfsync everysec --dir /data --busy-reply-threshold 2000", "3600")
	waitHealthy(t, ctlName, maintMarker)
	newClientAt := func(addr string) valkey.Client {
		c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Username: "loop", Password: "x", DisableCache: true})
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		t.Cleanup(c.Close)
		return c
	}
	newClient := func() valkey.Client { return newClientAt(addr) }
	admin := newClient()
	takeSHA, sweepDigest := luaSHA(t, "take.lua"), sweepSHA(t)

	cal := callCostMicros(ctx, t, admin)
	t.Logf("calibration: one redis.call in a script costs %.1f us here (10,000 PTTL in one EVAL)", cal)

	// Keys exactly as the limiter writes them, by its own script: a two-field hash with a lifetime of twice the
	// period (here 30 minutes, long enough for the whole test and short enough that a container a killed run
	// leaves behind empties itself), in batches pipelined over one connection.
	for from := 0; from < fill; from += 1000 {
		cmds := make(valkey.Commands, 0, 1000)
		for i := from; i < min(from+1000, fill); i++ {
			cmds = append(cmds, admin.B().Evalsha().Sha1(takeSHA).Numkeys(1).Key(fmt.Sprintf("ctrlz:rl:api:otp-send:fill-%d", i)).Arg("5", "900000").Build())
		}
		for _, r := range admin.DoMulti(ctx, cmds...) {
			if err := r.Error(); err != nil {
				t.Fatalf("filling the zone with the limiter's script: %v", err)
			}
		}
	}
	if err := admin.Do(ctx, admin.B().Set().Key(foreign).Value("1").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if err := admin.Do(ctx, admin.B().Pexpire().Key(foreign).Milliseconds(900000).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if err := admin.Do(ctx, admin.B().Arbitrary("CONFIG", "SET").Args("slowlog-log-slower-than", "500", "slowlog-max-len", "100000").Build()).Error(); err != nil {
		t.Fatalf("CONFIG SET slowlog: %v", err)
	}
	if err := admin.Do(ctx, admin.B().Arbitrary("CONFIG", "SET").Args("latency-monitor-threshold", "20").Build()).Error(); err != nil {
		t.Fatalf("CONFIG SET latency: %v", err)
	}
	if err := admin.Do(ctx, admin.B().Arbitrary("SLOWLOG", "RESET").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	filledAt := time.Now()
	size, _ := admin.Do(ctx, admin.B().Dbsize().Build()).AsInt64()
	t.Logf("the zone holds %d keys (budget %d); the loop's own log so far:\n%s", size, budget, logsOf(name))

	// The heartbeat, sampled from inside the container every few seconds for the rest of the test.
	var maxAge int
	var ageMu sync.Mutex
	sampleAge := func() {
		age, err := aliveAge(name)
		if err != nil {
			// One failed `docker exec` on a loaded machine is not a stale heartbeat: ask once more before failing.
			age, err = aliveAge(name)
		}
		if err != nil {
			t.Errorf("reading the heartbeat: %v", err)
			return
		}
		ageMu.Lock()
		maxAge = max(maxAge, age)
		ageMu.Unlock()
	}
	stopSampling := make(chan struct{})
	var sampling sync.WaitGroup
	sampling.Add(1)
	go func() {
		defer sampling.Done()
		for {
			sampleAge()
			if _, stop := testwait.TryReceive(stopSampling, 5*time.Second); stop {
				return
			}
		}
	}()

	// Stopped inline once the keys are gone, and by Cleanup when a Fatal comes first: the sampler reports with
	// t.Errorf, which panics once the test has ended.
	stopSampler := sync.OnceFunc(func() {
		close(stopSampling)
		sampling.Wait()
	})
	t.Cleanup(stopSampler)

	lc := make([]valkey.Client, clients)
	for i := range lc {
		lc[i] = newClient()
	}
	cc := make([]valkey.Client, clients)
	for i := range cc {
		cc[i] = newClientAt(ctlAddr)
	}
	// The keys over the budget and the foreign key are watched from here on, beside the load and not only after it: on a
	// host where a pass takes seconds they are gone long before the window ends, and the passes are counted against the
	// moment they went. DBSIZE and EXISTS are constant time, so the watcher costs the load nothing worth measuring.
	type goneResult struct {
		at time.Time
		ok bool
	}
	goneCh := make(chan goneResult, 1)
	go func() {
		var at time.Time
		ok := testwait.Holds(40*time.Minute, time.Second, func() bool {
			n, err := admin.Do(ctx, admin.B().Dbsize().Build()).AsInt64()
			if err != nil {
				return false
			}
			ex, _ := admin.Do(ctx, admin.B().Exists().Key(foreign).Build()).AsInt64()
			if n <= budget && ex == 0 {
				at = time.Now()
				return true
			}
			return false
		})
		goneCh <- goneResult{at, ok}
	}()

	windowStart := time.Now()
	var ctl loadResult
	ctlDone := make(chan struct{})
	go func() {
		defer close(ctlDone)
		ctl = runLoad(cc, takeSHA, rate, window)
	}()
	res := runLoad(lc, takeSHA, rate, window)
	windowEnd := time.Now()
	<-ctlDone

	// The watcher that started before the window has the answer, or is still waiting on a slow host.
	watched := <-goneCh
	gone, goneAt := watched.ok, watched.at
	if !gone {
		t.Errorf("the keys over the budget or the foreign key are still there after 40 minutes; log:\n%s", logsOf(name))
	}
	stopSampler()

	entries := sweepEntries(ctx, t, admin, sweepDigest)
	if len(entries) == 0 {
		t.Fatal("no sweep batch in SLOWLOG: the loop never swept")
	}

	// What the load saw.
	timeouts := res.timeouts + res.missed
	share := float64(timeouts) / float64(res.slots)
	ctlShare := float64(ctl.timeouts+ctl.missed) / float64(ctl.slots)
	t.Logf("load: %d slots, %d timeouts and %d missed slots (%.2f%%), %d BUSY, %d other errors; the control server with no sweep: %d and %d (%.2f%%)",
		res.slots, res.timeouts, res.missed, 100*share, res.busy, res.other, ctl.timeouts, ctl.missed, 100*ctlShare)
	t.Logf("latency of the calls that came back (this server / control): p50 %v / %v, p99 %v / %v, max %v / %v",
		pct(res.latencies, 50), pct(ctl.latencies, 50), pct(res.latencies, 99), pct(ctl.latencies, 99), pct(res.latencies, 100), pct(ctl.latencies, 100))
	if res.busy != 0 || ctl.busy != 0 {
		t.Errorf("%d limiter calls answered BUSY", res.busy+ctl.busy)
	}
	if res.other != 0 {
		t.Errorf("%d limiter calls failed for a reason other than a timeout or BUSY, the first: %s", res.other, res.firstOther)
	}
	if share-ctlShare > 0.05 {
		t.Errorf("%.1f%% of the limiter's slots timed out or were missed (%d of %d) against %.1f%% on a server that sweeps nothing: the sweep costs more than 5%% of the calls",
			100*share, timeouts, res.slots, 100*ctlShare)
	}

	// What the sweep spent. The longest batch is bounded by what the loop starts with, a batch of the default 200
	// keys, which costs about five calls a key and a SCAN, with half as much again and 50 ms of slack: after
	// the first batch the size follows the time, so no later batch is longer.
	var longest, inWindow int64
	var sizes []int
	var batchMicros []int64
	passStarts := 0
	var startsAfterFill []time.Time
	for _, e := range entries {
		longest = max(longest, e.micros)
		batchMicros = append(batchMicros, e.micros)
		sizes = append(sizes, e.batch)
		if e.at >= windowStart.Unix() && e.at <= windowEnd.Unix() {
			inWindow += e.micros
		}
		if e.cursor == "0" {
			passStarts++
			if time.Unix(e.at, 0).After(filledAt.Add(-time.Second)) {
				startsAfterFill = append(startsAfterFill, time.Unix(e.at, 0))
			}
		}
	}
	bound := time.Duration(200*6*cal*1.5)*time.Microsecond + 50*time.Millisecond
	t.Logf("sweep: %d batches in %d passes since the fill; batch sizes %v (first 12); longest batch %.1f ms (bound %v)",
		len(entries), passStarts, sizes[:min(12, len(sizes))], float64(longest)/1000, bound)
	// The bound is held by the 99th percentile and not by the single longest batch: SLOWLOG times a batch on the
	// wall, so one batch that the VM deschedules in the middle (238 ms against a typical 60 to 110 in a full run of the
	// package, with the loop having measured 100 ms of CPU for it) says something about the host and not about the
	// sweep. A sweep that sizes its batches wrongly is long in many of them (the first version of the timing, which
	// read a frozen clock, ran every batch at 500 keys and 135 batches took 350 ms), which the percentile sees. What
	// the limiter lost to the batches is asserted above, against the control server, call by call.
	sort.Slice(batchMicros, func(i, j int) bool { return batchMicros[i] < batchMicros[j] })
	p99 := batchMicros[min(len(batchMicros)-1, len(batchMicros)*99/100)]
	t.Logf("batch length: p99 %.1f ms, longest %.1f ms", float64(p99)/1000, float64(longest)/1000)
	if time.Duration(p99)*time.Microsecond > bound {
		t.Errorf("the 99th percentile of the sweep batches is %.1f ms, over %v (200 keys at %.1f us a call): a batch holds every client for its whole length", float64(p99)/1000, bound, cal)
	}
	duty := float64(inWindow) / float64(windowEnd.Sub(windowStart).Microseconds())
	t.Logf("duty cycle: the sweep spent %.1f%% of the %v window inside its batches", 100*duty, window)
	// The loop sleeps four times the CPU time a batch reports (os.clock), so its ceiling is 20% of the window in CPU
	// time; SLOWLOG counts the wall time of a batch, which on a VM that deschedules the guest can be up to twice
	// the CPU time (a 238 ms batch measured as 100 ms of CPU in a full run). 35% still fails a loop that does not
	// pause (about 100%) or paces by too little, and does not fail on the host's own stalls.
	if duty > 0.35 {
		t.Errorf("the sweep spent %.1f%% of the window inside batches, want at most 35%%", 100*duty)
	}

	// The heartbeat.
	ageMu.Lock()
	t.Logf("heartbeat: never older than %d s", maxAge)
	if maxAge >= aliveMax {
		t.Errorf("the heartbeat was %d s old at its oldest, want under %d s: a long paced pass looks unhealthy", maxAge, aliveMax)
	}
	ageMu.Unlock()

	// The deletions, in passes: the pass that was running when the fill finished may have missed some keys, the
	// next saw all of them. So the keys must be gone by the time the second pass after the fill has started.
	if gone {
		startsBeforeGone := 0
		for _, s := range startsAfterFill {
			if !s.After(goneAt) {
				startsBeforeGone++
			}
		}
		t.Logf("deletion: the keys over the budget and the foreign key were gone %v after the fill, %d passes had started since", goneAt.Sub(filledAt).Round(time.Second), startsBeforeGone)
		if startsBeforeGone > passCap {
			t.Errorf("%d passes started before the keys over the budget were gone, want at most %d", startsBeforeGone, passCap)
		}
	}
	// One pass at this size: the time between two starts, less the gap, and the batches in between.
	if len(startsAfterFill) >= 2 {
		t.Logf("pass: %v from one pass start to the next at %d keys", startsAfterFill[1].Sub(startsAfterFill[0]), budget)
	}
	t.Logf("the loop's own log:\n%s", logsOf(name))
}

// hostCallCost is callCostMicros measured once for the process, on a server of its own, for the tests whose
// waits depend on how long a sweep pass takes on this host (sweepPassBudget). A function value made once and
// not a variable that a test writes: the first test to ask pays for the container, the others read the answer.
var hostCallCost = sync.OnceValues(calibrateHost)

func calibrateHost() (float64, error) {
	deploy.RemoveStaleTestContainers()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	name := fmt.Sprintf("ctrlz-valkey-cal-%016x", rand.Uint64())
	defer func() { _ = deploy.Docker(context.Background(), "rm", "-f", name).Run() }()
	out, err := deploy.DockerRun(ctx, deploy.Image("VALKEY_IMAGE"),
		[]string{"-d", "--rm", "--name", name, "--label", testContainerLabel, "-p", "127.0.0.1::6379", "--entrypoint", "timeout"},
		testLifetime, "valkey-server", "--save", "", "--appendonly", "no", "--protected-mode", "no").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("starting the calibration server: %v: %s", err, out)
	}
	portOut, err := deploy.Docker(ctx, "port", name, "6379/tcp").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("docker port: %v: %s", err, portOut)
	}
	addr := strings.Replace(strings.TrimSpace(strings.Split(string(portOut), "\n")[0]), "0.0.0.0", "127.0.0.1", 1)
	var c valkey.Client
	if !testwait.Holds(60*time.Second, 500*time.Millisecond, func() bool {
		c, err = valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, DisableCache: true})
		return err == nil
	}) {
		return 0, fmt.Errorf("the calibration server never answered: %v", err)
	}
	defer c.Close()
	var runs []time.Duration
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		if err := c.Do(ctx, c.B().Eval().Script(callCostScript).Numkeys(0).Build()).Error(); err != nil {
			return 0, fmt.Errorf("calibration script: %v", err)
		}
		runs = append(runs, time.Since(t0))
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i] < runs[j] })
	return float64(runs[1].Microseconds()) / 10000, nil
}

// sweepPassBudget is how long a test may wait for the sweep to get through `keys` keys, on this host. It is a
// bound for the failing case, so it errs long: the wait ends as soon as the keys are gone. A pass is paced to a
// fifth of the server's time, so each batch costs five times what the script measures for itself, and the loop
// also starts a valkey-cli for every batch (60 to 70 ms on the Hyper-V host). The formula assumes the floor of 50
// keys a batch, which is the slowest the loop goes; on that host it settles at 100 (a pass over 42,000 keys took
// 110 s there, 300 s before the script timed itself). The budget is two passes (the one that was running when
// the keys were written may have missed them), two gaps of at most 30 s, and a minute and a half for a loaded
// machine. It stops at 25 minutes: the flood's keys live for 30.
func sweepPassBudget(t *testing.T, keys int) time.Duration {
	t.Helper()
	cost, err := hostCallCost()
	if err != nil {
		t.Fatalf("measuring the host's redis.call cost: %v", err)
	}
	batch := 70*time.Millisecond + time.Duration(300*cost)*time.Microsecond
	pass := time.Duration(keys/50) * 5 * batch
	return min(2*pass+2*30*time.Second+90*time.Second, 25*time.Minute)
}

// pct is the p-th percentile (100 is the largest) of the latencies, or 0 for none.
func pct(lats []time.Duration, p int) time.Duration {
	if len(lats) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), lats...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[min(len(s)-1, len(s)*p/100)].Round(100 * time.Microsecond)
}
