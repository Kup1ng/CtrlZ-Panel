package lint_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
)

// The adaptive batch and the pacing of maintain.sh's sweep, run as the real script in the pinned image with a
// stand-in for valkey-cli. The stand-in is a shell function that an alias puts in front of the name (dash does
// not take a hyphen in a function name), so the script under test is the file as it is, and the "server" answers
// a sweep batch after a delay the test chooses: no real keys, no real clock cost, only the arithmetic that
// turns a measured batch into the next batch size and the next pause. The real server and real keys are TestValkeySweepKeepsLimiterCallsOnTime.

// paceStub answers what maintain.sh asks: PING, SCRIPT LOAD (a fixed digest) and EVALSHA of the sweep, which
// it logs as "<uptime> <batch size>", holds for $STUB_DELAY seconds (the wall time of the call, which is also what a wait
// in the server's queue looks like from outside) and answers with a cursor that reaches 0 on every fifth call, so a
// pass is five batches. The time the batch says it ran is $STUB_US microseconds and the pressure flag $STUB_PRESSURE:
// the real script reports both (sweep.lua), and the loop must follow them and not the wall time.
const paceStub = `valkey_cli() {
	while [ "$#" -gt 0 ] && [ "$1" != --no-auth-warning ]; do shift; done
	shift
	if [ "$1" = -x ]; then cat >/dev/null; echo 0123456789012345678901234567890123456789; return; fi
	case "$1" in
	ping) echo PONG ;;
	evalsha)
		# Shell builtins only (read, echo, arithmetic): a process started here is time the script under test
		# counts as the server's, and on a slow host it would make a "fast" batch slower than its 25 ms line.
		# The time is the uptime in centiseconds, which is all a gap of a second needs.
		read up _ </proc/uptime
		read n </out/count
		n=$((n + 1))
		echo "$n" >/out/count
		echo "$up $7" >>/out/calls
		[ "$STUB_DELAY" = 0 ] || sleep "$STUB_DELAY"
		echo "$((n % 5)) 0 0 0 $STUB_US $STUB_PRESSURE"
		;;
	*) echo "stub: unexpected $1" ;;
	esac
}
alias valkey-cli=valkey_cli
`

type paceCall struct {
	start time.Duration // since the container booted
	batch int
}

// paceCase is what the stand-in server does for one batch: how long the call takes on the wall, and what the
// batch reports of itself.
type paceCase struct {
	delay    string // seconds the call is held
	us       string // microseconds the batch says it ran
	pressure string // "1" when it says the instance is over half of its memory
}

// runPaceStub runs maintain.sh for `window` seconds against the stand-in and returns the batches it asked for,
// in order.
func runPaceStub(t *testing.T, pc paceCase, window int) []paceCall {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: container tests skipped")
	}
	deploy.RemoveStaleTestContainers()
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub.sh")
	if err := os.WriteFile(stub, []byte(paceStub), 0o644); err != nil {
		t.Fatal(err)
	}
	abs := func(parts ...string) string {
		p, err := filepath.Abs(filepath.Join(append([]string{repoRoot(t)}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	name := fmt.Sprintf("ctrlz-valkey-pace-%016x", rand.Uint64())
	removeOnCleanup(t, name)
	script := `printf x >/out/pw; : >/out/calls; echo 0 >/out/count
timeout ` + strconv.Itoa(window) + ` sh -c '. /stub.sh; . /etc/valkey/maintain.sh' >/out/log 2>&1
echo ---; cat /out/calls; echo ===; cat /out/log`
	args := []string{"--rm", "--name", name, "--label", testContainerLabel, "--read-only", "--cap-drop", "ALL", "--tmpfs", "/out",
		"-e", "STUB_DELAY=" + pc.delay, "-e", "STUB_US=" + pc.us, "-e", "STUB_PRESSURE=" + pc.pressure, "-e", "MAINT_INTERVAL=1", "-e", "MAINT_PW_FILE=/out/pw", "-e", "MAINT_MARK=/out/mark", "-e", "ALIVE_FILE=/out/alive",
		"-v", stub + ":/stub.sh:ro",
		"-v", abs("deploy", "compose", "valkey", "maintain.sh") + ":/etc/valkey/maintain.sh:ro",
		"-v", abs("deploy", "compose", "valkey", "sweep.lua") + ":/etc/valkey/sweep.lua:ro",
		"-v", abs("internal", "ratelimit", "lua") + ":/etc/valkey/lua:ro",
		"--entrypoint", "timeout"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(window+120)*time.Second)
	defer cancel()
	out, err := deploy.DockerRun(ctx, deploy.Image("VALKEY_IMAGE"), args, testLifetime, "sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	_, rest, ok := strings.Cut(string(out), "---\n")
	calls, log, _ := strings.Cut(rest, "===\n")
	if !ok {
		t.Fatalf("no call log in the output:\n%s", out)
	}
	var cs []paceCall
	for _, line := range strings.Split(strings.TrimSpace(calls), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("a malformed call line %q; the loop said:\n%s", line, log)
		}
		secs, err1 := strconv.ParseFloat(f[0], 64)
		b, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			t.Fatalf("a malformed call line %q", line)
		}
		cs = append(cs, paceCall{time.Duration(secs * float64(time.Second)), b})
	}
	return cs
}

// TestSweepBatchShrinksAndPacesWhenTheServerIsSlow: a batch the stand-in holds for 400 ms is far over the
// 100 ms line, so the size must halve from 200 to the floor of 50 and stay there, the pause after each batch
// must be about four batch lengths (1.6 s), and the next pass must wait for the last pass's length (the gap
// is the larger of MAINT_INTERVAL, 1 s here, and that), not for the interval.
func TestSweepBatchShrinksAndPacesWhenTheServerIsSlow(t *testing.T) {
	cs := runPaceStub(t, paceCase{delay: "0.4", us: "400000", pressure: "0"}, 28)
	if len(cs) < 6 {
		t.Fatalf("%d batches in 28 s, want a pass of five and the start of the next", len(cs))
	}
	for i, want := range []int{200, 100, 50, 50, 50} {
		if cs[i].batch != want {
			t.Errorf("batch %d asked for %d keys, want %d (sizes %v)", i+1, cs[i].batch, want, sizes(cs))
		}
	}
	for i := 1; i < 5; i++ {
		// Start to start is the batch (0.4 s) and its pause (1.6 s), and the shell's own overhead on a slow host.
		if d := cs[i].start - cs[i-1].start; d < 1900*time.Millisecond || d > 3*time.Second {
			t.Errorf("batches %d and %d started %v apart, want about 2 s (0.4 s of work and a pause of four times that)", i, i+1, d)
		}
	}
	// The pass ran from the first start to the end of the fifth batch: about 4 x 2 s and 0.4 s. The next pass starts
	// after a gap of that length, far beyond the 1 s interval.
	pass := cs[4].start - cs[0].start + 400*time.Millisecond
	if gap := cs[5].start - cs[4].start - 400*time.Millisecond; gap < pass*3/4 {
		t.Errorf("the next pass started %v after the last batch, want about the pass's own length (%v), not the 1 s interval", gap, pass)
	}
}

// TestSweepBatchGrowsAndDoesNotPauseWhenTheServerIsFast: a batch that takes nothing doubles the size to its cap
// of 500 and is not followed by a pause, and a pass ends and the next waits for the interval only.
func TestSweepBatchGrowsAndDoesNotPauseWhenTheServerIsFast(t *testing.T) {
	cs := runPaceStub(t, paceCase{delay: "0", us: "0", pressure: "0"}, 14)
	if len(cs) < 6 {
		t.Fatalf("%d batches in 14 s, want at least a pass of five and the start of the next", len(cs))
	}
	for i, want := range []int{200, 400, 500, 500, 500} {
		if cs[i].batch != want {
			t.Errorf("batch %d asked for %d keys, want %d (sizes %v)", i+1, cs[i].batch, want, sizes(cs))
		}
	}
	// The stand-in costs a process start or two per call: far under the half second a pause of any size would add.
	if d := cs[4].start - cs[0].start; d > 2*time.Second {
		t.Errorf("five batches took %v: the loop paused after batches that took no time", d)
	}
	if gap := cs[5].start - cs[4].start; gap < 900*time.Millisecond {
		t.Errorf("the next pass started %v after the last batch, want at least the 1 s interval", gap)
	}
}

// TestSweepBatchFollowsTheTimeTheBatchReportsNotTheTimeOfTheCall: a call that is held 0.4 s on the wall but whose
// batch ran 10 ms is a server that was busy with other clients (a flood), not a slow sweep. If the loop sized and
// paced by the wall time it would shrink to 50 keys and sleep 1.6 s after each batch, and a flood that loads the
// server would slow the sweep down exactly when it has to be quick (round 1, sweep-r1-security-1). It must grow
// and sleep for four times the batch's own 10 ms.
func TestSweepBatchFollowsTheTimeTheBatchReportsNotTheTimeOfTheCall(t *testing.T) {
	cs := runPaceStub(t, paceCase{delay: "0.4", us: "10000", pressure: "0"}, 10)
	if len(cs) < 5 {
		t.Fatalf("%d batches in 10 s, want a pass of five", len(cs))
	}
	for i, want := range []int{200, 400, 500, 500, 500} {
		if cs[i].batch != want {
			t.Errorf("batch %d asked for %d keys, want %d (sizes %v)", i+1, cs[i].batch, want, sizes(cs))
		}
	}
	for i := 1; i < 5; i++ {
		// 0.4 s of call, a pause of 40 ms and the shell's own overhead; a pause of four wall times would be 2 s.
		if d := cs[i].start - cs[i-1].start; d > 1200*time.Millisecond {
			t.Errorf("batches %d and %d started %v apart, want well under 2 s: the pause followed the wall time of the call", i, i+1, d)
		}
	}
}

// TestSweepUnderPressure: when the batch says the instance is over half of its memory the sweep must get to the
// keys over the budget as fast as it can (round 1, sweep-r1-correctness-1: paced, a flood that fills the
// instance was cut back only after minutes), within the bound that the limiter still works between half and full
// (round 2, sweep-r2-security-2).
func TestSweepUnderPressure(t *testing.T) {
	// A batch that reports 150 ms: over the 100 ms line, so the size would halve, but under pressure it keeps 200
	// keys and does not pause. The pass is long (five batches of 0.6 s) against the 1 s interval, and the next
	// pass must still start after the interval and not after the pass's own length (round 2, sweep-r2-security-1:
	// the instance is still filling, nothing sits idle for the host's sake).
	t.Run("keeps its size, does not pause and does not stretch the gap", func(t *testing.T) {
		t.Parallel()
		cs := runPaceStub(t, paceCase{delay: "0.6", us: "150000", pressure: "1"}, 14)
		if len(cs) < 6 {
			t.Fatalf("%d batches in 14 s, want a pass of five and the start of the next", len(cs))
		}
		for i, c := range cs[:5] {
			if c.batch != 200 {
				t.Errorf("batch %d asked for %d keys, want 200 (sizes %v)", i+1, c.batch, sizes(cs))
			}
		}
		for i := 1; i < 5; i++ {
			// 0.6 s of call and the shell's overhead; a pause of four reported batch lengths would add 0.6 s.
			if d := cs[i].start - cs[i-1].start; d > 1050*time.Millisecond {
				t.Errorf("batches %d and %d started %v apart: the loop paused under pressure", i, i+1, d)
			}
		}
		// The pass is about 3.5 s. After it the loop PINGs, loads the scripts and sleeps the 1 s interval: far under
		// the pass's own length, which is what a gap that ignored pressure would be.
		if gap := cs[5].start - cs[4].start - 600*time.Millisecond; gap > 2300*time.Millisecond {
			t.Errorf("the next pass started %v after the last batch ended, want about the 1 s interval: the gap followed the pass's length under pressure", gap)
		}
	})
	// A batch that reports 400 ms is a host where 200 keys hold the limiter far past its timeout: the floor of 200
	// is not kept, the size follows the clock down to 50, and there is still no pause.
	t.Run("follows the clock when a batch is slow", func(t *testing.T) {
		t.Parallel()
		cs := runPaceStub(t, paceCase{delay: "0.2", us: "400000", pressure: "1"}, 10)
		if len(cs) < 5 {
			t.Fatalf("%d batches in 10 s, want a pass of five", len(cs))
		}
		for i, want := range []int{200, 100, 50, 50, 50} {
			if cs[i].batch != want {
				t.Errorf("batch %d asked for %d keys, want %d (sizes %v)", i+1, cs[i].batch, want, sizes(cs))
			}
		}
		for i := 1; i < 5; i++ {
			if d := cs[i].start - cs[i-1].start; d > 900*time.Millisecond {
				t.Errorf("batches %d and %d started %v apart: the loop paused under pressure", i, i+1, d)
			}
		}
	})
}

func sizes(cs []paceCall) []int {
	var s []int
	for _, c := range cs {
		s = append(s, c.batch)
	}
	return s
}

// TestValkeyStartNamesASlowClockSource: the start file says once, at start, when the host's clock source is
// not tsc or kvm-clock, because that is what makes a sweep batch stall the limiter for longer (a redis.call
// reads the clock, and on such a host the read traps), and it never refuses to start for it. The file the
// start reads is given by CTRLZ_CLOCKSOURCE_PATH, which only a test sets: the real one is the host's, and a test
// cannot choose it.
func TestValkeyStartNamesASlowClockSource(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		warns         bool
		named         string // what the warning says the clock source is, when it warns
	}{
		{"hyperv", "hyperv_clocksource_tsc_page\n", true, "hyperv_clocksource_tsc_page"},
		{"tsc", "tsc\n", false, ""},
		{"kvm-clock", "kvm-clock\n", false, ""},
		{"unreadable", "", false, ""},
		// The file the override names is the test's to choose, and the log is never the place for what is in it: a
		// line that is not the shape of a clock source (here a password's) is called unreadable (round 1, sweep-r1-security-4).
		{"not a clock source", valkeyPasswords["api"] + "\n", true, "unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := []string{"-e", "CTRLZ_CLOCKSOURCE_PATH=/clocksource"}
			if tc.content != "" {
				f := filepath.Join(t.TempDir(), "clocksource")
				if err := os.WriteFile(f, []byte(tc.content), 0o444); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-v", f+":/clocksource:ro")
			}
			name, _, _ := runValkeyZone(t, "api", []byte(valkeyPasswords["api"]+"\r\n"), false, args...)
			// The loop prints this a moment after the server starts, so the start file is past the place that warns.
			waitLog(t, name, "the limiter scripts are loaded", 120*time.Second)
			log := logsOf(name)
			if got := strings.Contains(log, "the clock source of this host is "+tc.named+","); tc.warns && !got {
				t.Errorf("no warning for %q; log:\n%s", tc.content, log)
			}
			if tc.named == "unreadable" && strings.Contains(log, strings.TrimSpace(tc.content)) {
				t.Errorf("the log holds the content of the file: %s", log)
			}
			if !tc.warns && strings.Contains(log, "clock source") {
				t.Errorf("a warning for %q; log:\n%s", tc.content, log)
			}
			if n := strings.Count(log, "clock source"); n > 1 {
				t.Errorf("the warning was printed %d times, want once", n)
			}
		})
	}
}
