package logattr_test

import (
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
)

// crashCanary is a value no log may hold. leak takes it BY VALUE, the way recovery.encode takes the
// ten bytes of a recovery code, so the runtime's traceback prints its words when the process dies.
var crashCanary = [16]byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe}

//go:noinline
func leak(secret [16]byte, n int) int {
	var m map[int]int
	m[n] = int(secret[0]) // an unrecovered panic with the secret in a frame
	return n
}

// TestCrashChild is the process the test below runs: it dies of an unrecovered panic under a frame
// that holds the canary. It does nothing unless the parent asked for it, and it returns without a skip:
// the CI shard fails a run on any skip that is not on its list of by-design skips (run 44855288724 failed
// on this one), and this is the body of a child process that the test below starts, not a skipped test.
func TestCrashChild(t *testing.T) {
	if os.Getenv("CTRLZ_CRASH_CHILD") != "1" {
		return
	}
	leak(crashCanary, 0)
}

// TestGoTracebackNoneKeepsFramesOutOfACrash is primitives-r17-9: the runtime prints the arguments of
// every frame when the process dies, a value passed by value is printed as its words, and
// debug.SetTraceback cannot lower the level (the default is already above none), so the image sets
// GOTRACEBACK=none (deploy/docker/Dockerfile, held by internal/lint TestTheImageSilencesGoCrashTracebacks).
// This test shows that the setting does what that line relies on: the control run, with the default
// level, prints the canary; the run with GOTRACEBACK=none prints the panic message and no frame.
func TestGoTracebackNoneKeepsFramesOutOfACrash(t *testing.T) {
	run := func(traceback string) string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.v")
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "GOTRACEBACK=") && !strings.HasPrefix(e, "CTRLZ_CRASH_CHILD=") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		cmd.Env = append(cmd.Env, "CTRLZ_CRASH_CHILD=1")
		if traceback != "" {
			cmd.Env = append(cmd.Env, "GOTRACEBACK="+traceback)
		}
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("GOTRACEBACK=%q: the child did not die", traceback)
		}
		return string(out)
	}
	if loud := run(""); !strings.Contains(loud, "0xde, 0xad, 0xbe") {
		t.Fatalf("the control run does not print the canary, so this test proves nothing:\n%s", loud)
	}
	quiet := run("none")
	if strings.Contains(quiet, "0xde") || strings.Contains(quiet, "goroutine ") {
		t.Errorf("a crash with GOTRACEBACK=none printed a frame:\n%s", quiet)
	}
	if !strings.Contains(quiet, "panic:") {
		t.Errorf("a crash with GOTRACEBACK=none lost the panic message:\n%s", quiet)
	}
}

// overflowByValue and overflowBySlice recurse until the runtime kills the process with a stack overflow,
// which it raises as a THROW. A throw prints every goroutine with the arguments of its frames whatever
// GOTRACEBACK says (the runtime raises the level itself, in Go 1.27 gotraceback() for throwTypeRuntime),
// so the environment of the image is not a wall for it (round 18, primitives-r18-9). The first holds the
// canary by value, the second only a slice of it.
//
//go:noinline
func overflowByValue(secret [16]byte, n int) int {
	if n < 0 {
		return int(secret[0])
	}
	return overflowByValue(secret, n+1) + 1
}

//go:noinline
func overflowBySlice(secret []byte, n int) int {
	if n < 0 {
		return int(secret[0])
	}
	return overflowBySlice(secret, n+1) + 1
}

// TestThrowChild is the process the test below starts for a runtime throw; like TestCrashChild it does
// nothing unless the parent asked for it.
func TestThrowChild(t *testing.T) {
	switch os.Getenv("CTRLZ_CRASH_CHILD") {
	case "throw-value":
		debug.SetMaxStack(1 << 20)
		overflowByValue(crashCanary, 0)
	case "throw-slice":
		debug.SetMaxStack(1 << 20)
		overflowBySlice(crashCanary[:], 0)
	}
}

// TestARuntimeThrowIgnoresGoTracebackNone is primitives-r18-9 and holds the reason the lint
// TestNoFunctionTakesAnArrayByValue exists. The environment of the image (GOTRACEBACK=none) keeps frames out
// of an unrecovered panic, and it does not keep them out of a runtime throw: a stack overflow with the canary
// held by value in the frames prints its words, and the same overflow with only a slice prints an address, a
// length and a capacity. So the class is removed by construction (no function takes an array by value), and
// the setting stays as a second wall. If a later Go release makes the throw respect the setting, the first
// assertion fails and the spec text (8.6) and rule closed-values-in-logs get a fresh look.
func TestARuntimeThrowIgnoresGoTracebackNone(t *testing.T) {
	run := func(mode string) string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestThrowChild$", "-test.v")
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "GOTRACEBACK=") && !strings.HasPrefix(e, "CTRLZ_CRASH_CHILD=") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		cmd.Env = append(cmd.Env, "CTRLZ_CRASH_CHILD="+mode, "GOTRACEBACK=none")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("%s: the child did not die", mode)
		}
		return string(out)
	}
	if byValue := run("throw-value"); !strings.Contains(byValue, "0xde, 0xad, 0xbe") || !strings.Contains(byValue, "stack overflow") {
		t.Errorf("a stack overflow with GOTRACEBACK=none no longer prints the arguments of its frames, so the setting covers more than the spec says:\n%.2000s", byValue)
	}
	if bySlice := run("throw-slice"); strings.Contains(bySlice, "0xde") || !strings.Contains(bySlice, "stack overflow") {
		t.Errorf("a slice argument printed its bytes, or the child did not overflow:\n%.2000s", bySlice)
	}
}
