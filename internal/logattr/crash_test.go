package logattr_test

import (
	"os"
	"os/exec"
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
