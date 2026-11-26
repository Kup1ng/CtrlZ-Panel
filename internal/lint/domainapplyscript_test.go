package lint_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// scripts/domain-apply.sh runs the one-shot and renames what it prints over the .env (p4-nodes 10.4). The fault it must
// never have is replacing a good .env with a bad or half-written one, or recreating the services after a failed run.
// The test runs a copy of the script in a scratch tree (never against a real .env) with a stand-in `docker` that prints
// what the case says and records how it was called.

type applyRun struct {
	code    int
	out     string
	env     string // the .env after the run
	prev    string // .env.prev, "" if none
	dockerL string // the docker calls, one a line
	left    []string
}

func runApplyScript(t *testing.T, oneShotOut string, oneShotCode string) applyRun {
	return runApplyScriptWith(t, oneShotOut, oneShotCode, "0")
}

// runApplyScriptWith also sets the exit code of the `--commit` call, the second run of the one-shot.
func runApplyScriptWith(t *testing.T, oneShotOut string, oneShotCode string, commitCode string) applyRun {
	return runApplyScriptFull(t, oneShotOut, oneShotCode, commitCode, "0", "0")
}

// runApplyScriptFull also sets the exit codes of the `--prune` call and of `up`, the recreate.
func runApplyScriptFull(t *testing.T, oneShotOut string, oneShotCode string, commitCode string, pruneCode string, upCode string) applyRun {
	return runApplyScriptStderr(t, oneShotOut, oneShotCode, commitCode, pruneCode, upCode, false)
}

// runApplyScriptStderr with deadStderr gives the script a standard error that fails every write, as a hung-up tty does.
func runApplyScriptStderr(t *testing.T, oneShotOut string, oneShotCode string, commitCode string, pruneCode string, upCode string, deadStderr bool) applyRun {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		git := `C:\Program Files\Git\usr\bin\sh.exe`
		if _, statErr := os.Stat(git); statErr != nil {
			t.Skip("no sh on PATH")
		}
		sh = git
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	comp := filepath.Join(root, "deploy", "compose")
	if err := os.MkdirAll(comp, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "domain-apply.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "domain-apply.sh")
	if err := os.WriteFile(script, src, 0o755); err != nil {
		t.Fatal(err)
	}
	const oldEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=old.example.ir\n"
	if err := os.WriteFile(filepath.Join(comp, ".env"), []byte(oldEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	logf := filepath.Join(t.TempDir(), "docker.log")
	outf := filepath.Join(t.TempDir(), "oneshot.out")
	if err := os.WriteFile(outf, []byte(oneShotOut), 0o600); err != nil {
		t.Fatal(err)
	}
	// commitCode is the exit code of the commit call, or a list of codes for the calls in turn (the last one repeats). The
	// word "hup" sends the script a HUP while the call runs, as a dropped ssh link would, and the call then ends 0.
	commitStub := "n=$(grep -c -e '--commit' '" + filepath.ToSlash(logf) + "'); set -- " + commitCode + "; " +
		"[ \"$n\" -gt \"$#\" ] && n=$#; eval \"c=\\${$n}\"; " +
		"if [ \"$c\" = hup ]; then kill -HUP $PPID; sleep 1; exit 0; fi; exit $c"
	stub := "#!/bin/sh\necho \"$@\" >> '" + filepath.ToSlash(logf) + "'\n" +
		"case \" $* \" in *\" --commit \"*) " + commitStub + " ;; *\" --prune \"*) exit " + pruneCode + " ;; *\" up \"*) exit " + upCode + " ;; *\" run \"*) cat '" + filepath.ToSlash(outf) + "'; exit " + oneShotCode + " ;; esac\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, filepath.ToSlash(script))
	if deadStderr {
		if _, err := os.Stat("/dev/full"); err != nil && runtime.GOOS != "windows" {
			t.Skip("no /dev/full")
		}
		cmd = exec.Command(sh, "-c", `exec 2>/dev/full; exec sh "$0"`, filepath.ToSlash(script))
	}
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	r := applyRun{out: string(out)}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(comp, ".env"))
	r.env = string(b)
	if b, err := os.ReadFile(filepath.Join(comp, ".env.prev")); err == nil {
		r.prev = string(b)
	}
	if b, err := os.ReadFile(logf); err == nil {
		r.dockerL = string(b)
	}
	entries, _ := os.ReadDir(comp)
	for _, e := range entries {
		if e.Name() != ".env" && e.Name() != ".env.prev" && e.Name() != ".env.domain-apply.lock" {
			r.left = append(r.left, e.Name())
		}
	}
	return r
}

func TestDomainApplyScriptReplacesTheEnvThenRecreates(t *testing.T) {
	const newEnv = "# kept\nCTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.example.ir\nCTRLZ_VERIFY_ORIGIN=https://*.verify.dns.example.ir\n"
	r := runApplyScript(t, newEnv, "0")
	if r.code != 0 {
		t.Fatalf("exit code %d\n%s", r.code, r.out)
	}
	if r.env != newEnv {
		t.Errorf("the .env is %q, want the printed one", r.env)
	}
	if !strings.Contains(r.prev, "old.example.ir") {
		t.Errorf(".env.prev is %q, want the old file", r.prev)
	}
	run := strings.Index(r.dockerL, " run ")
	up := strings.Index(r.dockerL, " up ")
	if run < 0 || up < run {
		t.Errorf("the one-shot must run before the recreate:\n%s", r.dockerL)
	}
	if !strings.Contains(r.dockerL, "domain-apply") {
		t.Errorf("the one-shot is not domain-apply:\n%s", r.dockerL)
	}
	for _, s := range []string{"caddy", "web-panel", "api", "admin"} {
		if !strings.Contains(r.dockerL[up:], " "+s) {
			t.Errorf("%s is not recreated:\n%s", s, r.dockerL)
		}
	}
	if len(r.left) != 0 {
		t.Errorf("the compose directory keeps %v", r.left)
	}
}

func TestDomainApplyScriptKeepsTheEnvWhenTheRunIsNotGood(t *testing.T) {
	const oldEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=old.example.ir\n"
	for name, c := range map[string]struct{ out, code string }{
		"the one-shot fails after printing":    {"CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=half.example.ir\n", "1"},
		"the one-shot prints nothing":          {"", "0"},
		"the printed file has no marker":       {"CTRLZ_PANEL_HOST=x.example.ir\n", "0"},
		"the printed file has a stray command": {"CTRLZ_ENV_FORMAT_2=1\nrm -rf /\n", "0"},
	} {
		t.Run(name, func(t *testing.T) {
			r := runApplyScript(t, c.out, c.code)
			if r.code == 0 {
				t.Fatalf("exit code 0\n%s", r.out)
			}
			if r.env != oldEnv {
				t.Errorf("the .env was changed to %q", r.env)
			}
			if strings.Contains(r.dockerL, " up ") {
				t.Errorf("services were recreated after a bad run:\n%s", r.dockerL)
			}
			if len(r.left) != 0 {
				t.Errorf("the compose directory keeps %v", r.left)
			}
		})
	}
}

// The applied_* columns are what the api's Host gate reads, so the second run of the one-shot (`--commit`) must come
// after the rename of the .env and before the recreate, and a first run that fails must never reach it (R34-r1-2, r1-7).
func TestDomainApplyScriptCommitsBetweenTheRenameAndTheRecreate(t *testing.T) {
	const newEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.example.ir\n"
	r := runApplyScript(t, newEnv, "0")
	if r.code != 0 {
		t.Fatalf("exit code %d\n%s", r.code, r.out)
	}
	run := strings.Index(r.dockerL, " --commit")
	up := strings.Index(r.dockerL, " up ")
	if run < 0 || up < run {
		t.Errorf("the commit run must come before the recreate:\n%s", r.dockerL)
	}
	if strings.Count(r.dockerL, " run ") != 3 {
		t.Errorf("want the one-shot three times (apply, commit, prune):\n%s", r.dockerL)
	}
	// The clean-up of the old host's files comes only after the recreate: the old containers read them until then.
	if prune := strings.Index(r.dockerL, " --prune"); prune < up {
		t.Errorf("the clean-up must come after the recreate:\n%s", r.dockerL)
	}

	// A first run that is refused never reaches the commit.
	for name, c := range map[string]struct{ out, code string }{
		"the one-shot fails":       {newEnv, "1"},
		"a line the check refuses": {"CTRLZ_ENV_FORMAT_2=1\nexport A=1\n", "0"},
	} {
		r := runApplyScript(t, c.out, c.code)
		if r.code == 0 || strings.Contains(r.dockerL, "--commit") {
			t.Errorf("%s: code %d, the commit ran:\n%s", name, r.code, r.dockerL)
		}
	}

	// A commit that recorded nothing (exit code 3) puts the old .env back, recreates nothing and says to run again. The old
	// .env matters: a host that nobody requested is read from it, and the refused one must not become the host that works
	// (R34-r2-4).
	const oldEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=old.example.ir\n"
	r = runApplyScriptWith(t, newEnv, "0", "3")
	if r.code == 0 || strings.Contains(r.dockerL, " up ") || strings.Contains(r.dockerL, " --prune") || !strings.Contains(r.out, "run this script again") {
		t.Errorf("a failed commit: code %d, out %q, calls:\n%s", r.code, r.out, r.dockerL)
	}
	if r.env != oldEnv {
		t.Errorf("the .env is %q after a failed commit, want the old one", r.env)
	}
	if len(r.left) != 0 {
		t.Errorf("the compose directory keeps %v", r.left)
	}
}

// After the commit the new .env stays whatever happens to the recreate: the hosts are recorded, and the rerun the script asks
// for plans from the database. A clean-up that fails is a warning and not a failure, and an .env that does not change
// leaves .env.prev as it was.
func TestDomainApplyScriptAfterTheCommit(t *testing.T) {
	const newEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.example.ir\n"
	r := runApplyScriptFull(t, newEnv, "0", "0", "0", "1")
	if r.code == 0 || r.env != newEnv || strings.Contains(r.dockerL, " --prune") || !strings.Contains(r.out, "run this script again") {
		t.Errorf("a failed recreate: code %d, env %q, out %q, calls:\n%s", r.code, r.env, r.out, r.dockerL)
	}
	r = runApplyScriptFull(t, newEnv, "0", "0", "1", "0")
	if r.code != 0 || r.env != newEnv || !strings.Contains(r.out, "warning") {
		t.Errorf("a failed clean-up: code %d, env %q, out %q", r.code, r.env, r.out)
	}
	// The printed file equals the one in place: nothing is replaced and no .env.prev is written over the older one.
	const sameEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=old.example.ir\n"
	r = runApplyScript(t, sameEnv, "0")
	if r.code != 0 || r.env != sameEnv || r.prev != "" {
		t.Errorf("an unchanged .env: code %d, env %q, prev %q", r.code, r.env, r.prev)
	}
}

// A commit whose outcome is unknown (the container died, the link dropped, the answer was lost) may have moved the columns,
// so the old .env must not go back over them: the commit is asked once more, and when that does not answer either the
// new .env stays (R34-r3-2).
func TestDomainApplyScriptKeepsTheNewEnvWhenTheCommitIsUnknown(t *testing.T) {
	const newEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.example.ir\n"
	// Still unknown on the second ask: the new .env stays, nothing is recreated.
	r := runApplyScriptWith(t, newEnv, "0", "1")
	if r.code == 0 || r.env != newEnv || strings.Contains(r.dockerL, " up ") || strings.Count(r.dockerL, "--commit") != 2 || !strings.Contains(r.out, "run this script again") {
		t.Errorf("an unknown outcome: code %d, env %q, out %q, calls:\n%s", r.code, r.env, r.out, r.dockerL)
	}
	// The second ask answers: the run goes on as after a first success.
	r = runApplyScriptWith(t, newEnv, "0", "1 0")
	if r.code != 0 || r.env != newEnv || !strings.Contains(r.dockerL, " up ") {
		t.Errorf("an answer on the second ask: code %d, env %q, out %q, calls:\n%s", r.code, r.env, r.out, r.dockerL)
	}
	// A refusal on the second ask is not proof that the first recorded nothing: the new .env stays too.
	r = runApplyScriptWith(t, newEnv, "0", "1 3")
	if r.code == 0 || r.env != newEnv || strings.Contains(r.dockerL, " up ") {
		t.Errorf("a refusal after an unknown first ask: code %d, env %q, calls:\n%s", r.code, r.env, r.dockerL)
	}
}

// The old .env is mounted for the commit only when the script replaced the .env, so the one-shot reads an unrequested host
// from the file the first run read (R34-r3-1).
func TestDomainApplyScriptMountsThePreviousEnvForTheCommit(t *testing.T) {
	commitLine := func(l string) string {
		for _, line := range strings.Split(l, "\n") {
			if strings.Contains(line, "--commit") {
				return line
			}
		}
		return ""
	}
	r := runApplyScript(t, "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.example.ir\n", "0")
	if !strings.Contains(commitLine(r.dockerL), ":/compose/.env.prev:ro") {
		t.Errorf("a replaced .env: the commit does not mount the old one:\n%s", r.dockerL)
	}
	r = runApplyScript(t, "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=old.example.ir\n", "0")
	if strings.Contains(commitLine(r.dockerL), ".env.prev") {
		t.Errorf("an unchanged .env: a stale .env.prev is mounted:\n%s", r.dockerL)
	}
}

// A stop that arrives while the commit runs must not put the old .env back over columns that may have moved: the signals
// are ignored from the rename until the outcome is known (R34-r3-2). Where the shell cannot signal itself the case does
// nothing and passes.
func TestDomainApplyScriptIgnoresAStopDuringTheCommit(t *testing.T) {
	const newEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.example.ir\n"
	r := runApplyScriptWith(t, newEnv, "0", "hup")
	if r.env != newEnv {
		t.Errorf("a HUP during the commit put the old .env back: env %q, code %d, out %q", r.env, r.code, r.out)
	}
}

// A link that drops hangs up the terminal: the diagnostics then fail to write. Under set -e that must not end the script
// with the old .env put back over columns the container may have moved (R34-r4-3).
func TestDomainApplyScriptKeepsTheNewEnvWhenStderrIsDead(t *testing.T) {
	const newEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.example.ir\n"
	// Unknown on the first ask, answered on the second: the run must go on as after a first success.
	r := runApplyScriptStderr(t, newEnv, "0", "1 0", "0", "0", true)
	if r.env != newEnv || !strings.Contains(r.dockerL, " up ") {
		t.Errorf("a dead stderr after an unknown first ask: code %d, env %q, calls:\n%s", r.code, r.env, r.dockerL)
	}
	// Unknown twice: the new .env stays.
	r = runApplyScriptStderr(t, newEnv, "0", "1", "0", "0", true)
	if r.code == 0 || r.env != newEnv || strings.Contains(r.dockerL, " up ") {
		t.Errorf("a dead stderr after two unknown asks: code %d, env %q, calls:\n%s", r.code, r.env, r.dockerL)
	}
}
