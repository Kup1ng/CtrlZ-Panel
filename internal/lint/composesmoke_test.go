package lint_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// admin-r16-3. The IPv6 source-address check of the Compose smoke skipped itself on a host with no usable IPv6
// path and said so in one line, and a skip in CI reads as green: the check that a client's X-Forwarded-For
// cannot spoof the source address a rate class keys on proved nothing there, and it was the one check no job
// ran (the Windows host cannot, and the runner had no address to try). The address is an input now
// (CTRLZ_SMOKE_IPV6), and under CTRLZ_CI a missing or unusable address is a failure. This test runs the block
// of compose-smoke.sh between its two markers on its own, with stand-ins for the commands it calls, and
// requires each outcome: the skip only in a developer run, the pass, and the mismatch.

func ipv6Block(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "compose-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "# --- ipv6 check begin")
	j := strings.Index(s, "# --- ipv6 check end")
	if i < 0 || j < i {
		t.Fatal("compose-smoke.sh has no marked IPv6 block: the test would run nothing")
	}
	return s[i:j]
}

// runIPv6Block runs the block with a stand-in for each command. curlOK is whether curl connects, seen is what
// the database says the admin saw, hostAddr is what `ip` finds on the host.
func runIPv6Block(t *testing.T, block string, env []string, curlOK bool, seen, hostAddr string) (int, string) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	curl := "return 1"
	if curlOK {
		curl = "return 0"
	}
	prelude := `https_port=18443
fail() { echo "FAIL: $*" >&2; exit 1; }
curl() { ` + curl + `; }
db() { echo "` + seen + `"; }
ip() { echo "2: eth0    inet6 ` + hostAddr + `/64 scope global"; }
`
	cmd := exec.Command(sh, "-c", prelude+block+"\necho DONE")
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestComposeSmokeIPv6CheckDoesNotSkipUnderCI(t *testing.T) {
	block := ipv6Block(t)
	const addr = "fd00:ffff::1"
	for _, tc := range []struct {
		name     string
		env      []string
		curlOK   bool
		seen     string
		hostAddr string
		wantCode int
		want     string // text the output must hold
		notWant  string // text it must not
	}{
		{"CI, an address, it works and is seen as itself", []string{"CTRLZ_CI=1", "CTRLZ_SMOKE_IPV6=" + addr}, true, addr, "", 0, "DONE", "SKIPPED"},
		{"CI, an address, the admin saw another source", []string{"CTRLZ_CI=1", "CTRLZ_SMOKE_IPV6=" + addr}, true, "172.18.0.1", "", 1, "reached the admin service as 172.18.0.1", "DONE"},
		{"CI, no address", []string{"CTRLZ_CI=1"}, true, addr, "", 1, "CTRLZ_SMOKE_IPV6", "DONE"},
		{"CI, no address, though the host has a global one (a guess is not an input)", []string{"CTRLZ_CI=1"}, true, "2001:db8::5", "2001:db8::5", 1, "CTRLZ_SMOKE_IPV6", "DONE"},
		{"CI, an address that cannot be reached", []string{"CTRLZ_CI=1", "CTRLZ_SMOKE_IPV6=" + addr}, false, "", "", 1, "not usable", "DONE"},
		{"developer, no address and none on the host: skipped and said so", nil, true, "", "", 0, "SKIPPED", ""},
		{"developer, an address that cannot be reached: skipped and said so", []string{"CTRLZ_SMOKE_IPV6=" + addr}, false, "", "", 0, "SKIPPED", ""},
		{"developer, the host's global address is tried", nil, true, "2001:db8::5", "2001:db8::5", 0, "DONE", "SKIPPED"},
		{"developer, the address is seen as another", []string{"CTRLZ_SMOKE_IPV6=" + addr}, true, "172.18.0.1", "", 1, "reached the admin service", "DONE"},
	} {
		code, out := runIPv6Block(t, block, tc.env, tc.curlOK, tc.seen, tc.hostAddr)
		if code != tc.wantCode || !strings.Contains(out, tc.want) || (tc.notWant != "" && strings.Contains(out, tc.notWant)) {
			t.Errorf("%s: exit %d, output %q; want exit %d, with %q and without %q", tc.name, code, out, tc.wantCode, tc.want, tc.notWant)
		}
	}
}

// TestCIScriptAsksForTheIPv6InputBeforeItExportsCTRLZ_CI (admin-r16-29). scripts/ci.sh exports CTRLZ_CI=1 for the
// whole run, so the "a developer may skip" branch of the smoke is unreachable through it, and a full run on a
// host with no IPv6 failed at the very end with a message that named an input the script never mentioned. The
// script now says what the smoke needs in its header and stops at once when a full run lacks it. The test holds
// the order: the check comes before the export, and the header names the input.
func TestCIScriptAsksForTheIPv6InputBeforeItExportsCTRLZ_CI(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "ci.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	export := strings.Index(s, "export CTRLZ_CI=1")
	smoke := strings.Index(s, "compose-smoke.sh\"")
	if export < 0 || smoke < 0 {
		t.Fatal("scripts/ci.sh no longer exports CTRLZ_CI or runs the Compose smoke: this test has nothing to hold")
	}
	check := strings.Index(s, `-z "${CTRLZ_SMOKE_IPV6:-}"`)
	if check < 0 || check > export {
		t.Error("scripts/ci.sh must stop on a missing CTRLZ_SMOKE_IPV6 before it exports CTRLZ_CI (the smoke cannot skip under it)")
	}
	header := s[:strings.Index(s, "\nset -eu")]
	if !strings.Contains(header, "CTRLZ_SMOKE_IPV6") {
		t.Error("the header of scripts/ci.sh does not name CTRLZ_SMOKE_IPV6")
	}
}
