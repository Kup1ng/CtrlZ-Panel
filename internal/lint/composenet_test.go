package lint_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scripts/compose-net-test.sh needs a running Compose stack, so no Go test ran it, and its
// neighbour probe accepted "none" (no HTTP status at all) as a pass: a `docker run` that failed,
// a name that did not resolve and a refused connection all looked like the service answering 400
// (round 5, admin-r5-12; the same class as admin-r1-11, which had no mutant). This runs the
// script against a stand-in `docker` that plays the stack, so the script's own logic can be shown
// to fail: it passes when the neighbour reaches the service and gets 400 with and without a forged
// header, each carrying the service's X-Request-Id, and fails in every other case. Round 8
// (admin-r8-5): the control used to expect the service's 200 or 401 from the neighbour's bare
// request, which a strict service (production) never gives, so the script failed on every run.

// netStubDocker is a `docker` that answers the calls of the script the way a healthy stack does,
// and answers the neighbour probe (`docker run ... sh -c`) as NEIGHBOUR says.
const netStubDocker = `#!/bin/sh
args="$*"
case "$args" in
  *"command -v node"*) exit 1 ;;
  *"exec -T web-"*"nc -z -w 2 127.0.0.1 3000"*) exit 0 ;;
  *"exec -T web-"*"nc -z"*) exit 1 ;;
  *"exec -T caddy sh -c"*) exit 0 ;;
  *"ip route"*) echo "10.1.0.0/24 dev eth0 src 10.1.0.2"; exit 0 ;;
  *"exec -T caddy wget"*)
    case "$args" in *":8080"*) echo "  HTTP/1.1 200 OK" ;; *) echo "  HTTP/1.1 401 Unauthorized" ;; esac
    exit 0 ;;
  *"run --rm --network"*"sh -c"*)
    # the probe reaches the service with nc (host and port as two words); busybox wget cannot show a 4xx header
    case "$args" in *" 8080"*|*":8080"*) want=200 ;; *) want=401 ;; esac
    rid="  X-Request-Id: 0123456789abcdef"
    case "$NEIGHBOUR" in
      ok)      echo "  HTTP/1.1 400 Bad Request"; echo "$rid"; echo "---"; echo "  HTTP/1.1 400 Bad Request"; echo "$rid" ;;
      trusts)  echo "  HTTP/1.1 400 Bad Request"; echo "$rid"; echo "---"; echo "  HTTP/1.1 $want OK"; echo "$rid" ;;
      barepasses) echo "  HTTP/1.1 $want OK"; echo "$rid"; echo "---"; echo "  HTTP/1.1 400 Bad Request"; echo "$rid" ;;
      dead)    echo "docker: image not found" >&2; exit 125 ;;
      silent)  echo "wget: bad address"; echo "---"; echo "wget: bad address" ;;
      nocontrol) echo "wget: can't connect"; echo "---"; echo "  HTTP/1.1 400 Bad Request"; echo "$rid" ;;
      foreign400) echo "  HTTP/1.1 400 Bad Request"; echo "---"; echo "  HTTP/1.1 400 Bad Request" ;;
    esac
    exit 0 ;;
esac
exit 0
`

func runNetScript(t *testing.T, neighbour string) (string, error) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		git := `C:\Program Files\Git\usr\bin\sh.exe`
		if _, statErr := os.Stat(git); statErr != nil {
			t.Skip("no sh on PATH")
		}
		sh = git
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(netStubDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.ToSlash(filepath.Join(repoRoot(t), "scripts", "compose-net-test.sh"))
	cmd := exec.Command(sh, script)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "NEIGHBOUR="+neighbour)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestComposeNetTestNeighbourProbeCanFail(t *testing.T) {
	out, err := runNetScript(t, "ok")
	if err != nil || !strings.Contains(out, "compose-net-test: ok") {
		t.Fatalf("a neighbour that reaches the service and gets 400 with and without a forged header must pass: %v\n%s", err, out)
	}
	for name, want := range map[string]string{
		"trusts":     "got 200 from api:8080/api/v1/auth/config with a forged X-Forwarded-For, want 400",
		"barepasses": "got 200 from api:8080/api/v1/auth/config without X-Forwarded-For, want 400",
		"dead":       "got no answer of the service",
		"silent":     "got no answer of the service",
		"nocontrol":  "got no answer of the service",
		"foreign400": "got no answer of the service",
	} {
		out, err := runNetScript(t, name)
		if err == nil {
			t.Errorf("%s: the script passed although the probe proved nothing or the service trusted a forged header\n%s", name, out)
			continue
		}
		if !strings.Contains(out, want) && !(name == "trusts" && strings.Contains(out, "want 400")) {
			t.Errorf("%s: the script failed for another reason:\n%s", name, out)
		}
	}
}
