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
  *"exec -T web-"*"nc -z -w 2 10.9.3."*)
    # By address (admin-r18-19): the web container reaches api or admin at an address of theirs only when the
    # networks are not isolated.
    [ "${WEB:-}" = ipleak ] && exit 0
    exit 1 ;;
  *"exec -T web-"*"nc -z"*) exit 1 ;;
  *"exec -T caddy sh -c"*"nc -z -w 2 10.9.3."*)
    [ "${WEB:-}" = nocontrol ] && exit 1
    exit 0 ;;
  *"exec -T caddy sh -c"*) exit 0 ;;
  *"ps --filter network="*"vk_api"*)
    echo "valkey-api"; echo "api"; [ "${VALKEY:-}" = member ] && echo "worker"; exit 0 ;;
  *"ps --filter network="*"vk_admin"*)
    echo "valkey-admin"; echo "admin"; [ "${VALKEY:-}" = adminmember ] && echo "worker"; exit 0 ;;
  *"network ls"*)
    [ "${VALKEY:-}" = nonetworks ] && exit 0
    for n in ingress hub_ingress web app egress vk_api vk_admin backend; do
      [ "${VALKEY:-}" = nozone ] && [ "$n" = vk_admin ] && continue
      echo "ctrlz_$n"
    done
    exit 0 ;;
  *"ps -q --filter"*"service=api"*)
    [ "${WEB:-}" = nocontainer ] && exit 0
    echo cid-svcapi; exit 0 ;;
  *"ps -q --filter"*"service=admin"*)
    [ "${WEB:-}" = nocontainer ] && exit 0
    echo cid-svcadmin; exit 0 ;;
  *"ps -q --filter"*)
    [ "${VALKEY:-}" = nocontainer ] && exit 0
    case "$args" in *"service=valkey-api"*) echo cid-api ;; *"service=valkey-admin"*) echo cid-admin ;; esac
    exit 0 ;;
  *"inspect -f"*"cid-svc"*)
    [ "${WEB:-}" = noaddress ] && exit 0
    # the list of every network of the container, or the one address on the app network
    case "$args" in *range*) echo "10.9.3.2 10.9.3.4 " ;; *) echo 10.9.3.2 ;; esac
    exit 0 ;;
  *"inspect -f"*)
    [ "${VALKEY:-}" = noaddress ] && exit 0
    case "$args" in *cid-api*) echo 10.9.1.2 ;; *cid-admin*) echo 10.9.2.2 ;; esac
    exit 0 ;;
  *"nc -z -w 2 10.9."*"6379"*)
    # By address (round 18, admin-r18-14): a stack whose networks are not isolated refuses the name (it does not
    # resolve) and accepts the address.
    [ "${VALKEY:-}" = ipleak ] && case "$args" in *"_backend"*"10.9.1.2"*) echo rc=0; exit 0 ;; esac
    [ "${VALKEY:-}" = adminipleak ] && case "$args" in *"_app"*"10.9.2.2"*) echo rc=0; exit 0 ;; esac
    [ "${VALKEY:-}" = ipdead ] && case "$args" in *"_vk_api"*"10.9.1.2"*) echo rc=1; exit 0 ;; esac
    [ "${VALKEY:-}" = adminipdead ] && case "$args" in *"_vk_admin"*"10.9.2.2"*) echo rc=1; exit 0 ;; esac
    case "$args" in
      *"_vk_api"*"10.9.1.2"*|*"_vk_admin"*"10.9.2.2"*) echo rc=0; exit 0 ;;
    esac
    echo rc=1; exit 0 ;;
  *"nc -z -w 2 valkey-"*"6379"*)
    # the probe prints the status of nc on a line of its own; a run that fails prints none
    [ "${VALKEY:-}" = dockerfail ] && case "$args" in *"_backend"*) echo "docker: network not found" >&2; exit 125 ;; esac
    [ "${VALKEY:-}" = leak ] && case "$args" in *"valkey-api"*) echo rc=0; exit 0 ;; esac
    [ "${VALKEY:-}" = adminleak ] && case "$args" in *"valkey-admin"*) echo rc=0; exit 0 ;; esac
    [ "${VALKEY:-}" = deadcontrol ] && case "$args" in *"_vk_api"*"valkey-api"*) echo rc=1; exit 0 ;; esac
    [ "${VALKEY:-}" = admindead ] && case "$args" in *"_vk_admin"*"valkey-admin"*) echo rc=1; exit 0 ;; esac
    case "$args" in
      *"_vk_api"*"valkey-api"*|*"_vk_admin"*"valkey-admin"*) echo rc=0; exit 0 ;;
    esac
    echo rc=1; exit 0 ;;
  *"ip route"*) echo "10.1.0.0/24 dev eth0 src 10.1.0.2"; exit 0 ;;
  *"exec -T caddy wget"*)
    case "$args" in *":8080"*) echo "  HTTP/1.1 200 OK" ;; *) echo "  HTTP/1.1 401 Unauthorized" ;; esac
    exit 0 ;;
  *"run --pull never --rm --network"*"sh -c"*)
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

func runNetScript(t *testing.T, neighbour string, valkey ...string) (string, error) {
	return runNetScriptWith(t, neighbour, "", valkey...)
}

func runNetScriptWith(t *testing.T, neighbour, web string, valkey ...string) (string, error) {
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
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "NEIGHBOUR="+neighbour, "WEB="+web, "VALKEY="+strings.Join(valkey, ""))
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
		// Each run of the script is dozens of forks, slow where a fork is slow, so the plants run side by side.
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, err := runNetScript(t, name)
			if err == nil {
				t.Errorf("%s: the script passed although the probe proved nothing or the service trusted a forged header\n%s", name, out)
				return
			}
			if !strings.Contains(out, want) && !(name == "trusts" && strings.Contains(out, "want 400")) {
				t.Errorf("%s: the script failed for another reason:\n%s", name, out)
			}
		})
	}
}

// TestComposeNetTestValkeyZonesCanFail (round 17, admin-r17-1; round 17 fix gate, admin-r17-13, -14): the Valkey
// half of the script fails when a backend peer can connect to a zone, when a zone network holds a service that is
// not its own, when the control (the zone's own network reaching its own server) does not connect, which would
// make the negative probes prove nothing, when a probe container did not run to its end (a missing network, a
// daemon error) and when Docker does not list the zone networks. Every plant is expected once for each zone, with
// a message that names the zone, so that a clause of one half cannot be covered by the other half failing in the
// same words (the control mutant of vk_api survived while the control of vk_admin failed first).
func TestComposeNetTestValkeyZonesCanFail(t *testing.T) {
	for name, want := range map[string]string{
		"leak":        "can connect to valkey-api; only the api's zone network may",
		"adminleak":   "can connect to valkey-admin; only the admin's zone network may",
		"member":      "the network vk_api holds",
		"adminmember": "the network vk_admin holds",
		"deadcontrol": "a container on vk_api cannot connect to valkey-api",
		"admindead":   "a container on vk_admin cannot connect to valkey-admin",
		"dockerfail":  "the Valkey probe on backend toward valkey-api did not run to its end",
		"nonetworks":  "Docker has no network vk_api",
		"nozone":      "Docker has no network vk_admin",
		// By address: the name of a server does not resolve from a network it is not on, so only the address
		// shows a missing isolation (admin-r18-14). Each clause has its plant, for each zone.
		"ipleak":      "can connect to valkey-api at its address 10.9.1.2",
		"adminipleak": "can connect to valkey-admin at its address 10.9.2.2",
		"ipdead":      "a container on vk_api cannot connect to valkey-api at 10.9.1.2",
		"adminipdead": "a container on vk_admin cannot connect to valkey-admin at 10.9.2.2",
		"nocontainer": "no running container of valkey-api",
		"noaddress":   "valkey-api has no IPv4 address on the network vk_api",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, err := runNetScript(t, "ok", name)
			if err == nil {
				t.Errorf("%s: the script passed although a Valkey zone was open or the probe proved nothing\n%s", name, out)
				return
			}
			if !strings.Contains(out, want) {
				t.Errorf("%s: the script failed for another reason (want %q):\n%s", name, want, out)
			}
		})
	}
}

// TestComposeNetTestWebRefusalsAreProbedByAddress (round 18 fix gate, admin-r18-19): the refusal of the web
// containers toward api and admin was probed by service name only, which fails at resolution on a network the
// prober is not on whether or not the address is routable (the blind spot admin-r18-14 found for the Valkey
// servers). The script now probes every address api and admin hold from each web container, with the control that
// caddy reaches the app address; each clause has a plant, and the probe of a daemon with no isolation fails.
func TestComposeNetTestWebRefusalsAreProbedByAddress(t *testing.T) {
	if out, err := runNetScriptWith(t, "ok", ""); err != nil || !strings.Contains(out, "compose-net-test: ok") {
		t.Fatalf("an isolated stack must pass: %v\n%s", err, out)
	}
	for name, want := range map[string]string{
		"ipleak":      "can connect to api at its address 10.9.3.2:8080",
		"nocontrol":   "caddy cannot reach api at its address 10.9.3.2:8080 on app",
		"noaddress":   "api has no IPv4 address",
		"nocontainer": "no running container of api",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, err := runNetScriptWith(t, "ok", name)
			if err == nil {
				t.Errorf("%s: the script passed although the address probe was open or proved nothing\n%s", name, out)
				return
			}
			if !strings.Contains(out, want) {
				t.Errorf("%s: the script failed for another reason (want %q):\n%s", name, want, out)
			}
		})
	}
}
