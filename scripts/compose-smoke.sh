#!/bin/sh
# The Compose smoke of spec 18.4 (once per phase): bring up the Go services of
# the Panel in production mode on a throw-away project and secrets directory,
# run `ctrlz-admin bootstrap` and `reset-password` in it, and prove that the
# one-time passwords reached no docker log, no stdout or stderr, no audit row and
# no admin session row. ctrlz-admin never prints a password (spec 10.1): it writes
# it to --out-file and prints the path, so the check is the same for every way the
# container was started. Then run the network checks of spec 17.2.
#
# Needs Docker and the image (docker build -f deploy/docker/Dockerfile -t ctrlz/panel:dev .).
# Starts every service of the Compose file that runs on its own: postgres, the two Valkey servers
# (valkey-api, valkey-admin), clickhouse, migrate, api, admin, worker, hub, caddy and the two web
# containers (the busybox placeholder, see below). Round 8 started only the Go services and caddy, so the Valkey ACL line, the ClickHouse wrapper and the hub never ran,
# the secret canary searched the logs of containers that never read those secrets, and the
# console's Valkey clear only ever met a Valkey that was not there (round 9, admin-r9-4). Everything
# is removed at the end, including the volumes of the throw-away project.
# Values are never printed: a failure names the sink, not the secret.
#
#   scripts/compose-smoke.sh
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
export MSYS_NO_PATHCONV=1
project="${CTRLZ_SMOKE_PROJECT:-ctrlzsmoke}"
http_port="${CTRLZ_SMOKE_HTTP_PORT:-18080}"
https_port="${CTRLZ_SMOKE_HTTPS_PORT:-18443}"
image="${CTRLZ_IMAGE:-ctrlz/panel:dev}"
fail() { echo "compose-smoke: $*" >&2; exit 1; }

docker image inspect "$image" >/dev/null 2>&1 || fail "image $image not found; build it first (docker build -f deploy/docker/Dockerfile -t $image .)"

# The Go CI has no token and no CDN, so it cannot build the web images (deploy/docker/web.Dockerfile). The two web
# containers run the busybox placeholder instead, through ci-placeholder.yml: this run judges the Go services, the
# networks and the secrets, and the real web images are the business of scripts/ci-web.sh. The placeholder image
# is the one the Compose file pins by digest for caddy-init, the one place that names it (round 16, admin-r16-9),
# as a literal with no variable to override it (round 17, admin-r17-6): read it from there. The stack has pulled it
# by now; a docker run says --pull never like every docker run of this script.
bb=$(awk '/^  caddy-init:/ {f=1; next} f && /^    image:/ {print $2; exit}' deploy/compose/docker-compose.yml)
[ -n "$bb" ] || fail "the Compose file has no image for caddy-init"
docker image inspect "$bb" >/dev/null 2>&1 || docker pull -q "$bb" >/dev/null || fail "the placeholder image $bb is not on this machine and could not be pulled"

# A path Docker Desktop on Windows can mount; on Linux the path is already right.
host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }

work=$(mktemp -d)
secrets="$work/secrets"
out="$work/out"
mkdir -p "$out"
chmod 0777 "$out"   # the container runs as 65532 and writes the --out-file here

envfile="$work/env"
{
  grep -v '^#' deploy/compose/.env.example | grep -v '^$' | grep -v '^CTRLZ_HTTP_PORT\|^CTRLZ_HTTPS_PORT\|^CTRLZ_IMAGE'
  grep -v '^#' deploy/compose/profiles/small.env | grep -v '^$'
  echo "CTRLZ_IMAGE=$image"
  echo "CTRLZ_WEB_PANEL_IMAGE=$bb"
  echo "CTRLZ_WEB_ADMIN_IMAGE=$bb"
  echo "CTRLZ_HTTP_PORT=$http_port"
  echo "CTRLZ_HTTPS_PORT=$https_port"
  echo "CTRLZ_SECRETS_DIR=$(host_path "$secrets")"
} > "$envfile"

dc() { docker compose -p "$project" -f deploy/compose/docker-compose.yml -f deploy/compose/ci-placeholder.yml --env-file "$(host_path "$envfile")" "$@"; }

cleanup() {
  docker rm -f "${project}-bootstrap" "${project}-reset" "${project}-tty" "${project}-tty-init" "${project}-unlock" >/dev/null 2>&1 || true
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

sh scripts/gen-secrets.sh "$secrets" >/dev/null || fail "gen-secrets failed"
for f in kek_root kek_user_totp kek_admin_totp kek_sms_cred kek_otp_delivery kek_auth_mac kek_admin_mac kek_invite_sign pub_invite_sign; do
  [ -s "$secrets/$f" ] || fail "gen-secrets did not make $f"
done

echo "compose-smoke: starting the stack"
dc up -d >/dev/null 2>&1 || { dc logs --no-color --tail 40 2>&1 | sed 's/^/  /' >&2; fail "docker compose up failed"; }

wait_healthy() { # service
  i=0
  while [ $i -lt 120 ]; do
    cid=$(dc ps -q "$1" 2>/dev/null || true)
    if [ -n "$cid" ]; then
      st=$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo none)
      [ "$st" = "healthy" ] && return 0
    fi
    i=$((i + 1)); sleep 2
  done
  dc logs --no-color --tail 30 "$1" 2>&1 | sed 's/^/  /' >&2
  fail "$1 did not become healthy"
}
# Every long-running service that holds a secret: the three Go roles that read keys, the hub, and the
# three stores whose start lines (the Valkey ACL line, the ClickHouse wrapper, the Postgres init) are
# the places a careless echo would leave a password in a log.
for s in api admin worker hub valkey-api valkey-admin clickhouse; do wait_healthy "$s"; done

# Production mode: the roles run on their key files, not on throw-away keys. Each service must have
# printed its own start line, so a container that is up but silent (or never started) fails here and
# not as an empty search in the canary below.
expect_start() { # service ERE
  dc logs --no-color "$1" 2>&1 | grep -Eq -- "$2" || fail "$1 logged no start line"
}
for s in api admin worker hub; do expect_start "$s" '"msg":"started"|database connected'; done
expect_start valkey-api 'the ACL file is written'
expect_start valkey-admin 'the ACL file is written'
expect_start clickhouse 'the user file is written'
expect_start postgres 'database system is ready to accept connections'

# Through the front door: the panel's public configuration, and the admin API
# refusing an unauthenticated call. -k because Caddy uses its own private CA.
cfg=$(curl -sk --resolve "panel.localhost:$https_port:127.0.0.1" "https://panel.localhost:$https_port/api/v1/auth/config" || true)
echo "$cfg" | grep -q 'registration_mode' || fail "GET /auth/config through Caddy: $cfg"
code=$(curl -sk -o /dev/null -w '%{http_code}' --resolve "admin.localhost:$https_port:127.0.0.1" "https://admin.localhost:$https_port/api/v1/me" || true)
[ "$code" = "401" ] || fail "GET /me on the admin host without a session gave $code"

# The CLI. Without --out-file it must refuse as a usage error and write nothing
# (10.1). The old rule asked whether stdout was a terminal and guessed from the
# process id and its parent whether the terminal was a log (admin-r1-2, admin-r2-6,
# admin-r3-6); the CLI no longer looks, so every start form below must give the same
# answer, and none may leave a password-shaped token in a log. The refusal comes
# before the database is touched, so the tty forms need no network.
shape='[A-Z2-7]{24}'
if dc run -T --rm admin ctrlz-admin bootstrap --username smoke-admin >"$work/refused" 2>&1; then fail "bootstrap without --out-file succeeded"; fi
grep -q -- "--out-file" "$work/refused" || fail "the refusal did not point at --out-file"

# 'docker run --pull never -t' (the CLI is PID 1 on a terminal), with an init process (PID 7,
# parent 1), and 'docker exec -t' (a terminal outside the log): all refuse, and what
# the logging driver recorded says so and holds no password.
tty="${project}-tty"
if docker run --pull never -t --name "$tty" --network none "$image" ctrlz-admin reset-password --user smoke-admin >/dev/null 2>&1; then fail "reset-password on a terminal as PID 1 succeeded without --out-file"; fi
docker logs "$tty" 2>&1 | grep -q -- "--out-file" || fail "the PID 1 terminal refusal did not point at --out-file"
tty_init="${project}-tty-init"
if docker run --pull never -t --init --name "$tty_init" --network none "$image" ctrlz-admin reset-password --user smoke-admin >/dev/null 2>&1; then fail "reset-password on a terminal under an init process succeeded without --out-file"; fi
docker logs "$tty_init" 2>&1 | grep -q -- "--out-file" || fail "the init-process terminal refusal did not point at --out-file"
admin_cid=$(dc ps -q admin)
[ -n "$admin_cid" ] || fail "no admin container to exec in"
if docker exec -t "$admin_cid" ctrlz-admin reset-password --user smoke-admin >"$work/exec.out" 2>&1; then fail "reset-password through docker exec -t succeeded without --out-file"; fi
grep -q -- "--out-file" "$work/exec.out" || fail "the exec refusal did not point at --out-file"

# One-off containers without --rm and with a fixed name, so the logging driver's
# record of them can be read afterwards. The password goes to the 0600 file only.
dc run -T --name "${project}-bootstrap" -v "$(host_path "$out"):/out" admin ctrlz-admin bootstrap --username smoke-admin --out-file /out/bootstrap >"$work/bootstrap.stdout" 2>"$work/bootstrap.stderr" || fail "bootstrap failed"
dc run -T --name "${project}-reset" -v "$(host_path "$out"):/out" admin ctrlz-admin reset-password --user smoke-admin --out-file /out/reset >"$work/reset.stdout" 2>"$work/reset.stderr" || fail "reset-password failed"
# The files are mode 0600 and owned by uid 65532, which a non-root host user cannot
# read (Docker Desktop hides this, a Linux runner does not). Read them as root in a
# throw-away container, so the script does not depend on the host's user (review
# round 3, admin-r3-6).
read_out() { docker run --pull never --rm -v "$(host_path "$out"):/out:ro" "$bb" cat "/out/$1" || fail "could not read $1 from the out directory"; }
pw1=$(read_out bootstrap | sed 's/^[^:]*: //')
pw2=$(read_out reset | sed 's/^[^:]*: //')
[ ${#pw1} -ge 16 ] && [ ${#pw2} -ge 16 ] || fail "the one-time passwords are too short to be real"
[ "$pw1" != "$pw2" ] || fail "reset-password issued the bootstrap password again"
# stdout holds the path and nothing else. stderr is kept apart and is scanned for secrets with the rest: it carries
# the compose progress lines ("Container ... Started", Compose 5 writes them to stderr) and the notice
# "admin created; ...", which are not output of the command a script may parse (A7 did not run this
# step in CI, so the merged capture was never exercised until round 8 put the smoke into ci.sh).
[ "$(tr -d '\r' < "$work/bootstrap.stdout")" = "/out/bootstrap" ] || fail "bootstrap printed more than the path of its out-file"
[ "$(tr -d '\r' < "$work/reset.stdout")" = "/out/reset" ] || fail "reset-password printed more than the path of its out-file"

# The console's Valkey clear against the real Valkey (round 9, admin-r9-4). Valkey is running now, so the
# resets above cleared the limiter's keys as the admin ACL user (ZRANGE, UNLINK, ZREM) and must say
# nothing about a store that could not be cleared. A change to the ACL line that drops one of those
# commands makes the warning appear on every real install and would have passed while Valkey was absent
# and the warning was the normal output. `unlock` must say exactly "unlocked", the word for both stores.
for f in "$work/bootstrap.stderr" "$work/reset.stderr"; do
  grep -q '^warning: ' "$f" && fail "$(basename "$f") holds a console warning against the real Valkey and database"
done
# The admin limiter has written keys of its own by now (one failed login through Caddy, which charges the
# class admin-login and indexes its key), so the clear has something to read and UNLINK: without a key
# the clear stops after an empty ZRANGE, and a drop of +unlink from the ACL line would not show.
curl -sk -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"username":"smoke-admin","password":"not-the-password"}' \
  --resolve "admin.localhost:$https_port:127.0.0.1" "https://admin.localhost:$https_port/api/v1/auth/login" || true
dc run -T --name "${project}-unlock" admin ctrlz-admin unlock --user smoke-admin >"$work/unlock.stdout" 2>"$work/unlock.stderr" || fail "unlock failed"
[ "$(tr -d '\r' < "$work/unlock.stdout")" = "unlocked" ] || fail "unlock did not report both stores cleared"
grep -q '^warning: ' "$work/unlock.stderr" && fail "unlock warned against the real Valkey and database"

# The grep: docker logs of every container (the one-off ones too), the audit
# rows and the admin sessions. A match is a failure; the value is not printed.
logs="$work/logs"
{
  dc logs --no-color 2>&1 || true
  docker logs "${project}-bootstrap" 2>&1 || true
  docker logs "${project}-reset" 2>&1 || true
  docker logs "${project}-tty" 2>&1 || true
  docker logs "${project}-tty-init" 2>&1 || true
  docker logs "${project}-unlock" 2>&1 || true
} > "$logs"
# Every file a one-time password could have been printed to, and the logs of the
# containers that ran the CLI, hold nothing shaped like one.
for f in "$work/refused" "$work/exec.out" "$work/bootstrap.stdout" "$work/reset.stdout" "$work/bootstrap.stderr" "$work/reset.stderr" "$work/unlock.stdout" "$work/unlock.stderr"; do
  grep -Eq -- "$shape" "$f" && fail "something shaped like a one-time password is in $(basename "$f")"
done
for c in "${project}-bootstrap" "${project}-reset" "${project}-tty" "${project}-tty-init" "${project}-unlock"; do
  docker logs "$c" 2>&1 | grep -Eq -- "$shape" && fail "something shaped like a one-time password is in the log of $c"
done
db() { dc exec -T -u postgres postgres psql -d ctrlz -At -c "$1"; }
{
  db "SELECT t::text FROM ctrlz.audit_log t"
  db "SELECT t::text FROM ctrlz.admin_sessions t"
  db "SELECT t::text FROM ctrlz.alerts t"
} > "$work/rows"
[ -s "$work/rows" ] || fail "the audit query returned nothing; the check would be empty"
# Every secret of the stack (the key root and the key files, the database, ClickHouse and Valkey
# passwords, the proof key) is looked for in the logs of every container, in the rows and in what
# the commands printed. The Go canary tests run in process and never see what the Valkey start
# line, the ClickHouse wrapper or the shell of any container prints (round 8, admin-r8-6). The
# check names the secret FILE and the sink and never the value.
# Who reads which secret, from the Compose file itself, and the log of each of those containers on its
# own. The canary fails for a consumer whose log is empty (a container that never started, or never
# printed a line) and for a secret file nothing reads, so the check cannot be clean for a secret
# whose container it never looked at (round 9, admin-r9-4). The services under a profile (rekey) do not
# run here, so the secrets only they read are named, with the reason.
svclogs="$work/svclogs"
mkdir -p "$svclogs"
consumers="$work/consumers"
: > "$consumers"
dc config 2>/dev/null | tr -d '\r' | awk '
  /^services:/ { ins = 1; next }
  /^[a-z]/ { ins = 0 }
  ins && /^  [A-Za-z0-9_-]+:$/ { svc = $1; sub(/:$/, "", svc); insec = 0; next }
  ins && /^    secrets:$/ { insec = 1; next }
  ins && /^    [A-Za-z_]+:/ { insec = 0 }
  ins && insec && /source:/ { print $NF, svc }
' | sort -u | while read -r sname svc; do
  [ -f "$secrets/$sname" ] || continue
  [ -f "$svclogs/$svc" ] || dc logs --no-color --no-log-prefix "$svc" > "$svclogs/$svc" 2>&1 </dev/null || true
  echo "$sname $svc $svclogs/$svc" >> "$consumers"
done
[ -s "$consumers" ] || fail "no service of the Compose file reads a secret file: the consumer list is empty"
# The one secret no file holds: the maintenance password of Valkey, made by the container and written to
# its ACL file in the tmpfs (admin-r15-3). It is read out of the running container into a second directory
# the canary treats as secret files, and the Valkey log is its consumer, so a line of maintain.sh or of the
# start line that printed it fails the smoke. The sed pattern is the one TestMaintainPasswordCanary pins.
runtime="$work/runtime-secrets"
mkdir -p "$runtime"
# Each zone's server makes a maintenance password of its own (round 16, admin-r16-6).
for zone in api admin; do
  dc exec -T "valkey-$zone" sh -c 'sed -n "s/^user maint on >\([^ ]*\) .*/\1/p" /tmp/users.acl' | tr -d '\r\n' > "$runtime/valkey_password_maint_$zone"
  [ "$(wc -c < "$runtime/valkey_password_maint_$zone")" -ge 32 ] || fail "the maintenance password could not be read out of the valkey-$zone container; the canary would not look for it"
  echo "valkey_password_maint_$zone valkey-$zone $svclogs/valkey-$zone" >> "$consumers"
done
export CTRLZ_CANARY_RUNTIME_DIR="$runtime"
export CTRLZ_CANARY_CONSUMERS="$consumers"
# Secret files that no running container reads, each with its reason. kek_root is never mounted: the owner
# copies it off the server and `keys derive` reads it from the host (8.3). kek_cert_wrap and kek_doh_token
# belong to the certificate and endpoint features of later phases, which no service of the stack reads
# yet; the day one does, the entry goes and the check requires that container's log.
export CTRLZ_CANARY_UNCONSUMED="kek_root kek_cert_wrap kek_doh_token"
sh scripts/secret-canary.sh "$secrets" "$logs" "$work/rows" "$work/refused" "$work/exec.out" "$work/bootstrap.stdout" "$work/reset.stdout" "$work/bootstrap.stderr" "$work/reset.stderr" || fail "a secret of the stack is in a log, a row or an output (named above)"
for pw in "$pw1" "$pw2"; do
  grep -qF -- "$pw" "$logs" && fail "a one-time password is in a docker log"
  grep -qF -- "$pw" "$work/rows" && fail "a one-time password is in audit_log, admin_sessions or alerts"
done
# The password hash is not a secret to find here, but a bootstrap that logged it
# would be as bad: the stored hash must not be in the logs either.
hash=$(db "SELECT password_hash FROM ctrlz.admin_users WHERE username = 'smoke-admin'")
[ -n "$hash" ] && grep -qF -- "$hash" "$logs" && fail "the admin password hash is in a docker log"

# --- ipv6 check begin (internal/lint TestComposeSmokeIPv6CheckDoesNotSkipUnderCI runs this block alone)
# An IPv6 client must reach the services under its own address, not Docker's
# gateway: with an IPv4-only ingress network the userland proxy would hand every IPv6
# client over as one address and every per-network limit would be shared (review round
# 3, admin-r3-10). The address to try is an input, CTRLZ_SMOKE_IPV6 (a global or unique-local
# address of this host, the CI job adds one to lo), and not a guess (admin-r16-3). A skip reads as a
# pass in a summary, so under CTRLZ_CI nothing is skipped: a missing or unusable address fails the
# smoke. Only a developer run, with CTRLZ_CI unset, may skip, and the output says SKIPPED. A developer
# run with no address given still looks for a global address on the host, as before; a CI run does not
# guess, because a guess that works on one runner and not on the next is the gap this closes.
v6=${CTRLZ_SMOKE_IPV6:-}
if [ -z "$v6" ] && [ -z "${CTRLZ_CI:-}" ]; then
  v6=$(ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1 || true)
fi
ipv6_skip() { # reason
  if [ -n "${CTRLZ_CI:-}" ]; then
    fail "$1; under CTRLZ_CI the IPv6 source-address check has to run: set CTRLZ_SMOKE_IPV6 to an IPv6 address of this host"
  fi
  echo "compose-smoke: SKIPPED the IPv6 source-address check: $1"
}
if [ -z "$v6" ]; then
  ipv6_skip "no IPv6 address was given in CTRLZ_SMOKE_IPV6 and this host has no global one"
elif ! curl -sk -g -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"username":"smoke-v6","password":"not-the-password"}' \
    --resolve "admin.localhost:$https_port:[$v6]" "https://admin.localhost:$https_port/api/v1/auth/login"; then
  ipv6_skip "the address $v6 is not usable: the stack could not be reached through it"
else
  seen6=$(db "SELECT host(ip) FROM ctrlz.audit_log WHERE action = 'admin.login_failed' AND ip IS NOT NULL ORDER BY id DESC LIMIT 1")
  [ "$seen6" = "$v6" ] || fail "a request over IPv6 reached the admin service as $seen6, not as $v6"
fi
# --- ipv6 check end

export CTRLZ_COMPOSE_ENV="$(host_path "$envfile")"
sh scripts/compose-net-test.sh "$project" || fail "network checks failed"
echo "compose-smoke: ok"
