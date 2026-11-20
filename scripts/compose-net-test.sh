#!/bin/sh
# The network checks of spec 17.2, on a running stack:
#   - a web container cannot connect to api:8080 or admin:8081;
#   - a neighbour on app or backend (hub, worker, a compromised container) gets 400
#     from api and admin whatever it sends, with or without X-Forwarded-For, because
#     they take a client address from caddy alone;
#   - the app and web networks have no default route (they are internal), so
#     api and admin, which sit on app and backend only, have no way out.
# The Go images have no shell, so a throwaway busybox on the same network proves
# the route for them.
#
#   scripts/compose-net-test.sh [project]      project defaults to ctrlz
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
project="${1:-ctrlz}"
file="${CTRLZ_COMPOSE_FILE:-$here/deploy/compose/docker-compose.yml}"
envfile="${CTRLZ_COMPOSE_ENV:-}"
export MSYS_NO_PATHCONV=1
fail() { echo "compose-net-test: $*" >&2; exit 1; }
dc() {
  if [ -n "$envfile" ]; then docker compose -p "$project" -f "$file" --env-file "$envfile" "$@"
  else docker compose -p "$project" -f "$file" "$@"; fi
}
# The placeholder image is pinned by digest in the Compose file, the one place that names it (round 16,
# admin-r16-9): read the default from there instead of keeping a floating tag of our own.
bb="${PLACEHOLDER_IMAGE:-$(sed -n 's/.*\${PLACEHOLDER_IMAGE:-\([^}]*\)}.*/\1/p' "$file" | head -n 1)}"
[ -n "$bb" ] || fail "the Compose file has no default for PLACEHOLDER_IMAGE"

# 1. From each web container, api and admin are unreachable. The web image may
# be the placeholder (busybox: nc) or the Next.js image (node); use what exists.
probe() { # service host port
  if dc exec -T "$1" sh -c 'command -v node' >/dev/null 2>&1; then
    dc exec -T "$1" node -e "const s=require('net').connect({host:'$2',port:$3,timeout:2000});s.on('connect',()=>process.exit(0));s.on('error',()=>process.exit(1));s.on('timeout',()=>process.exit(1))"
  else
    dc exec -T "$1" nc -z -w 2 "$2" "$3"
  fi
}
# A probe that fails because the container is down or has no nc/node proves
# nothing. Each web container must first reach itself on its own port; only
# then does a refusal to api and admin mean the network is closed.
for web in web-panel web-admin; do
  probe "$web" 127.0.0.1 3000 >/dev/null 2>&1 || fail "$web cannot connect to its own port 3000; the isolation probe would prove nothing"
done
for web in web-panel web-admin; do
  for target in "api 8080" "admin 8081"; do
    set -- $target
    if probe "$web" "$1" "$2" >/dev/null 2>&1; then fail "$web can connect to $1:$2"; fi
  done
done
# Caddy, on the other hand, must reach both: the split must not cut the front door.
for target in "api 8080" "admin 8081"; do
  set -- $target
  dc exec -T caddy sh -c "nc -z -w 2 $1 $2" >/dev/null 2>&1 || fail "caddy cannot reach $1:$2"
done

# 2. No default route on app and web.
for net in app web; do
  routes=$(docker run --rm --network "${project}_${net}" "$bb" ip route)
  if echo "$routes" | grep -q '^default'; then fail "network ${project}_${net} has a default route: $routes"; fi
done
# 3. Only caddy may speak for a client (review round 3, admin-r3-13). api and admin
# listen on every interface of app and backend, so hub, worker or a compromised
# neighbour could reach them with a forged X-Forwarded-For. In production they accept a request
# from caddy's address alone (httpx.ClientIP, strict) and answer 400 to every other peer BEFORE
# they read the header, so a neighbour gets 400 with and without the header. The probe is a
# throw-away busybox on each network, standing for a neighbour; the positive control is the
# same request from caddy, which must get the service's own answer (200 for the panel's public
# config, 401 for the admin's /me without a session).
#
# What proves that a neighbour's 400 came from the service and not from a probe that missed it
# (a wrong network name, a name that did not resolve, a proxy in the way): the response carries
# the X-Request-Id header, which the service's own middleware sets before it checks the peer, and
# nothing else on the path does. Round 8 (admin-r8-5): the first version of this control expected
# the service's 200 or 401 from the neighbour's bare request, which a strict service never gives,
# so the script failed on every run whether or not the isolation held.
panel_host="${CTRLZ_PANEL_HOST:-panel.localhost}"
admin_host="${CTRLZ_ADMIN_HOST:-admin.localhost}"
status_of() { # prints the HTTP status of the last response line, or none
  awk '/^ *HTTP\//{c=$2} END{print (c == "" ? "none" : c)}'
}
# statuses_of reads the output of a probe that made two requests with a line "---" between them
# and prints, for each, its status ("none" for no response line) and whether the response carried
# the service's X-Request-Id header (yes or no): "400 yes 400 yes".
statuses_of() {
  awk 'BEGIN{n=0} /^---/{n++} /^ *HTTP\//{c[n]=$2} tolower($0) ~ /^ *x-request-id:/{r[n]=1} END{
    print (c[0]==""?"none":c[0]), (r[0]?"yes":"no"), (c[1]==""?"none":c[1]), (r[1]?"yes":"no")}'
}
for target in "api 8080 $panel_host /api/v1/auth/config 200" "admin 8081 $admin_host /api/v1/me 401"; do
  set -- $target
  svc="$1"; port="$2"; host="$3"; path="$4"; want="$5"
  got=$(dc exec -T caddy wget -S -q -O /dev/null --header "Host: $host" --header "X-Forwarded-For: 203.0.113.9" "http://$svc:$port$path" 2>&1 | status_of)
  [ "$got" = "$want" ] || fail "caddy got $got from $svc:$port$path, want $want; the control for the neighbour probe failed"
  for net in app backend; do
    # One throw-away container makes both requests: the bare one (no X-Forwarded-For) and the
    # forged one. Both must get 400 from the service, and both responses must carry its
    # X-Request-Id: a 400 without it came from somewhere else, and a failed `docker run` (no
    # busybox image offline, a wrong network name), a name that did not resolve and a refused
    # connection all printed "none", which was once accepted as a pass, so a service that trusted
    # every peer again passed whenever the probe never reached it (round 5, admin-r5-12; the same
    # class as admin-r1-11). The bare request must be 400 too: a strict service refuses the peer
    # whatever it sends, and a service that answered it 200 or 401 would be taking a client address
    # from a neighbour (round 8, admin-r8-5).
    # A raw request over nc and not wget: busybox wget stops at the status line of a 4xx or 5xx
    # ("server returned error") and never prints the headers, so with wget the X-Request-Id of a
    # 400 could not be seen and this check failed on every real run (round 8, found by the first
    # full run of the Compose smoke; the stand-in docker of the lint test had assumed that wget -S
    # prints headers). nc prints the whole response, and Connection: close ends it.
    probe="printf 'GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n' | nc -w 3 $svc $port 2>&1; echo ---; printf 'GET $path HTTP/1.1\r\nHost: $host\r\nX-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n' | nc -w 3 $svc $port 2>&1"
    out=$(docker run --rm --network "${project}_${net}" "$bb" sh -c "$probe" 2>&1 || true)
    set -- $(echo "$out" | statuses_of)
    bare="$1"; bare_rid="$2"; forged="$3"; forged_rid="$4"
    [ "$bare_rid" = yes ] && [ "$forged_rid" = yes ] || fail "the neighbour probe on $net got no answer of the service (X-Request-Id missing: bare $bare, forged $forged) from $svc:$port$path; the probe does not reach the service, so it proves nothing"
    [ "$bare" = 400 ] || fail "a neighbour on $net got $bare from $svc:$port$path without X-Forwarded-For, want 400; only caddy may speak for a client"
    [ "$forged" = 400 ] || fail "a neighbour on $net got $forged from $svc:$port$path with a forged X-Forwarded-For, want 400; only caddy may speak for a client"
  done
done
echo "compose-net-test: ok"
