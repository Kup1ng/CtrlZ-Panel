#!/bin/sh
# The network checks of spec 17.2, on a running stack:
#   - a web container cannot connect to api:8080 or admin:8081, by name or by any address they hold
#     (round 18 fix gate, admin-r18-19: a name does not resolve across networks, so only an address proves isolation);
#   - a neighbour on app or backend (hub, worker, a compromised container) gets 400
#     from api and admin whatever it sends, with or without X-Forwarded-For, because
#     they take a client address from caddy alone;
#   - the app and web networks have no default route (they are internal), so
#     api and admin, which sit on app and backend only, have no way out;
#   - each Valkey server is on a network of its own with its one service, and nothing else can open
#     a connection to either (rule 29; round 17, admin-r17-1).
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
# admin-r16-9) and as a literal there, with no variable to override it (round 17, admin-r17-6): read it from
# there. Every docker run below says --pull never, so what it starts is a reference that is on the machine
# (the stack that is running used it), and a missing one is an error and not a pull of whatever a tag now is.
bb=$(awk '/^  web-panel:/ {f=1; next} f && /^    image:/ {print $2; exit}' "$file")
[ -n "$bb" ] || fail "the Compose file has no image for web-panel"
docker image inspect "$bb" >/dev/null 2>&1 || docker pull -q "$bb" >/dev/null || fail "the placeholder image $bb is not on this machine and could not be pulled"

# Addresses are read from Docker's own state (round 18 fix gate, admin-r18-19): see step 4 c) for why a refusal by
# name alone proves nothing.
svc_ip() { # service network -> the IPv4 address of the service's container on that network
  zcid=$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$1" | head -n 1)
  [ -n "$zcid" ] || fail "no running container of $1 in the project $project; the address probe would prove nothing"
  zip=$(docker inspect -f "{{with index .NetworkSettings.Networks \"${project}_$2\"}}{{.IPAddress}}{{end}}" "$zcid" 2>/dev/null || true)
  case "$zip" in
    [0-9]*.[0-9]*.[0-9]*.[0-9]*) echo "$zip" ;;
    *) fail "$1 has no IPv4 address on the network $2 ($zip); the address probe would prove nothing" ;;
  esac
}
svc_ips() { # service -> every IPv4 address of the service's container, on every network it is attached to, one line
  scid=$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$1" | head -n 1)
  [ -n "$scid" ] || fail "no running container of $1 in the project $project; the address probe would prove nothing"
  sips=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$scid" 2>/dev/null || true)
  case "$sips" in
    [0-9]*.[0-9]*.[0-9]*.[0-9]*) echo $sips ;;
    *) fail "$1 has no IPv4 address ($sips); the address probe would prove nothing" ;;
  esac
}
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
# The same refusal by ADDRESS (admin-r18-19). Docker's embedded DNS has no entry for api or admin on the web
# network, so the probe above fails at resolution whether or not the address is routable: with the isolation chains
# flushed (or a daemon without inter-bridge isolation) it passes while a compromised Next.js server can still talk to
# the admin API by IP. Every address api and admin hold, on every network they are on, is probed from each web
# container, with the control that caddy (which shares the app network with both) connects to the app address.
for target in "api 8080" "admin 8081"; do
  set -- $target
  tsvc="$1"; tport="$2"
  tips=$(svc_ips "$tsvc")
  for ip in $tips; do
    for web in web-panel web-admin; do
      if probe "$web" "$ip" "$tport" >/dev/null 2>&1; then fail "$web can connect to $tsvc at its address $ip:$tport; the name check cannot see a missing network isolation"; fi
    done
  done
  appip=$(svc_ip "$tsvc" app)
  dc exec -T caddy sh -c "nc -z -w 2 $appip $tport" >/dev/null 2>&1 || fail "caddy cannot reach $tsvc at its address $appip:$tport on app; the address probe would prove nothing"
done
# Caddy, on the other hand, must reach both: the split must not cut the front door.
for target in "api 8080" "admin 8081"; do
  set -- $target
  dc exec -T caddy sh -c "nc -z -w 2 $1 $2" >/dev/null 2>&1 || fail "caddy cannot reach $1:$2"
done

# 2. No default route on app and web.
for net in app web; do
  routes=$(docker run --pull never --rm --network "${project}_${net}" "$bb" ip route)
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
    out=$(docker run --pull never --rm --network "${project}_${net}" "$bb" sh -c "$probe" 2>&1 || true)
    set -- $(echo "$out" | statuses_of)
    bare="$1"; bare_rid="$2"; forged="$3"; forged_rid="$4"
    [ "$bare_rid" = yes ] && [ "$forged_rid" = yes ] || fail "the neighbour probe on $net got no answer of the service (X-Request-Id missing: bare $bare, forged $forged) from $svc:$port$path; the probe does not reach the service, so it proves nothing"
    [ "$bare" = 400 ] || fail "a neighbour on $net got $bare from $svc:$port$path without X-Forwarded-For, want 400; only caddy may speak for a client"
    [ "$forged" = 400 ] || fail "a neighbour on $net got $forged from $svc:$port$path with a forged X-Forwarded-For, want 400; only caddy may speak for a client"
  done
done
# 4. The two Valkey servers are zones of their own (rule 29, round 16, admin-r16-6, -7, -13). Each has an internal
# network shared with its one service and with nobody else, so the worker, the hub, Postgres, ClickHouse and the
# other zone cannot open one of its 512 client slots with no credential. The Compose lints read network NAMES
# from the YAML (TestComposeNetworks); this is what Docker routes, which a later edit (an alias, vk_api on the
# worker, valkey-admin on backend) would change without touching the table (round 17, admin-r17-1). Two proofs,
# and a control so that the second cannot pass by probing nothing:
#   a) the containers attached to each zone network are exactly that zone's server and its service;
#   b) a throw-away container on every OTHER network of the stack cannot connect to either server by its
#      service name, while one on the zone's own network can (the control: the probe reaches a server when it
#      is allowed to).
# Two things made b) pass without proving anything (round 17 fix gate, admin-r17-14): `docker run` answered a
# missing network, a missing image or a busy daemon with its own failure status, which the probe read as "cannot
# connect", and the list of networks was a typed copy of the Compose file, so a network added later was never
# probed. The probe now prints the status of nc itself on a line of its own (a run that printed none is an error,
# not an answer), and the networks are what Docker has for this Compose project, read from its label.
zone_members() { # network -> the compose services attached, sorted, one line
  docker ps --filter "network=${project}_$1" --format '{{.Label "com.docker.compose.service"}}' | sort | tr '
' ' '
}
[ "$(zone_members vk_api)" = "api valkey-api " ] || fail "the network vk_api holds [$(zone_members vk_api)], want exactly api and valkey-api"
[ "$(zone_members vk_admin)" = "admin valkey-admin " ] || fail "the network vk_admin holds [$(zone_members vk_admin)], want exactly admin and valkey-admin"
reach() { # network host -> 0 when nc connected, 1 when it did not; a probe that did not run at all stops the script
  rout=$(docker run --pull never --rm --network "${project}_$1" "$bb" sh -c "nc -z -w 2 $2 6379 >/dev/null 2>&1; echo rc=\$?" 2>&1) || rout=${rout:-"(no output)"}
  rrc=$(printf '%s\n' "$rout" | sed -n 's/^rc=\([0-9][0-9]*\)$/\1/p' | tail -n 1)
  [ -n "$rrc" ] || fail "the Valkey probe on $1 toward $2 did not run to its end ($rout); a probe that did not run proves nothing"
  [ "$rrc" = 0 ]
}
stack_networks=$(docker network ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}' | sed -n "s/^${project}_//p" | sort)
for zone in vk_api vk_admin; do
  case " $(echo $stack_networks) " in *" $zone "*) ;; *) fail "Docker has no network $zone for the project $project (found: $(echo $stack_networks)); the Valkey probe would prove nothing" ;; esac
done
reach vk_api valkey-api || fail "a container on vk_api cannot connect to valkey-api; the Valkey probe would prove nothing"
reach vk_admin valkey-admin || fail "a container on vk_admin cannot connect to valkey-admin; the Valkey probe would prove nothing"
for net in $stack_networks; do
  [ "$net" = vk_api ] && continue
  if reach "$net" valkey-api; then fail "a container on $net can connect to valkey-api; only the api's zone network may"; fi
done
for net in $stack_networks; do
  [ "$net" = vk_admin ] && continue
  if reach "$net" valkey-admin; then fail "a container on $net can connect to valkey-admin; only the admin's zone network may"; fi
done
# c) (round 18, admin-r18-14) the same refusal by ADDRESS. Docker's embedded DNS has no name for a service on a
# network the prober is not on, so b) by name fails at resolution whether or not the address is routable: on a
# daemon with no inter-bridge isolation (iptables off, a firewall that flushed the isolation chains, a network that
# shares a route) it would pass, and a compromised worker or hub connects by IP, not by name. So each server's
# address on its zone network is read from Docker and every other network of the project is probed toward it,
# with the control that the zone's own network reaches it by that address too.
api_ip=$(svc_ip valkey-api vk_api)
admin_ip=$(svc_ip valkey-admin vk_admin)
reach vk_api "$api_ip" || fail "a container on vk_api cannot connect to valkey-api at $api_ip; the address probe would prove nothing"
reach vk_admin "$admin_ip" || fail "a container on vk_admin cannot connect to valkey-admin at $admin_ip; the address probe would prove nothing"
for net in $stack_networks; do
  [ "$net" = vk_api ] || if reach "$net" "$api_ip"; then fail "a container on $net can connect to valkey-api at its address $api_ip; only the api's zone network may, and the name check cannot see a missing network isolation"; fi
  [ "$net" = vk_admin ] || if reach "$net" "$admin_ip"; then fail "a container on $net can connect to valkey-admin at its address $admin_ip; only the admin's zone network may, and the name check cannot see a missing network isolation"; fi
done
echo "compose-net-test: ok"
