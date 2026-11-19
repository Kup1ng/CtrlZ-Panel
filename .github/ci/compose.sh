#!/bin/sh
# The Compose smoke of scripts/ci.sh, run on a GitHub runner, with the IPv6 check made real.
#
# Why it is not just `sh scripts/compose-smoke.sh`. That script ends with a check that an
# IPv6 client reaches the admin service under its own address and not as Docker's gateway
# (review round 3, admin-r3-10): the per-network login limits and the audit IP depend on it.
# It takes the first `scope global` IPv6 address of the host as the client. A GitHub runner
# has none, so the check would print that it is skipped and the job would stay green; and
# once the stack is up, the first such address could be the gateway address of the Compose
# IPv6 bridge, which would then be "seen" as itself by construction. Neither says anything.
#
# So the runner is given a client address that is not Docker's: a unique-local address on the
# loopback device. Loopback is interface 1, so it comes first in `ip -6 addr` whatever Docker
# creates later; the check then connects from that address and the admin service must record
# it. The job fails when the address cannot be added, when it would not be the one the script
# picks, or when the script says the check was skipped. This is the proof that a host address
# is preserved through the published port; it is not a client on a real IPv6 network, which
# the local run owes (see summary.sh and the README).
#
# Run from the repository root, after the image is built (ctrlz/panel:dev).
set -eu
v6=fd7a:5c00:6e6e::10

sudo ip -6 addr add "$v6/128" dev lo nodad
first=$(ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n 1)
[ "$first" = "$v6" ] || { echo "compose: the first global IPv6 address is '$first', not $v6; the smoke would test another address"; exit 1; }
echo "compose: client address for the IPv6 check is $v6 (on lo)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export CTRLZ_IMAGE="${CTRLZ_IMAGE:-ctrlz/panel:dev}"
# No pipefail in POSIX sh: the exit status goes through a file.
{ sh scripts/compose-smoke.sh && echo 0 > "$work/rc" || echo "$?" > "$work/rc"; } 2>&1 | tee "$work/out"
rc=$(cat "$work/rc")
[ "$rc" = 0 ] || { echo "compose: the smoke failed ($rc)"; exit "$rc"; }
if grep -q "IPv6 source-address check is skipped" "$work/out"; then
  echo "compose: the smoke skipped its IPv6 source-address check, which this job may not do"
  exit 1
fi
echo "compose: ok"
