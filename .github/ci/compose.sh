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
# it. The job fails when the address cannot be added or when it would not be the one the script
# picks. A skipped check is not detected here by reading the output: the smoke is run the way
# scripts/ci.sh runs it, with CTRLZ_CI=1 and the address in CTRLZ_SMOKE_IPV6, and under CTRLZ_CI the
# smoke itself fails instead of skipping, whatever its wording (CI review round 11, ci-r11-2; a
# grep for a message that the smoke no longer printed would have read a skip as green). This is
# the proof that a host address is preserved through the published port; it is not a client on a
# real IPv6 network, which the local run owes (see summary.sh and the README).
#
# Run from the repository root, after the image is built (ctrlz/panel:dev).
set -eu
v6=fd7a:5c00:6e6e::10

sudo ip -6 addr add "$v6/128" dev lo nodad
first=$(ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n 1)
[ "$first" = "$v6" ] || { echo "compose: the first global IPv6 address is '$first', not $v6; the smoke would test another address"; exit 1; }
echo "compose: client address for the IPv6 check is $v6 (on lo)"

export CTRLZ_IMAGE="${CTRLZ_IMAGE:-ctrlz/panel:dev}"
export CTRLZ_CI=1 CTRLZ_SMOKE_IPV6="$v6"
rc=0
sh scripts/compose-smoke.sh || rc=$?
[ "$rc" = 0 ] || { echo "compose: the smoke failed ($rc)"; exit "$rc"; }
echo "compose: ok"
