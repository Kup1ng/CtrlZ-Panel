#!/bin/sh
# Runs inside the valkey container, started by start.sh, under the `maint` ACL user whose
# password exists only in the container's tmpfs: start.sh makes it from /dev/urandom, writes it to
# the ACL file and to one private file that this script reads once and deletes. Two jobs, both for round
# 13, admin-r13-5:
#
#  1. Load the limiter's Lua scripts (/etc/valkey/lua, the very files internal/ratelimit embeds).
#     The api and admin users may run EVALSHA but not EVAL, so no credential of a service can submit
#     a script of its own. SCRIPT LOAD is idempotent and cheap, so it runs every few seconds: after a
#     restart the scripts are back within one interval, and a flushed script cache heals itself.
#  2. Watch for BUSY. A script that runs past busy-reply-threshold makes every command answer BUSY.
#     With EVAL refused to the services this should not happen, but a stuck server must not outlive one
#     interval (between two passes, see below): SCRIPT KILL, and when the script has written and cannot be killed, SHUTDOWN NOSAVE, which
#     the container's restart policy turns into a fresh start (the append-only file keeps the buckets).
#
# valkey-cli exits 0 when the server answers with an error (checked on valkey/valkey:8.1: SCRIPT KILL
# with nothing running printed NOTBUSY and exited 0, an UNKILLABLE answer and a failed SCRIPT LOAD the
# same), so nothing here is decided by an exit status. Every decision reads the reply text (admin-r14-1,
# admin-r14-5); TestValkeyMaintenance* in internal/lint run the unkillable and the unloadable cases.
#
# The marker file (MAINT_MARK, in the container tmpfs) is written once every script file has loaded. The
# healthcheck waits for it, so the container is not reported healthy before the scripts are known. No
# service may depend on a healthy valkey (a Valkey outage must not stop a service, spec 17.2), so a
# service that starts first meets NOSCRIPT or a refused connection and the limiter handles it as the
# outage it is; the marker is for the operator and for `docker compose ps`.
#
# The password is a variable of this shell and is never exported: it reaches valkey-cli in REDISCLI_AUTH,
# set on that one command, so the only process that holds it in its environment is a valkey-cli that
# lives for the length of one command. internal/lint TestNoPasswordIsAnEnvironmentOfALongRunningProcess
# lets that one line stand and refuses every other command that is given an environment (an assignment
# before it or in front of any word of it, export, env, set -a, a container's -e or --env-file, a script
# given to sh -c), whatever the variable is called.
#
# The heartbeat (ALIVE_FILE, in the container tmpfs) is touched after every PONG and after every sweep batch
# the server answered with a well-formed reply, and the healthcheck of the Compose file reads its age. It
# replaces the password-less `health` user a client could sign in as with any password (admin-r16-12): the
# judge of "is the server answering" is the one party that holds the maintenance credential, and a server that
# is BUSY or stuck stops being healthy within a minute. The batches touch it too because a paced pass on a slow
# host lasts minutes, and a loop that is busy sweeping is not a loop that stopped asking.
#
# What the sweep costs the limiter. One batch is one script, and the server answers nobody while it runs. A
# batch that finishes under busy-reply-threshold never makes a client see BUSY, but it does make a limiter
# call that arrived meanwhile wait past its own 250 ms timeout (ratelimit.Config.Timeout), and then the
# limiter marks the backend down for three seconds: the classes that fail closed (the SMS ones) answer 503
# without any BUSY ever being sent, and the others fall back to their in-process bucket. So the length of a
# batch, not a key count, is what is held down:
#   - the batch size is the loop's, passed to sweep.lua, and moves with the time the last batch ran (over
#     100 ms halves it to a floor of 50, under 25 ms doubles it to a cap of 500), so the stall follows the
#     host's real clock cost: a redis.call is about a microsecond on an ordinary host and about 150 on a VM
#     whose clock read traps. The time is the one the script measures of itself with os.clock (the fifth
#     number of its reply), not the wall time of the call: that holds the start of valkey-cli and the wait in the server's
#     queue behind other clients, and a flood that loads the server would then slow the sweep down;
#   - after a batch that ran t ms the loop sleeps 4 x t before the next, so the sweep holds the server for
#     about a fifth of the time while a pass runs, whatever the host;
#   - EXCEPT under pressure: when the script reports the instance over half of its maxmemory (the sixth number)
#     the loop does not sleep and does not let the batch fall under 200 keys, unless a batch ran over 200 ms
#     (then the size follows the clock as always). Whoever fills the instance (a credential holder, or an
#     over-budget flood of limiter-shaped keys; 64 MB, noeviction, about 250 bytes a key) is heading for OOM,
#     where every limiter write fails and the SMS classes fail closed. Between half and full the limiter still
#     works, so the sweep trades some limiter latency for a faster cut-back, and the batch size bounds that
#     trade. Paced, the cut-back would be the time a pass takes to scan the 40,000 keys it keeps and then
#     delete the rest, which on a slow host is minutes;
#   - the gap between passes is the larger of MAINT_INTERVAL and the last pass's duration, but at most 30 s
#     for the part that comes from the duration. The interval is a floor and not a period: a pass that is long
#     because the host is slow must not be followed at once by another. The cap keeps the gap itself bounded;
#     it does not bound the time to cut a flood back, which is one pass (linear in the keys, see above) and the
#     gap. A pass whose last batch still reported pressure is followed by the interval alone: the instance is
#     still filling and the next pass is what makes room, so nothing sits idle for the host's sake then.
# What runs when. A pass is run inline: during it only its batches run, and the PING, the kill of a stuck
# script and the script load wait for the end of the pass, which comes at once when a batch gets any bad reply
# (a server that is BUSY answers the next batch with BUSY). Between passes they run every MAINT_INTERVAL.
#
# Every script this loop loads is in one script cache that both service users may EVALSHA from, whichever
# directory the file came from (the sweep is kept in a file of its own so that a change to the limiter
# scripts never loads it by accident, not because a service could not call it). What keeps a service from
# running the sweep is its ACL: it holds no SCAN, so the sweep stops at its first call and writes nothing.
# TestValkeyServicesCannotRunAnyLoadedScript runs every digest this loop loads under every service user.
#
# It prints one line when the scripts are first loaded and one per BUSY or failed load it acts on, and
# never a value. It also says, at most once every 30 seconds for each kind, that a sweep batch took over 200 ms
# or that a pass took over 10 s: numbers only, so an operator on a slow host sees why the limiter is slow.
set -u
user=${MAINT_USER:-maint}
port=${VALKEY_PORT:-6379}
dir=${LUA_DIR:-/etc/valkey/lua}
every=${MAINT_INTERVAL:-2}
# Whole seconds: the gap arithmetic below is in integers, and an interval of 0 would spin.
case "$every" in
'' | *[!0-9]*) every=2 ;;
esac
[ "$every" -ge 1 ] || every=1
mark=${MAINT_MARK:-/tmp/limiter-scripts-loaded}
alive=${ALIVE_FILE:-/tmp/valkey-alive}
pwfile=${MAINT_PW_FILE:-/tmp/maint.pw}
pw=$(cat "$pwfile" 2>/dev/null) || pw=
rm -f "$pwfile"
if [ -z "$pw" ]; then
	echo "valkey: the maintenance password is missing, the limiter scripts will not be loaded" >&2
	exit 1
fi
cli() { REDISCLI_AUTH=$pw valkey-cli -h 127.0.0.1 -p "$port" --user "$user" --no-auth-warning "$@"; }
sweepfile=${SWEEP_FILE:-/etc/valkey/sweep.lua}
sweepsha=
lastsweepbad=-
lastsweepsaid=0
lastbatchsaid=0
lastpasssaid=0
announced=0
lastbad=-

# now is the wall clock in milliseconds, set by ms. date is GNU in the image (%N works); a date without %N
# answers a word that is not a number, and then the clock is whole seconds, which only makes the sweep
# believe its batches are slower or faster by up to a second and so costs no safety, as the batch size is
# bounded either way.
now=0
ms() {
	now=$(date +%s%N 2>/dev/null)
	case "$now" in
	'' | *[!0-9]*) now=$(($(date +%s) * 1000)) ;;
	*) now=$((now / 1000000)) ;;
	esac
}

# pause sleeps the given number of milliseconds. The image's sleep takes fractions (checked on
# valkey/valkey:8.1: GNU coreutils); a sleep that does not falls back to whole seconds rounded up, which paces
# a little more and never less.
pause() {
	p=$1
	[ "$p" -gt 0 ] || return 0
	sleep "$((p / 1000)).$(printf '%03d' $((p % 1000)))" 2>/dev/null || sleep $(((p + 999) / 1000))
}

# due says whether a throttled line may be said again: the time of the last one is $1 (ms) and the throttle is
# 30 s. A wall clock that stepped back (a VM resumed, an NTP step) puts $1 in the future, and the line is then
# due at once: otherwise the throttle would stay shut for as long as the clock stepped back.
due() { [ $((now - $1)) -ge 30000 ] || [ "$now" -lt "$1" ]; }

# The sweep's own tuning. bsize is the keys one batch asks SCAN for, carried from batch to batch and from pass
# to pass. The bounds are sweep.lua's own (50 to 2000) narrowed: 500 is as large as the loop lets it grow, so
# a host that is fast today and loaded tomorrow is never one doubling from a long stall.
bsize=200
BSIZE_MIN=50
BSIZE_MAX=500
BSIZE_PRESSURE=200 # the least a batch asks for while the instance is over half of its memory, unless the last batch ran over PRESSURE_SLOW_MS
PRESSURE_SLOW_MS=200
SLOW_MS=100        # a batch over this halves the size
FAST_MS=25         # a batch under this doubles it
PACE=4             # sleep this many batch lengths between two batches: the sweep holds the server about a fifth of the time
PAUSE_MAX_MS=5000  # and never so long that the heartbeat of a pass goes stale (the healthcheck reads a minute)
GAP_CAP_MS=30000   # the longest the last pass's duration may stretch the gap between passes: see the header
passms=0
lastpressure=0 # the pressure flag of the last batch of the last pass
lastpressuresaid=0

# sweep runs sweep.lua batch by batch until its cursor is back at 0 (admin-r15-1, admin-r15-4). The reply
# is read as text, like every reply here: it is six numbers (cursor, the two services' kept counts, keys
# deleted, microseconds the batch ran, pressure), and anything else (an error, no answer, a script that is not
# loaded) is a failed sweep that is said once per kind. It says how many keys it deleted, at most once every
# 30 seconds, and never a key name: those carry a tenant id and a network.
# The next batch's size and the pause before it follow from the time the batch says it ran (see the header for
# why that and not the wall time), and passms is left as the length of the whole pass, pauses included, for the
# gap the caller leaves before the next. A failed pass leaves passms at 0: the loop is then back at its PING
# within one interval, which is what a server that answers a sweep with BUSY needs.
sweep() {
	[ -n "$sweepsha" ] || return 0
	cursor=0 api=0 admin=0 total=0 batches=0
	passms=0
	lastpressure=0
	ms
	passstart=$now
	while [ "$batches" -lt 20000 ]; do
		r=$(cli evalsha "$sweepsha" 0 "$cursor" "$api" "$admin" "$bsize" 2>&1)
		case "$r" in
		'' | *[!0-9\ ]*)
			if [ "$lastsweepbad" = - ]; then echo "valkey: the keyspace sweep failed"; fi
			lastsweepbad=x
			return 0
			;;
		esac
		set -- $r
		if [ "$#" != 6 ]; then
			if [ "$lastsweepbad" = - ]; then echo "valkey: the keyspace sweep answered something unexpected"; fi
			lastsweepbad=x
			return 0
		fi
		: >"$alive" # a well-formed answer: the server is answering the loop, so the heartbeat of a long pass keeps moving
		cursor=$1 api=$2 admin=$3 total=$((total + $4))
		took=$(($5 / 1000))
		pressure=$6
		lastpressure=$pressure
		batches=$((batches + 1))
		if [ "$took" -gt 200 ]; then
			ms
			if due "$lastbatchsaid"; then
				echo "valkey: a sweep batch took $took ms"
				lastbatchsaid=$now
			fi
		fi
		[ "$cursor" = 0 ] && break
		if [ "$took" -gt "$SLOW_MS" ]; then
			bsize=$((bsize / 2))
			[ "$bsize" -ge "$BSIZE_MIN" ] || bsize=$BSIZE_MIN
		elif [ "$took" -lt "$FAST_MS" ]; then
			bsize=$((bsize * 2))
			[ "$bsize" -le "$BSIZE_MAX" ] || bsize=$BSIZE_MAX
		fi
		if [ "$pressure" = 1 ]; then
			# No pause, and no small batches unless the last one was slow: the cut-back is what matters now (see the header).
			if [ "$took" -le "$PRESSURE_SLOW_MS" ] && [ "$bsize" -lt "$BSIZE_PRESSURE" ]; then bsize=$BSIZE_PRESSURE; fi
			ms
			if due "$lastpressuresaid"; then
				echo "valkey: the instance is over half of its memory, the sweep runs without pauses"
				lastpressuresaid=$now
			fi
			continue
		fi
		p=$((took * PACE))
		[ "$p" -le "$PAUSE_MAX_MS" ] || p=$PAUSE_MAX_MS
		pause "$p"
	done
	lastsweepbad=-
	ms
	passms=$((now - passstart))
	# A clock that stepped back during the pass makes it negative: no duration, so the gap is the interval.
	[ "$passms" -ge 0 ] || passms=0
	if [ "$passms" -gt 10000 ] && due "$lastpasssaid"; then
		echo "valkey: a sweep pass took $((passms / 1000)) s ($batches batches)"
		lastpasssaid=$now
	fi
	if [ "$total" -gt 0 ] && due "$lastsweepsaid"; then
		echo "valkey: the keyspace sweep deleted $total keys that no limiter script wrote or that were over a budget"
		lastsweepsaid=$now
	fi
}

# nextsweep is the time (ms) before which the loop does not start a pass: the larger of MAINT_INTERVAL and the
# last pass's duration capped at GAP_CAP_MS, counted from the end of that pass.
nextsweep=0

while :; do
	out=$(cli ping 2>&1)
	case "$out" in
	PONG) : >"$alive" ;;
	*BUSY*)
		echo "valkey: a script is holding the server, killing it"
		r=$(cli script kill 2>&1)
		case "$r" in
		*UNKILLABLE*)
			# The script has written, so Valkey will not stop it: only a restart ends it.
			echo "valkey: the script has written and cannot be killed, shutting the server down"
			cli shutdown nosave >/dev/null 2>&1
			;;
		esac
		sleep 1
		continue
		;;
	*)
		sleep 1
		continue
		;;
	esac
	# The sweep goes first: a server that is full cannot take a script load, and the sweep is what makes room.
	# It runs only when the gap since the last pass is over, so a long gap never delays the PING, the kill of
	# a stuck script or the script load. A pass itself does not PING, but a server that is BUSY answers its
	# next batch with BUSY, which ends the pass (a failed sweep) and brings the loop back here.
	ms
	# The gap is never more than the cap or the interval, so a next sweep further away than both is a wall clock
	# that stepped back (a VM resumed, an NTP step): the sweep is due now and not after the step, which would leave a
	# server that is filling unswept while the PING keeps the heartbeat fresh.
	[ $((nextsweep - now)) -le $((GAP_CAP_MS + every * 1000)) ] || nextsweep=$now
	if [ "$now" -ge "$nextsweep" ]; then
		sweep
		gap=$passms
		[ "$gap" -le "$GAP_CAP_MS" ] || gap=$GAP_CAP_MS
		[ "$gap" -ge $((every * 1000)) ] || gap=$((every * 1000))
		# A pass that ended under pressure is followed by the interval alone (see the header).
		[ "$lastpressure" != 1 ] || gap=$((every * 1000))
		ms
		nextsweep=$((now + gap))
	fi
	ok=1
	loaded=0
	bad=
	for f in "$dir"/*.lua "$sweepfile"; do
		[ -f "$f" ] || continue
		r=$(cli -x script load <"$f" 2>&1)
		# A SCRIPT LOAD that worked answers the 40 hex digits of the digest, and anything else is
		# an error reply or no reply at all.
		case "$r" in
		*[!0-9a-f]*) ok=0; bad="$bad ${f##*/}" ;;
		*)
			if [ "${#r}" = 40 ]; then
				loaded=$((loaded + 1))
				[ "$f" = "$sweepfile" ] && sweepsha=$r
			else
				ok=0; bad="$bad ${f##*/}"
			fi
			;;
		esac
	done
	# The sweep is part of what the container is healthy with: no sweep, no marker.
	[ -n "$sweepsha" ] || ok=0
	# No script file at all is a broken mount, not a loaded set.
	[ "$loaded" -gt 0 ] || ok=0
	if [ "$ok" = 0 ] && [ "$bad" != "$lastbad" ]; then
		echo "valkey: the limiter scripts did not load:${bad:- none found in $dir}"
	fi
	lastbad=$bad
	if [ "$ok" = 1 ] && [ "$announced" = 0 ]; then
		echo "valkey: the limiter scripts are loaded ($loaded files)"
		: >"$mark"
		announced=1
	fi
	sleep "$every"
done
