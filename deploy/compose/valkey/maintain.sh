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
#     interval: SCRIPT KILL, and when the script has written and cannot be killed, SHUTDOWN NOSAVE, which
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
# The heartbeat (ALIVE_FILE, in the container tmpfs) is touched after every PONG, and the healthcheck of the
# Compose file reads its age. It replaces the password-less `health` user a client could sign in as with any
# password (admin-r16-12): the judge of "is the server answering" is the one party that holds the maintenance
# credential, and a server that is BUSY or stuck stops being healthy within a minute.
#
# Every script this loop loads is in one script cache that both service users may EVALSHA from, whichever
# directory the file came from (the sweep is kept in a file of its own so that a change to the limiter
# scripts never loads it by accident, not because a service could not call it). What keeps a service from
# running the sweep is its ACL: it holds no SCAN, so the sweep stops at its first call and writes nothing.
# TestValkeyServicesCannotRunAnyLoadedScript runs every digest this loop loads under every service user.
#
# It prints one line when the scripts are first loaded and one per BUSY or failed load it acts on, and
# never a value.
set -u
user=${MAINT_USER:-maint}
port=${VALKEY_PORT:-6379}
dir=${LUA_DIR:-/etc/valkey/lua}
every=${MAINT_INTERVAL:-2}
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
announced=0
lastbad=-

# sweep runs sweep.lua batch by batch until its cursor is back at 0 (admin-r15-1, admin-r15-4). The reply
# is read as text, like every reply here: it is four numbers, and anything else (an error, no answer, a
# script that is not loaded) is a failed sweep that is said once per kind. It says how many keys it
# deleted, at most once every 30 seconds, and never a key name: those carry a tenant id and a network.
sweep() {
	[ -n "$sweepsha" ] || return 0
	cursor=0 api=0 admin=0 total=0 batches=0
	while [ "$batches" -lt 4000 ]; do
		r=$(cli evalsha "$sweepsha" 0 "$cursor" "$api" "$admin" 2>&1)
		case "$r" in
		'' | *[!0-9\ ]*)
			if [ "$lastsweepbad" = - ]; then echo "valkey: the keyspace sweep failed"; fi
			lastsweepbad=x
			return 0
			;;
		esac
		set -- $r
		if [ "$#" != 4 ]; then
			if [ "$lastsweepbad" = - ]; then echo "valkey: the keyspace sweep answered something unexpected"; fi
			lastsweepbad=x
			return 0
		fi
		cursor=$1 api=$2 admin=$3 total=$((total + $4))
		batches=$((batches + 1))
		[ "$cursor" = 0 ] && break
	done
	lastsweepbad=-
	if [ "$total" -gt 0 ]; then
		now=$(date +%s)
		if [ $((now - lastsweepsaid)) -ge 30 ]; then
			echo "valkey: the keyspace sweep deleted $total keys that no limiter script wrote or that were over a budget"
			lastsweepsaid=$now
		fi
	fi
}

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
	sweep
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
