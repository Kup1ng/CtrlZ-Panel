#!/bin/sh
# The start line of one Valkey zone, run by the valkey-api and valkey-admin services of docker-compose.yml
# (round 16, admin-r16-6, -7, -12, -13). It lived in the Compose file when there was one Valkey; it is a file
# now because both zones run the same text and only VK_ZONE tells them apart.
#
# Why two instances. The api faces the internet and the admin is meant to be a zone of its own, but one
# Valkey gave them one maxmemory and one set of 512 client slots, so a holder of ANY credential or any
# container on the backend network could keep both limiters failing: fill the instance faster than the
# sweep, or hold every slot. Valkey has no per-user memory or connection quota, so the only boundary that
# closes it is a process each. Each zone has its own server, its own maxmemory, its own ACL with ONE
# service user, its own volume and its own internal network shared with that one service and nobody else
# (the worker, the hub, Postgres and ClickHouse cannot reach either).
#
# One ACL user per zone, written into a private file in a tmpfs at start, so no password appears in the
# process arguments (printf is a shell builtin). Each user may touch only the keys of its own limiter
# (ctrlz:rl:<zone>:*) and only the commands its Lua scripts and its connection handshake use: no FLUSHALL,
# CONFIG, KEYS, SCAN, DEBUG. Neither service may run EVAL or load a script (round 13, admin-r13-5): key
# patterns limit what a script touches and not how long it runs, so one EVAL "while true do end" held every
# command BUSY for every tenant until somebody restarted Valkey by hand. The limiter's scripts are loaded at
# start by maintain.sh, which signs in as a user whose password only this container has, and the services run
# them with EVALSHA. maintain.sh also kills a script that holds the server (SCRIPT KILL, then SHUTDOWN NOSAVE).
#
# Key patterns bind only commands that name a key. SCAN, KEYS and RANDOMKEY name none, so a user that holds
# one lists every key of the instance (round 7, admin-r7-6). The admin limiter keeps a sorted set of its own
# keys (ctrlz:rl:admin:index, written by its scripts with ZADD and trimmed with ZREMRANGEBYSCORE) and
# `ctrlz-admin unlock` reads that set (ZRANGE), UNLINKs the keys and ZREMs them.
#
# There is no password-less user (admin-r16-12). The `health` user of the earlier layout let any client that
# reached the port sign in with any password, and being signed in lifts the limits Valkey puts on a client that
# is not; one connection that trickled a partial bulk kept memory over maxmemory and the sweep, which walks
# keys, could not see it. The default user is off and nobody else is on, so a client that is not one of the
# zone's two users is refused before it can send anything of size. The healthcheck asks maintain.sh, which
# signs in as the maintenance user: the loop touches /tmp/valkey-alive after every PONG, so a stuck server
# stops being healthy within a minute.
#
# TestValkeyACLUsersKeepToTheirOwnKeys applies this very file to a real Valkey.
set -eu
umask 077
zone=${VK_ZONE:?VK_ZONE is not set}
case "$zone" in
api | admin) ;;
*)
	echo "valkey: VK_ZONE must be api or admin" >&2
	exit 1
	;;
esac
# The maintenance user's password is made here, kept in this shell and written to one file of the tmpfs, which
# maintain.sh reads once and deletes (it holds the value in a shell variable and gives it to each valkey-cli on
# that command alone, never to a long-running process: admin-r14-8). It is in no file of the host and no secret,
# so no service can sign in as that user.
maint_pw=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
# The service's password is read INSIDE the printf argument of its own ACL line and kept in no shell variable
# (round 16, admin-r16-21): a variable that held it was a second place where the secret lived, and the lint
# of the Compose secrets (TestComposeSecretsStayOutOfArgumentsAndEnvironments) follows a secret by the lines
# that name its path, so every later use of the variable was invisible to it. With no variable there is
# nothing to follow, and a line that reads the secret in any other shape is refused by that lint. The read
# drops the CR LF a secret file may end in, as the clients do.
#
# An empty secret (a truncated file, or one of only CR LF) stops the start, as it does in the ClickHouse
# wrapper (admin-r16-22): `user api on > ~...` is a user with an EMPTY password, and a client that signs in
# as it with an empty password is accepted, while Valkey starts and nothing fails.
if [ -z "$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")" ]; then
	echo "valkey: the password file of the zone is empty or unreadable; not starting" >&2
	exit 1
fi
{
	printf 'user default off\n'
	printf 'user maint on >%s ~ctrlz:rl:* -@all +ping +script|load +script|kill +shutdown +evalsha +scan +type +pttl +hlen +zcard +memory|usage +unlink\n' "$maint_pw"
	case "$zone" in
	api) printf 'user api on >%s ~ctrlz:rl:api:* -@all +hello +auth +reset +client|setinfo +client|setname +evalsha +time +hmget +hset +pexpire\n' "$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")" ;;
	admin) printf 'user admin on >%s ~ctrlz:rl:admin:* -@all +hello +auth +reset +client|setinfo +client|setname +evalsha +time +hmget +hset +pexpire +zadd +zremrangebyscore +zrange +zrem +unlink\n' "$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")" ;;
	esac
} > /tmp/users.acl
# Loglevel is warning, so this is the one line a healthy start prints, and it names no value.
echo "valkey: the ACL file is written, starting the server"
printf '%s' "$maint_pw" > /tmp/maint.pw
MAINT_USER=maint sh /etc/valkey/maintain.sh &
exec valkey-server /etc/valkey/valkey.conf --aclfile /tmp/users.acl --maxmemory "${VK_MAXMEMORY:-64mb}"
