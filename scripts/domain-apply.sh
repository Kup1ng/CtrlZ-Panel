#!/bin/sh
# Apply a domain change on the server (spec p4-nodes 10.4). Run it by hand after the admin saved a new panel host, admin
# host or zone, or uploaded a new panel or admin certificate: the old hosts keep serving until it runs.
#
# What it does, in this order:
#   1. runs the one-shot `domain-apply` (role ctrlz_domain_apply): it picks the hosts and the certificates, writes the
#      certificate pairs and the Caddy snippets into the Caddy data volume and prints the new .env on its standard
#      output. It changes no database row;
#   2. checks that output and renames it over deploy/compose/.env (the old file is kept as .env.prev, and only when the
#      .env really changes). The container runs as the Caddy user and reads the .env read-only, so the file is replaced
#      here, by the user who owns it, with one rename;
#   3. runs `domain-apply --commit`: it checks the new .env and the snippets hold what it plans, then sets the applied_*
#      columns. Those columns are what the api's Host gate reads, so they move only now, after the .env is in place. The
#      old .env is mounted beside it, so a host nobody requested is read from the file the first run read. The old .env is
#      put back only when the commit says (exit code 3) that it recorded nothing: a host nobody requested is the .env's
#      own, and a later run must not read the refused one as the host that works. Any other failure leaves the outcome
#      unknown (a lost answer, a dropped link): the commit is asked once more, it is safe to repeat, and if that does not
#      answer either the NEW .env stays, since the columns may name it, and the script says to run it again. INT, TERM and
#      HUP are ignored from the rename until the outcome is known, so a stop cannot put the old .env back over columns that
#      moved;
#   4. recreates caddy, web-panel, api and admin together, so the Host gates, Caddy and the web tier change at one moment;
#   5. runs `domain-apply --prune`: only now, with the old containers gone, are the files nothing reads any more removed,
#      the old host's private key among them. A failure here is only reported: the next run removes them.
#
# A failure before step 3 leaves the database, the running containers and the files they read as they were (the new pair
# and snippet files are written beside the old ones, and no run removes an old one before step 5). A refusal in step 3
# puts the old .env back; a step 3 whose outcome is unknown keeps the new .env and the script says to run it again. A failure in step 4 leaves the new .env and the recorded hosts, with some of the old
# containers possibly still running: running the script again repairs it, it is safe to repeat.
# The stack must be up (the one-shot reaches the database over the compose network and the Caddy volume must exist).
set -eu
umask 077
here=$(cd "$(dirname "$0")/.." && pwd)
dir="$here/deploy/compose"
cd "$dir"

die() { echo "domain-apply: $*" >&2; exit 1; }

[ "$#" -eq 0 ] || { echo "usage: domain-apply.sh" >&2; exit 2; }
[ -f .env ] || die "deploy/compose/.env is missing: run scripts/select-profile.sh first"

# One run at a time: two would write the same files and race on the rename. The name matches the .env.* ignore rule.
if command -v flock >/dev/null 2>&1; then
  exec 9>"$dir/.env.domain-apply.lock"
  flock -n 9 || die "another domain-apply is running"
fi

new=$(mktemp "$dir/.env.new.XXXXXX")
# swapped is 1 from the rename on and says the .env was replaced (the commit mounts the old one only then). asked is 1 from
# the moment the commit is first asked for: from then on the columns may name the new host, so only the exit code 3 of the
# one-shot (nothing recorded) may put the old .env back, never an exit of this script, whatever ended it (R34-r4-3).
swapped=0
asked=0
restore() {
  swapped=0
  # The diagnostics may fail on a hung-up tty; under set -e that must not end the script before the file is back.
  if mv -f .env.prev .env; then
    echo "domain-apply: the previous .env was put back" >&2 || true
  else
    echo "domain-apply: could not put the previous .env back: copy .env.prev over .env by hand" >&2 || true
  fi
}
onexit() {
  # Before the commit is asked for, a failed rename or a stop records nothing: the old .env goes back.
  if [ "$swapped" = 1 ] && [ "$asked" = 0 ]; then restore; fi
  rm -f "$new"
}
trap onexit EXIT
# A signal must end the script: a trap that only removes the file would let the run go on to the rename with a partial one.
trap 'exit 1' INT TERM HUP
# After the commit has been asked for, a stop may leave the hosts recorded: say so.
stopped() { echo "domain-apply: stopped; the hosts may already be recorded: run this script again" >&2 || true; exit 1; }
# The copy keeps the owner and mode of the .env; the redirect below truncates it and fills it.
cp -p .env "$new"

# stdout is the new .env and nothing else (compose writes its progress to stderr). --no-deps: the stack is up, and a run
# must not start the migrator again.
docker compose --profile tools run --rm -T --no-deps domain-apply >"$new"

# Refuse an output that is not a .env before it replaces one: empty, without the layout marker, or with a line that is
# neither a comment, a blank line nor an assignment. The one-shot refuses the same shapes before it writes a file
# (internal/domainapply envLineShape): keep the two expressions equal.
[ -s "$new" ] || die "the one-shot printed no .env; nothing was replaced"
grep -q '^CTRLZ_ENV_FORMAT_2=' "$new" || die "the printed .env lacks the layout marker; nothing was replaced"
if grep -v -E '^(#.*|[A-Za-z_][A-Za-z0-9_]*=.*|)$' "$new" | grep -q .; then
  die "the printed .env has a line that is not an assignment; nothing was replaced"
fi

# An unchanged .env (a certificate change only, or the run after a failed recreate) is not replaced, and .env.prev keeps
# the file the last real change replaced.
if ! cmp -s .env "$new"; then
  # No stop from here until the commit's outcome is known: a signal handled after a commit that went through would put the
  # old .env back over columns that name the new host. The docker client may still die with the link (a Go program
  # installs its own handler even over an inherited ignore), but the container it started commits on its own, and the exit
  # code of a client that died is never 3: it counts as an unknown outcome and the new .env stays.
  trap '' INT TERM HUP
  cp -p .env .env.prev
  swapped=1
  mv "$new" .env
fi

# The columns move only now. No output is expected from this call. When the script replaced the .env, the old file is mounted
# beside the new one for the commit (the one-shot looks for /compose/.env.prev), so a host nobody requested is judged from
# the file the first run read.
commit() {
  if [ "$swapped" = 1 ]; then
    docker compose --profile tools run --rm -T --no-deps -v "$dir/.env.prev:/compose/.env.prev:ro" \
      domain-apply domain-apply --commit >/dev/null
  else
    docker compose --profile tools run --rm -T --no-deps domain-apply domain-apply --commit >/dev/null
  fi
}
# An unchanged .env has nothing to put back, but a stop may still leave the hosts recorded: say so.
[ "$swapped" = 1 ] || trap stopped INT TERM HUP
# Exit code 3 of the one-shot is "nothing was recorded" (internal/domainapply exitNothingRecorded); only then does the old
# .env go back (R34-r3-2).
rc=0
asked=1
commit || rc=$?
if [ "$rc" -eq 3 ]; then
  restore
  die "the applied hosts were not recorded; run this script again"
fi
if [ "$rc" -ne 0 ]; then
  echo "domain-apply: the commit ended without a clear answer; asking once more" >&2 || true
  rc=0
  commit || rc=$?
  if [ "$rc" -ne 0 ]; then
    # The columns may name the new host, so the new .env stays: the next run repairs it, and the old one would not.
    swapped=0
    trap stopped INT TERM HUP
    die "the applied hosts may or may not be recorded and the new .env stays; run this script again"
  fi
fi
swapped=0
trap stopped INT TERM HUP

docker compose up -d --force-recreate --no-deps caddy web-panel api admin \
  || die "the hosts are recorded but the services were not recreated; run this script again"
# The old containers are gone: what only they read can go now. Nothing depends on it, so a failure is a warning.
docker compose --profile tools run --rm -T --no-deps domain-apply domain-apply --prune >/dev/null \
  || echo "domain-apply: warning: stale certificate files were not removed; the next run removes them" >&2
echo "domain-apply: done; the previous .env is kept as .env.prev"
