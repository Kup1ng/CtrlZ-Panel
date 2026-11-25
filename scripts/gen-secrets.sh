#!/bin/sh
# Create the Docker secret files the Compose stack reads. Safe to run again:
# an existing file is never overwritten, because replacing a database password
# in a file does not change it in the database. The values are never printed.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
dir="${1:-$here/secrets}"
umask 077
mkdir -p "$dir"

new_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-48
  else
    head -c 64 /dev/urandom | base64 | tr -d '\n=+/' | cut -c1-48
  fi
}

# Which root the key files belong to is PROVED here, not guessed (review round 5, rule
# key-identity; spec 8.3). Every run derives the key files again from kek_root in the
# throwaway container and compares: `ctrlz keys derive` refuses, writing nothing,
# when a file's newest key is not one this root derives. That covers the three ways
# a root and its files come apart: the host copy of kek_root was deleted after a
# backup (the installer says it may be), a wrong backup was put back, and a root was
# made again. This script never looks at whether a kek_ file is there or not to decide.
#
# A root that is missing is made here, but it is kept only if the derive wrote key files
# with it: with key files already present it cannot accept it, and a failure of any kind
# (a refusal or a daemon that is down) stops the run with the directory as it was A deliberate new root (the backup is lost too, spec 8.5) is
# asked for by name, CTRLZ_NEW_KEK_ROOT=1. The existing key files then stay as they
# are, the command says they are not derived from the new root, and every domain is
# rotated onto it with: ctrlz keys derive --rotate D --new-root.

# The derive needs the image, and Compose will not start without the secret files,
# so the image comes first. Plain docker build reads no Compose secrets, so it can
# be built before any secret exists. Checked before anything is created.
image="${CTRLZ_IMAGE:-ctrlz/panel:dev}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "secrets: image $image not found; run: docker build -f deploy/docker/Dockerfile -t $image ." >&2
  exit 1
fi

# kek_root (spec 8.1): 32 raw random bytes, the one secret a backup needs. It
# stays on the host as 0400 and no container mounts it. Never overwritten.
root="$dir/kek_root"
root_made=0
root_gone=0
if [ -e "$root" ]; then
  [ "$(wc -c < "$root" | tr -d " ")" -eq 32 ] || { echo "secrets: $root is not 32 bytes; restore it, or move it and every key file away" >&2; exit 1; }
else
  if command -v openssl >/dev/null 2>&1; then
    openssl rand 32 > "$root" || true
  else
    head -c 32 /dev/urandom > "$root" || true
  fi
  if [ "$(wc -c < "$root" | tr -d " ")" -ne 32 ]; then
    rm -f "$root"
    echo "secrets: could not generate kek_root" >&2
    exit 1
  fi
  chmod 0400 "$root"
  root_made=1
fi

# kek_<domain> files (spec 8.3): derived from the root by the Panel binary in a
# throwaway container, so the root is in a process list of nobody. The command writes
# a missing file, proves an existing one against the root and writes nothing at all
# when one is refused. The container runs as the host user because the directory is
# 0700 for that user while the image's own user is 65532. The files are written 0444,
# the rule for every secret here. On Windows (Git Bash) Docker needs a Windows path
# for the mount.
mount="$dir"
if command -v cygpath >/dev/null 2>&1; then mount=$(cygpath -m "$dir"); fi
derive_flags=""
if [ "${CTRLZ_NEW_KEK_ROOT:-}" = 1 ]; then derive_flags="--new-root"; fi
# How many entries the directory holds before the derive. Only used to tell, after a failure,
# whether the derive wrote anything: a root made in this run belongs to the files it wrote with
# it, and to nothing else (review round 5, admin-r5-6). It is a count and not a look at any key
# file: which root a file belongs to is the derive's proof (above), and this is only the
# bookkeeping of a run that failed.
entries_before=$(ls -A "$dir" 2>/dev/null | wc -l | tr -d ' ')
rc=0
# shellcheck disable=SC2086 # the flag list is empty or one fixed word
MSYS_NO_PATHCONV=1 docker run --pull never --rm --network none --read-only --cap-drop ALL \
  --user "$(id -u):$(id -g)" -v "$mount:/secrets" "$image" keys derive $derive_flags >/dev/null || rc=$?
if [ "$rc" -ne 0 ]; then
  # A root made in this run is kept only if the derive wrote files with it, since only then do
  # files belong to it and the next run proves them again. A refusal (exit 3: the files are not
  # this root's), a Docker failure (the daemon is down, the image does not run, the process was
  # killed: 125, 137 and so on) and any other end that wrote nothing all leave a random root
  # that owns nothing and would sit beside the old files looking like the real one, so it is
  # taken away and the directory is as the run found it. What decides is whether the directory
  # grew, not the exit code, which no list of codes keeps complete: a kill after the first file
  # was written exits 137 like a kill before it.
  if [ "$root_made" -eq 1 ]; then
    entries_after=$(ls -A "$dir" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$entries_after" = "$entries_before" ]; then rm -f "$root"; root_gone=1; fi
  fi
  # The one refusal that is not a failure of this run (review round 13, admin-r13-6): kek_root is
  # not on this host and the key files that are there are another root's. That is where an install
  # is after the owner moved kek_root off the server as the last line below advises, and the plain
  # secrets below do not depend on the root. Stopping here made every upgrade that adds a secret
  # file (valkey_password_api in round 6 was one) impossible without putting the root key back on
  # the internet-facing host. The derive proved nothing was wrong, only that it could not prove the
  # files without the root, so the run says so and carries on. A root that is there and wrong (a
  # wrong backup) is still a failure, and so is an explicit new root: those are the operator's act.
  if [ "$rc" -eq 3 ] && [ "$root_made" -eq 1 ] && [ "${root_gone:-0}" -eq 1 ] && [ -z "$derive_flags" ]; then
    echo "secrets: kek_root is not on this host, so the key files were not checked against it (spec 8.3). None of them is missing (the derive exits 4, and this run stops, when one is, because a key file is made only from the root that owns the rest). Put the backed-up kek_root back for a run that rotates, checks or adds key files; the other secrets below do not need it" >&2
  elif [ "$rc" -eq 4 ]; then
    # The refusal above with a key file missing as well (admin-r14-7). Carrying on would end in a
    # success line and a stack that fails at `docker compose up` on a secret that was never made.
    echo "secrets: a key file is missing and kek_root, which would make it, is not the one that owns the other key files (the derive printed which). Put the backed-up kek_root back and run this again (spec 8.4 step 1); if it is lost for good, run this again with CTRLZ_NEW_KEK_ROOT=1 (spec 8.5)" >&2
    exit 1
  else
    echo "secrets: keys derive failed (exit $rc). If kek_root was deleted or is the wrong backup, put the backed-up kek_root back (spec 8.4 step 1); if the backup is lost too, run this again with CTRLZ_NEW_KEK_ROOT=1 and rotate every domain onto the new root (spec 8.5)" >&2
    exit 1
  fi
fi

made=0
# A root made in this run counts only while it is still there: a run that took it back made none.
[ "$root_made" -eq 1 ] && [ -e "$root" ] && made=1
for name in pg_superuser_password pg_migrator_password pg_tenant_password pg_hub_password \
            pg_compiler_password pg_worker_password pg_keytool_password pg_admin_password \
            clickhouse_migrator_password clickhouse_ingest_password clickhouse_api_password clickhouse_preview_password clickhouse_janitor_password \
            valkey_password_api valkey_password_admin \
            proof_key; do
  f="$dir/$name"
  if [ -e "$f" ]; then
    # Never overwritten, but an empty one is a fault to report: the stack would
    # start with a passwordless account or refuse to start, and the next run
    # would skip it again.
    [ -s "$f" ] || { echo "secrets: $f exists and is empty; delete it and run this again" >&2; exit 1; }
    continue
  fi
  # No pipefail in POSIX sh: when openssl fails the pipeline still succeeds and
  # leaves an empty file, which the next run would then keep for good. A short
  # file means the generator failed, so the file is removed and the run stops.
  if ! new_secret > "$f" || [ "$(wc -c < "$f" | tr -d " ")" -lt 32 ]; then
    rm -f "$f"
    echo "secrets: could not generate $name" >&2
    exit 1
  fi
  # Readable inside the container by whatever user the image runs as. The
  # directory itself stays private to the host's administrator.
  chmod 0444 "$f"
  made=$((made + 1))
done

# spool_key_prev (P5 3.4): the hub's previous log-sealing key during a rotation. It is EMPTY on purpose, an empty
# file meaning "no rotation is going on", so it is the one secret file this script makes empty and the one
# the loop above must not treat as a fault. scripts/rotate-spool-key.sh fills it. Never overwritten.
f="$dir/spool_key_prev"
if [ ! -e "$f" ]; then
  : > "$f"
  chmod 0444 "$f"
  made=$((made + 1))
fi

chmod 0700 "$dir"
echo "secrets: $made created in $dir"
if [ -e "$root" ]; then
  echo "secrets: copy $dir/kek_root off this server and keep it apart from the database backups; the host copy may then be deleted"
fi
