#!/bin/sh
# Looks for the content of every secret file of a Compose stack in the files a stack leaves behind
# (collected docker logs, database rows). The owner requires that no secret reaches a log; the Go
# canary tests run in process and never see what the Valkey start line, the ClickHouse wrapper, the
# Postgres init or the shell of any container prints, so this is the check of those (spec 18.4,
# round 8, admin-r8-6).
#
#   scripts/secret-canary.sh SECRETS_DIR SINK...
#
# A secret is looked for as the container reads it and in the forms a careless log line gives it:
#   - a text file: each line (CR removed), the last word of each line, and the whole content with
#     the line ends removed;
#   - a binary file (kek_root, 32 raw bytes): its hex in both cases, its base64 and its base64url.
# Anything shorter than 16 characters is not looked for (no secret of the stack is that short, and
# a short word would match anywhere). A match fails the run and names the secret FILE and the sink,
# never the value. An empty directory, a directory with no file long enough to look for and a sink
# that does not exist fail too: a check that looked at nothing must not read as clean.
# Secrets that no file of SECRETS_DIR holds (round 15, admin-r15-3): CTRLZ_CANARY_RUNTIME_DIR is a second
# directory of files, each treated exactly as a secret file (the forms above, a consumer required). The
# maintenance password of Valkey is made by the container from /dev/urandom and is in no secret, so the
# check of the directory could never look for it, and a debugging echo in maintain.sh would have passed.
# The smoke reads it out of the running container into this directory.
set -eu
dir="${1:-}"
[ -n "$dir" ] && [ -d "$dir" ] || { echo "secret-canary: usage: $0 SECRETS_DIR SINK..." >&2; exit 2; }
shift
[ "$#" -gt 0 ] || { echo "secret-canary: no sink to look in" >&2; exit 2; }
for sink in "$@"; do
  [ -f "$sink" ] || { echo "secret-canary: sink $(basename "$sink") does not exist" >&2; exit 2; }
done

looked=0
found=0
reported=""
lines=$(mktemp)
trap 'rm -f "$lines"' EXIT
# look NAME FORM: fails the run when FORM is in any sink. The value never reaches the output.
look() {
  [ "${#2}" -ge 16 ] || return 0
  looked=$((looked + 1))
  for sink in $sinks; do
    if grep -aqF -- "$2" "$sink"; then
      case " $reported " in
        *" $1:$(basename "$sink") "*) ;;
        *) echo "secret-canary: the content of $1 is in $(basename "$sink")" >&2; reported="$reported $1:$(basename "$sink")" ;;
      esac
      found=1
    fi
  done
}

# The sinks as one word list: their paths come from mktemp and the caller, and hold no space.
sinks="$*"

# Who reads which secret (round 9, admin-r9-4). A secret that is looked for in the log of a container
# that never started is looked for nowhere: the first smoke started api, admin and worker only, so
# the Valkey ACL line, the ClickHouse wrapper and the Postgres init, the places the canary exists
# for, were never run and the check said ok. CTRLZ_CANARY_CONSUMERS is a file of lines
# `<secret file> <container> <its log file>`; every consumer must have logged something, and every
# secret file must have a consumer or be named in CTRLZ_CANARY_UNCONSUMED (the caller says why).
# Without the variable the script only searches, as the planted-file tests do.
silent=0
consumers="${CTRLZ_CANARY_CONSUMERS:-}"
if [ -n "$consumers" ]; then
  [ -s "$consumers" ] || { echo "secret-canary: the consumers file is missing or empty" >&2; exit 2; }
  while read -r sname cname clog; do
    [ -n "$sname" ] || continue
    if [ ! -s "$clog" ]; then
      echo "secret-canary: $cname reads $sname and its log is empty: the check of its log would look at nothing" >&2
      silent=1
    fi
  done < "$consumers"
  for f in "$dir"/* ${CTRLZ_CANARY_RUNTIME_DIR:+"$CTRLZ_CANARY_RUNTIME_DIR"/*}; do
    [ -s "$f" ] || continue
    n=$(basename "$f")
    if awk -v n="$n" '$1 == n { f = 1 } END { exit !f }' "$consumers"; then continue; fi
    case " ${CTRLZ_CANARY_UNCONSUMED:-} " in
      *" $n "*) ;;
      *) echo "secret-canary: no container of the stack reads $n, so no log was searched for it" >&2; silent=1 ;;
    esac
  done
fi

for f in "$dir"/* ${CTRLZ_CANARY_RUNTIME_DIR:+"$CTRLZ_CANARY_RUNTIME_DIR"/*}; do
  [ -f "$f" ] || continue
  name=$(basename "$f")
  [ -s "$f" ] || continue
  if [ "$name" = kek_root ]; then
    hex=$(od -An -v -tx1 "$f" | tr -d ' \n')
    look "$name" "$hex"
    look "$name" "$(printf '%s' "$hex" | tr 'a-f' 'A-F')"
    std=$(base64 < "$f" | tr -d '\n')
    look "$name" "$std"
    look "$name" "$(printf '%s' "$std" | tr '+/' '-_' | tr -d '=')"
    continue
  fi
  look "$name" "$(tr -d '\r\n' < "$f")"
  tr -d '\r' < "$f" | while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '#'*|'') continue ;; esac
    printf '%s\n' "$line"
  done > "$lines" || true
  while IFS= read -r line; do
    look "$name" "$line"
    look "$name" "${line##* }"
  done < "$lines"
done

[ "$looked" -gt 0 ] || { echo "secret-canary: nothing in $(basename "$dir") was long enough to look for; the check would be empty" >&2; exit 1; }
[ "$found" -eq 0 ] || exit 1
[ "$silent" -eq 0 ] || exit 1
echo "secret-canary: ok ($looked forms looked for)"
