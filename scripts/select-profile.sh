#!/bin/sh
# Write deploy/compose/.env from the detected RAM (R37): the "small" profile
# below 12 GB, "standard" from there up. Pass small or standard to force one.
# An existing .env is kept unless --force is given.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
dir="$here/deploy/compose"
profile=""
force=0
for a in "$@"; do
  case "$a" in
    --force) force=1 ;;
    small|standard) profile="$a" ;;
    *) echo "usage: select-profile.sh [small|standard] [--force]" >&2; exit 2 ;;
  esac
done
if [ -z "$profile" ]; then
  kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  if [ "$kb" -eq 0 ]; then
    echo "cannot read /proc/meminfo; pass small or standard" >&2
    exit 1
  fi
  # 12 GB in kB. The plan's floor is 8 GB, which lands in "small".
  if [ "$kb" -lt 12582912 ]; then profile=small; else profile=standard; fi
fi
if [ -e "$dir/.env" ] && [ "$force" -ne 1 ]; then
  echo ".env exists; use --force to replace it" >&2
  exit 1
fi
{
  cat "$dir/.env.example"
  echo
  echo "# --- profile: $profile (profiles/$profile.env) ---"
  cat "$dir/profiles/$profile.env"
} > "$dir/.env"
echo "profile: $profile -> $dir/.env"
