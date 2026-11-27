#!/bin/sh
# Copies Ctrl Z Panel/shared to Ctrl Z Node/shared and proves the copies match.
# No logic here: everything is in shared/cmd/sharedtool. Extra arguments (for
# example --force) are passed through.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
node="$here/../Ctrl Z Node/shared"
exec go -C "$here/shared" run ./cmd/sharedtool sync --from "$here/shared" --to "$node" "$@"
