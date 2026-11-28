#!/bin/sh
# Verifies this copy of shared against its CHECKSUMS, and against the Node copy
# when the two repositories sit side by side. No logic here.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
node="$here/../Ctrl Z Node/shared"
if [ -d "$node" ]; then
  exec go -C "$here/shared" run ./cmd/sharedtool verify "$here/shared" "$node"
fi
exec go -C "$here/shared" run ./cmd/sharedtool verify "$here/shared"
