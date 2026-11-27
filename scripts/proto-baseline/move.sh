#!/bin/sh
# Rebuild the contract baseline that scripts/ci.sh runs 'buf breaking' against.
#
# Run this at a phase gate, after the owner has accepted the contract, and put
# the result in a commit of its own. Running it moves the line that later
# changes are measured from: whatever shared/proto says now becomes the
# released contract, and a break that is in it is forgiven for good. Never run
# it to make a failing ci.sh pass.
#
# Source info is left out so the image holds only the contract, not the
# comments and positions of the files, and the same proto always gives the same
# bytes.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
export PATH="$(go env GOPATH)/bin:$PATH"
command -v buf >/dev/null 2>&1 || { echo "move.sh: buf is not installed"; exit 1; }

out="$here/scripts/proto-baseline/image.binpb"
tmp="$out.new"
trap 'rm -f "$tmp"' EXIT
(cd "$here/shared" && buf build --exclude-source-info -o "../scripts/proto-baseline/image.binpb.new")
[ -s "$tmp" ] || { echo "move.sh: buf wrote an empty image"; exit 1; }
mv "$tmp" "$out"
echo "move.sh: wrote scripts/proto-baseline/image.binpb; commit it on its own"
