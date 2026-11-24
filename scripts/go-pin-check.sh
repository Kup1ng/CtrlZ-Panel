#!/bin/sh
# Fails unless the compiler this shell would use is the one go.mod pins.
# The Go version has one source of truth, the `go` line of go.mod (review round 8,
# go-bump findings c3 and s2). internal/lint/goversion_test.go ties the files to
# it; this script ties the HOST compiler to it, so govulncheck and the tests
# judge the toolchain that ships. GOTOOLCHAIN=local is forced: with "auto" a
# go.mod ahead of the installed Go would silently download a toolchain from the
# module proxy, which needs international internet and is an unrecorded fetch.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
want=$(awk '$1=="go" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ {print $2; exit}' "$here/go.mod")
[ -n "$want" ] || { echo "go-pin-check: no go X.Y.Z line in go.mod" >&2; exit 1; }
for mod in "$here/shared/go.mod"; do
  [ -f "$mod" ] || continue
  got=$(awk '$1=="go" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ {print $2; exit}' "$mod")
  [ "$got" = "$want" ] || { echo "go-pin-check: $mod says go $got, go.mod says $want" >&2; exit 1; }
done
have=$(GOTOOLCHAIN=local go env GOVERSION)
[ "$have" = "go$want" ] || { echo "go-pin-check: the installed compiler is $have, go.mod pins go$want (install it; do not rely on a toolchain download)" >&2; exit 1; }
echo "go-pin-check: ok (go$want)"
