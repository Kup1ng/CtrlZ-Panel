#!/bin/sh
# The job "tests (lab)": shared/ built with the tag ctrlz_lab, the build the P4 fault tests run on a
# private network, and whatever of the root module that tag changes. The release jobs (static, tests)
# never build a file with that tag, so without this job shared/netclass/lab_test.go and the lab cases of
# the golden vectors (ptv-050, ptv-052, ptv-053 of shared/vectors) would run in no job, and the release
# cases of the same vectors (ptv-049, ptv-051) skip here, by design, and run in `static` (shardrun
# accepts the skips of each build only in that build). gofiles.sh knows the tag set from its own table
# and refuses a job whose GOFLAGS names another one. The same script, with the same table, is the Node's.
#
# Why it does not run the whole root module again: the Panel's tests start Postgres and Valkey and take
# the better part of an hour in eight shards, and the tag changes nothing for the packages that hold no
# lab file. So the root module is built and vetted under the tag (a lab file that does not compile is
# found by every branch), and its tests run only for the packages whose file list differs between the
# lab build and the default one. Today that is none, and the step says so and does nothing; the planner
# (.github/ci/plan: prove) still refuses a lab-tagged *test* file of the root module, so the first one
# comes with the change that teaches it, and then this step is what runs it.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
"$here/scripts/go-pin-check.sh"
# Exported for every go command below, shardrun's own go run included: the helper has no build tag of
# its own, so it compiles the same.
export GOFLAGS=-tags=ctrlz_lab
cd "$here"
sh .github/ci/gofiles.sh "$here/shared" "$here"
go -C shared build ./...
go -C shared vet ./...
go build ./...
go vet ./...
go run ./.github/ci/shardrun module shared

# The packages of the root module whose Go files (code or tests) differ under the tag.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fmt='{{.ImportPath}} {{join .GoFiles ","}} {{join .TestGoFiles ","}} {{join .XTestGoFiles ","}}'
GOFLAGS= go list -f "$fmt" ./... | sort >"$tmp/release"
go list -f "$fmt" ./... | sort >"$tmp/lab"
mod=$(go list -m)
packages=""
for ip in $(comm -13 "$tmp/release" "$tmp/lab" | awk '{ print $1 }'); do
  rel=.
  [ "$ip" = "$mod" ] || rel=./${ip#"$mod"/}
  packages="$packages${packages:+,}\"$rel\""
done
if [ -z "$packages" ]; then
  echo "lab: the root module has no file that only the tag ${GOFLAGS#-tags=} builds; its tests stay with the release jobs"
  echo "lab: ok"
  exit 0
fi
# A packages shard, judged like the ones of `tests`: every test the packages declare must have a result, and a skip that is
# not on the list of by-design skips fails. The packages may start containers, so the environment is the one of a test
# shard (the reaper is off, the host-dependent tests fail instead of skipping).
export CTRLZ_CI=1 TESTCONTAINERS_RYUK_DISABLED=true
SHARD_JSON="{\"id\":\"lab-root\",\"kind\":\"packages\",\"packages\":[$packages],\"parallel\":2,\"timeout_minutes\":40}" go run ./.github/ci/shardrun tests
echo "lab: ok"
