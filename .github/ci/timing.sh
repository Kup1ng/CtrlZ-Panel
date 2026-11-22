#!/bin/sh
# Runs the known-versus-unknown phone timing tests of spec 18.5 (internal/api/timing_test.go, build tag timing) the way
# the nightly job needs it: each test twice at most, judged by what it logged, and never green for a run that took no
# samples (CI review round 13, ci-r13-1; Plan.md D64, ci-unrun-checks).
#
# WHICH tests run comes from the tree, not from this file (ci-r22-1): the tests that only the build tag timing builds
# are `go test -tags timing -list` minus `go test -list`. A test added to timing_test.go is therefore run tonight, and
# one that has no rule below makes this script fail instead of being left out. The rules below say what a measurement of
# each test is; `plan prove` fails the build of a tree whose timing-only tests are not all named in this file, so the
# omission is found by the run of the commit that adds the test and not by the nightly job.
#
# The statistics are the tests': each logs the median of each side over N interleaved samples (known and unknown phone
# alternate, so drift of a shared runner hits both) and fails when the medians are 20 ms apart or more. What this
# script adds is what a shared runner needs around a hard threshold, because a flake is a finding and not an
# accepted cost:
#   - a failure is reported only when a second, independent run of the same test fails as well. A real leak is a
#     property of the code, so it fails both; a neighbour on the host that stalled one run fails one. Each attempt's
#     medians are printed, so a pattern (the same side always slower) can be told from noise.
#   - the exit status of `go test` is not the verdict by itself. A run that skipped, that matched no test, or that
#     took fewer samples than the test's default (TIMING_SAMPLES in the environment is refused) says nothing about
#     timing, and counts as a failure. The verdict is read from the "--- PASS" line of that very test and from the
#     median lines that only a finished measurement prints; the fewest samples of any of them is judged.
#
# Each attempt has its own go test timeout, and every attempt of every test plus the setup must fit in the
# timeout-minutes of timing.yml, or a hang in one attempt would end as a job timeout without the report below
# (ci-r14-2; workflows-r13.test.mjs reads these numbers).
#
# Run from the repository root; needs Docker (the tests start Postgres and Valkey).
set -eu
unset TIMING_SAMPLES
LC_ALL=C
export LC_ALL # sort and comm must agree on the order
attempts=2
# test:samples. The samples are the default of the test itself: the password login takes 500 per side; the oracle
# routes take 100 per route and per load, and run for a quarter of an hour on their floors (300 and 500 ms per request).
rules="TestTimingKnownAndUnknownPhone:500 TestTimingKnownAndUnknownPhoneOnEveryOracleRoute:100"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
list() { # list [go test flags]: the names of the tests of internal/api, one per line (the planner's own definition of a test; -short keeps TestMain from starting Postgres just to print names, the list is the same)
  out=$(go test -short "$@" -count=1 -list '.*' ./internal/api) || { echo "timing: go test -list $* failed" >&2; exit 1; }
  printf '%s\n' "$out" | grep -E '^(Test|Fuzz|Example)[A-Za-z0-9_]*$' | sort || true
}
list > "$tmp/default"
list -tags timing > "$tmp/tagged"
comm -13 "$tmp/default" "$tmp/tagged" > "$tmp/tests"
if [ ! -s "$tmp/tests" ]; then
  echo "timing: go test -tags timing lists no test that the default build lacks, so there is nothing to measure and a green run would mean nothing" >&2
  exit 1
fi
want_of() { for r in $rules; do [ "${r%%:*}" = "$1" ] && { echo "${r#*:}"; return 0; }; done; return 1; }
bad=0
while read -r t; do
  want_of "$t" > /dev/null || { echo "timing: $t only builds with the tag timing and has no rule in rules= of .github/ci/timing.sh (how many samples make it a measurement)" >&2; bad=1; }
done < "$tmp/tests"
for r in $rules; do
  grep -qx "${r%%:*}" "$tmp/tests" || { echo "timing: rules= names ${r%%:*}, which the tag timing does not add to the tests of internal/api" >&2; bad=1; }
done
[ "$bad" = 0 ] || exit 1

failed=0
while read -r t; do
  want=$(want_of "$t")
  n=1
  passed=0
  while [ "$n" -le "$attempts" ]; do
    log="$tmp/log"
    rc=0
    go test -tags timing -count=1 -v -timeout 25m -run "^$t\$" ./internal/api > "$log" 2>&1 < /dev/null || rc=$?
    meds=$(grep -E 'median known .* over [0-9]+ samples each' "$log" || true)
    med=$(printf '%s\n' "$meds" | head -n 1)
    samples=$(printf '%s\n' "$meds" | sed -n 's/.* over \([0-9][0-9]*\) samples each.*/\1/p' | sort -n | head -n 1)
    why=""
    if [ "$rc" != 0 ]; then why="go test exited $rc"
    elif ! grep -q -- "^--- PASS: $t " "$log"; then why="the test did not report a pass (it was skipped, or no test matched)"
    elif [ -z "$meds" ]; then why="the test passed without logging its medians, so no measurement was taken"
    elif [ "${samples:-0}" -lt "$want" ]; then why="the medians are over ${samples:-0} samples, fewer than the $want that make them a measurement"
    fi
    if [ -z "$why" ]; then
      echo "timing: $t attempt $n passed: $med"
      passed=1
      break
    fi
    echo "timing: $t attempt $n failed: $why"
    [ -z "$meds" ] || printf '%s\n' "$meds" | sed "s/^/timing: $t attempt $n measured: /"
    tail -n 25 "$log" | sed 's/^/  | /'
    n=$((n + 1))
  done
  if [ "$passed" = 0 ]; then
    echo "timing: $t failed in $attempts independent runs, so it is not noise of the runner: a known phone is told from an unknown one by timing, or the test cannot run" >&2
    failed=1
  fi
done < "$tmp/tests"
exit "$failed"
