#!/bin/sh
# Runs the known-versus-unknown phone timing test of spec 18.5 (internal/api/timing_test.go, build tag timing) the way
# the nightly job needs it: twice at most, judged by what the test logged, and never green for a run that took no
# samples (CI review round 13, ci-r13-1; Plan.md D64, ci-unrun-checks).
#
# The statistics are the test's: it logs the median of each side over N interleaved samples (known and unknown phone
# alternate, so drift of a shared runner hits both) and fails when the medians are 20 ms apart or more. What this
# script adds is what a shared runner needs around a hard threshold, because a flake is a finding and not an
# accepted cost:
#   - a failure is reported only when a second, independent run fails as well. A real leak is a property of the code,
#     so it fails both; a neighbour on the host that stalled one run fails one. Each attempt's medians are printed,
#     so a pattern (the same side always slower) can be told from noise.
#   - the exit status of `go test` is not the verdict by itself. A run that skipped, that matched no test, or that
#     took fewer samples than the test's default of 500 (TIMING_SAMPLES in the environment is refused) says nothing
#     about timing, and counts as a failure. The verdict is read from the "--- PASS" line and from the median line
#     that only a finished measurement prints.
#
# Each attempt has its own go test timeout, and the two together plus the setup must fit in the timeout-minutes of
# timing.yml, or a hang in the first attempt would end as a job timeout without the report below (ci-r14-2;
# workflows-r13.test.mjs reads both numbers).
#
# Run from the repository root; needs Docker (the test starts Postgres and Valkey).
set -eu
unset TIMING_SAMPLES
want=500
attempts=2
n=1
while [ "$n" -le "$attempts" ]; do
  log=$(mktemp)
  rc=0
  go test -tags timing -count=1 -v -timeout 25m -run '^TestTimingKnownAndUnknownPhone$' ./internal/api > "$log" 2>&1 || rc=$?
  med=$(grep -E 'median known .* over [0-9]+ samples each' "$log" | head -n 1 || true)
  samples=$(printf '%s' "$med" | sed -n 's/.* over \([0-9][0-9]*\) samples each.*/\1/p')
  why=""
  if [ "$rc" != 0 ]; then why="go test exited $rc"
  elif ! grep -q -- '--- PASS: TestTimingKnownAndUnknownPhone' "$log"; then why="the test did not report a pass (it was skipped, or no test matched)"
  elif [ -z "$med" ]; then why="the test passed without logging its medians, so no measurement was taken"
  elif [ "${samples:-0}" -lt "$want" ]; then why="the medians are over ${samples:-0} samples, fewer than the $want that make them a measurement"
  fi
  if [ -z "$why" ]; then
    echo "timing: attempt $n passed: $med"
    rm -f "$log"
    exit 0
  fi
  echo "timing: attempt $n failed: $why"
  [ -z "$med" ] || echo "timing: attempt $n measured: $med"
  tail -n 25 "$log" | sed 's/^/  | /'
  rm -f "$log"
  n=$((n + 1))
done
echo "timing: failed in $attempts independent runs, so it is not noise of the runner: a known phone is told from an unknown one by timing, or the test cannot run" >&2
exit 1
