#!/bin/sh
# Computes the test and mutant matrices from the checked-out tree, then proves them.
# Run from the repository root. The proof reads the tree again and shares nothing with the
# planner, so a bug in the planner cannot vouch for itself (see .github/ci/plan/main.go).
# The matrices are written to $GITHUB_OUTPUT by the planner; a failed proof fails this
# step, and every job that needs the plan is then skipped.
#
# The proof also reads $GITHUB_OUTPUT back: the jobs run the matrices of that file, not plan.json,
# and the hop between the two is the one place a shard could drop out with the proof saying ok
# (CI review round 6, ci-r6-2). Off GitHub there is no such file and the proof reads plan.json only.
set -eu
out="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ctrlz-plan.json"
go run ./.github/ci/plan plan -out "$out"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  go run ./.github/ci/plan prove -in "$out" -outputs "$GITHUB_OUTPUT"
else
  go run ./.github/ci/plan prove -in "$out"
fi
# The plan is printed so that a run can be read afterwards without a download.
echo "::group::plan.json"
cat "$out"
echo "::endgroup::"
