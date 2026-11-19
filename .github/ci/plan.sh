#!/bin/sh
# Computes the test and mutant matrices from the checked-out tree, then proves them.
# Run from the repository root. The proof reads the tree again and shares nothing with the
# planner, so a bug in the planner cannot vouch for itself (see .github/ci/plan/main.go).
# The matrices are written to $GITHUB_OUTPUT by the planner; a failed proof fails this
# step, and every job that needs the plan is then skipped.
set -eu
out="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ctrlz-plan.json"
go run ./.github/ci/plan plan -out "$out"
go run ./.github/ci/plan prove -in "$out"
# The plan is printed so that a run can be read afterwards without a download.
echo "::group::plan.json"
cat "$out"
echo "::endgroup::"
