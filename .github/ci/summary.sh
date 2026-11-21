#!/bin/sh
# Writes a table of the duration of every job of this run to the job summary, so the gain
# over the local run (hours, in series) can be read off, and fails when any job of the run
# did not succeed. gh and jq are on the runner image; the token is the run's own and
# read-only, and the one call is a read of this run's job list.
#
# The workflow runs this job unless the run was cancelled (a newer push cancels the older
# run through the concurrency group); a cancelled run has no verdict to give.
set -eu
out="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
rows=$(mktemp)
gh api --paginate "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/${GITHUB_RUN_ATTEMPT:-1}/jobs?per_page=100" \
  --jq '.jobs[] | select(.name != "summary") | [.name, (.conclusion // .status), (if .completed_at then ((.completed_at|fromdateiso8601) - (.started_at|fromdateiso8601)) else 0 end), (if .started_at then (.started_at|fromdateiso8601) else 0 end), (if .completed_at then (.completed_at|fromdateiso8601) else 0 end)] | @tsv' > "$rows" || true
tab=$(printf '\t')
{
  echo "### Job durations"
  echo
  echo "| job | result | minutes |"
  echo "|---|---|---|"
  sort -t "$tab" -k3,3nr "$rows" | awk -F '\t' '{ printf "| %s | %s | %.1f |\n", $1, $2, $3/60 }'
  echo
  awk -F '\t' '
    { sum += $3; if ($4 > 0 && (lo == 0 || $4 < lo)) lo = $4; if ($5 > hi) hi = $5 }
    END { printf "Wall time (first start to last end): %.1f min. Sum of all jobs: %.1f min.\n", (hi - lo)/60, sum/60 }' "$rows"
  echo
  echo "Still owed by the local run (ci/local-only.sh in the workspace runs all of them; the IPv6 one is OPEN until a host with real IPv6 runs it):"
  echo
  echo "- the web stack, when the tree has one (it needs the HeroUI token, which is not on GitHub);"
  echo "- the workspace mutants and the tests that read the workspace documents (the expected skips listed in the shard summaries);"
  echo "- the equality of the two shared copies (it needs both repositories);"
  echo "- gitleaks over the real history (GitHub holds snapshots only);"
  echo "- the nightly timing test of a known against an unknown phone (timing.yml runs from the clock on main only, so this run does not include it; node scripts/publish.mjs timing --repo panel reads its newest verdict, and local-only.sh runs that);"
  echo "- the IPv6 source-address check of the Compose smoke against a real IPv6 client: here it only proves that a host address is seen as itself (an address added to the loopback of the runner), because a GitHub runner has no IPv6 route to connect from. A local run on a Linux host with a global IPv6 address closes it; local-only.sh says when it could not."
} >> "$out"
rm -f "$rows"

# The mutants job is skipped, legitimately, when the tree has no mutant for GitHub to run
# (the plan said so with a shard count of 0). Every other job must have succeeded.
bad=""
for pair in plan:"${PLAN_RESULT:-}" static:"${STATIC_RESULT:-}" tests:"${TESTS_RESULT:-}" mutants:"${MUTANTS_RESULT:-}" compose:"${COMPOSE_RESULT:-}" scan:"${SCAN_RESULT:-}"; do
  job=${pair%%:*}
  result=${pair#*:}
  [ "$result" = success ] && continue
  [ "$job" = mutants ] && [ "$result" = skipped ] && [ "${MUTANT_SHARDS:-}" = "0" ] && continue
  bad="$bad$job: ${result:-unknown}
"
done
if [ -n "$bad" ]; then
  echo "summary: jobs that did not succeed:"
  echo "$bad"
  exit 1
fi
echo "summary: every job succeeded"
