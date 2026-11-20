# .github/ci

Helpers of `.github/workflows/ci.yml`. The long explanation, with what stays local and why,
is `ci/github/README.md` of the owner's workspace; this is the short map.

| file | job | what it is |
|---|---|---|
| `plan.sh`, `plan/main.go` | `plan` | `plan` cuts the tree into test and mutant shards; `prove` recomputes the universe and fails unless every package, every `internal/api` test and every mutant is in exactly one shard and the rest shard names exactly the tests it must run (the mutants left to the local run are named); `local-mutants` prints their ids |
| `shardrun/main.go` | `tests`, `mutants`, `static` | runs one shard (or, with `module <dir>`, a whole Go module) and fails it unless everything it was given has a result of the right kind; repeats a measuring guard that skips as noise; writes skips and timings to the job summary |
| `static.sh` | `static` | the part of `scripts/ci.sh` before the image build |
| `gofiles.sh` | `static` | fails on a `_test.go` file that go leaves out on the runner (a GOOS suffix, a build tag) in `shared/`, which the planner does not prove, and on any `go.mod` other than the root's and `shared/`'s; the same file as in the Node overlay (run as `gofiles.sh <module> <repository root>`) |
| `compose.sh` | `compose smoke` | the Compose smoke with an IPv6 client address added to the runner, run under `CTRLZ_CI=1` and `CTRLZ_SMOKE_IPV6` so the smoke itself fails instead of skipping its IPv6 check |
| `install-tools.sh` | `static`, `scan` | `go install` of buf, the two protobuf generators (versions read from `scripts/ci.sh`), gitleaks and govulncheck at exact versions |
| `summary.sh` | `summary` | table of job durations, and a failure if any job failed |
| `weights.json` | `plan` | estimated seconds per package, to balance the shards; refresh it from the "Slowest packages" tables of a run |

The directory starts with a dot, so `./...` never matches it: `go list ./...`, `go vet ./...`
and the test partition do not see these programs. Run them by path, for example
`go run ./.github/ci/plan prove -in plan.json`.

`static.sh` is a copy of part of `scripts/ci.sh`. A change to the static part of `ci.sh`
must be made there as well.
