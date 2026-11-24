# .github/ci

Helpers of `.github/workflows/ci.yml` and `.github/workflows/timing.yml`. The long explanation, with what stays local and why,
is `ci/github/README.md` of the owner's workspace; this is the short map.

| file | job | what it is |
|---|---|---|
| `plan.sh`, `plan/main.go` | `plan` | `plan` cuts the tree into test and mutant shards; `prove` recomputes the universe and fails unless every package, every `internal/api` test and every mutant is in exactly one shard and the rest shard names exactly the tests it must run (the mutants left to the local run are named); `local-mutants` prints their ids |
| `shardrun/main.go` | `tests`, `mutants`, `static` | runs one shard (or, with `module <dir>`, a whole Go module) and fails it unless everything it was given has a result of the right kind; repeats a measuring guard that skips as noise; writes skips and timings to the job summary |
| `static.sh` | `static` | the part of `scripts/ci.sh` before the image build |
| `gofiles.sh` | `static` | fails on a `_test.go` file that go leaves out on the runner (a GOOS suffix, a build tag) in `shared/`, which the planner does not prove, and on any `go.mod` other than the root's and `shared/`'s; the same file as in the Node overlay (run as `gofiles.sh <module> <repository root>`) |
| `compose.sh` | `compose smoke` | the Compose smoke with an IPv6 client address added to the runner, run under `CTRLZ_CI=1` and `CTRLZ_SMOKE_IPV6` so the smoke itself fails instead of skipping its IPv6 check |
| `install-tools.sh` | `static`, `scan` | `go install` of buf, the two protobuf generators (versions read from `scripts/ci.sh`), gitleaks and govulncheck at exact versions |
| `images.sh` | `tests`, `mutants`, `compose smoke`, `timing` | `before` lists the images of the runner, `after` fails for any image that appeared since whose digest is not pinned by the Compose file, a Dockerfile or a digest constant of the non-test Go files under `deploy/` (the reaper image `deploy.PinReaper` pulls), or that is not another name for such an image (the Panel's own build and build layers excepted); the reaper of testcontainers is switched off on the runner and this proves nothing took its place |
| `timing.sh` | `timing` (`timing.yml`) | every nightly timing test the tag adds (`-tags timing`, derived from the tree; one with no rule fails the job), each run again once before a failure is reported, and never green for a run that skipped or took fewer samples than the test's default (500, 100) |
| `summary.sh` | `summary` | table of job durations, and a failure if any job failed |
| `weights.json` | `plan` | estimated seconds per package and per mutant (`mutant_seconds`: the mutants whose gap before their `killed` line was 10 s or more in a run, 87 now; a guess at the order of the shards, see the comment in the file), to balance the shards; refresh it from the "Slowest packages" tables and the `killed` lines of a run |

The directory starts with a dot, so `./...` never matches it: `go list ./...`, `go vet ./...`
and the test partition do not see these programs. Run them by path, for example
`go run ./.github/ci/plan prove -in plan.json`.

`static.sh` is a copy of part of `scripts/ci.sh`. A change to the static part of `ci.sh`
must be made there as well.
