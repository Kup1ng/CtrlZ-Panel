#!/bin/sh
# Local CI for the Panel repository. Fails on the first problem.
#   scripts/ci.sh          everything, including the container tests (needs Docker)
#   scripts/ci.sh -short   skip the tests that start Postgres
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
short=""
[ "${1:-}" = "-short" ] && short="-short"
gobin=$(go env GOPATH)/bin

# The host compiler must be the one go.mod pins, before anything is judged with it.
"$here/scripts/go-pin-check.sh"

# The shared module, which both repositories carry an identical copy of.
"$here/scripts/shared-verify.sh"
go -C "$here/shared" build ./...
go -C "$here/shared" vet ./...
go -C "$here/shared" test ./...

# The wire contract (contract section 16): the proto files, the generated code
# under shared/gen and the previous contract must agree. None of this is
# optional: a missing tool must not read as a clean result.
#
# The generators are pinned to the versions named in the headers of shared/gen.
# A different version writes different bytes, so a version drift would show up
# as a diff that is not a contract change.
want_protoc_gen_go="v1.36.12"
want_protoc_gen_go_grpc="1.6.2"
export PATH="$gobin:$PATH"
for tool in buf protoc-gen-go protoc-gen-go-grpc; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "ci: $tool is not installed; the proto checks cannot run (see README, Before the first commit)"
    exit 1
  }
done
have=$(protoc-gen-go --version | awk '{print $NF}')
[ "$have" = "$want_protoc_gen_go" ] || { echo "ci: protoc-gen-go is $have, want $want_protoc_gen_go"; exit 1; }
have=$(protoc-gen-go-grpc --version | awk '{print $NF}')
[ "$have" = "$want_protoc_gen_go_grpc" ] || { echo "ci: protoc-gen-go-grpc is $have, want $want_protoc_gen_go_grpc"; exit 1; }

(cd "$here/shared" && buf lint)

# Generate into a temporary directory and compare with what is committed, so a
# .proto edit without regeneration cannot pass.
gen_tmp=$(mktemp -d)
trap 'rm -rf "$gen_tmp"' EXIT
(cd "$here/shared" && buf generate --output "$gen_tmp")
diff -r "$gen_tmp/gen" "$here/shared/gen" >"$gen_tmp/diff.txt" || {
  echo "ci: shared/gen differs from what buf generate writes; run 'buf generate' in shared and commit the result"
  head -n 40 "$gen_tmp/diff.txt"
  exit 1
}

# Breaking changes, against a committed image of the released contract. A git
# ref would not do: the commit before the last proto change forgets a break one
# commit later, and a shallow checkout has no earlier commit at all. The image
# moves only when scripts/proto-baseline/move.sh is run on purpose. It is the
# baseline for a clean tree and a dirty one alike, and a missing or empty one
# fails the run: there is no way to skip the check.
baseline="$here/scripts/proto-baseline/image.binpb"
[ -s "$baseline" ] || {
  echo "ci: $baseline is missing or empty; buf breaking has nothing to compare with (see README, Before the first commit)"
  exit 1
}
# A valid image that holds no files would let everything through.
[ -n "$(cd "$here/shared" && buf ls-files ../scripts/proto-baseline/image.binpb)" ] || {
  echo "ci: the baseline image holds no proto files"
  exit 1
}
(cd "$here/shared" && buf breaking --against ../scripts/proto-baseline/image.binpb)

# The Panel module.
cd "$here"
test -z "$(gofmt -l cmd internal tools migrations)" || { echo "gofmt: run gofmt -w"; gofmt -l cmd internal tools migrations; exit 1; }
go run ./tools/genmig -check
go build ./...
# The server code of both APIs is generated from the OpenAPI documents (spec 2.2).
# Regenerate into a temporary file and compare, so a document edit without
# `go generate` cannot pass. Line endings are ignored: a checkout on Windows may
# convert them, and the content is what matters.
for p in api adminapi; do
  spec="api/openapi.yaml"
  [ "$p" = "adminapi" ] && spec="api/admin-openapi.yaml"
  out=$(mktemp)
  go tool oapi-codegen -config "internal/$p/oapi.yaml" -o "$out" "$spec"
  tr -d '\r' <"$out" >"$out.a"
  tr -d '\r' <"internal/$p/gen/api.gen.go" >"$out.b"
  if ! cmp -s "$out.a" "$out.b"; then
    rm -f "$out" "$out.a" "$out.b"
    echo "ci: internal/$p/gen/api.gen.go is stale; run 'go generate ./internal/$p' and commit the result"
    exit 1
  fi
  rm -f "$out" "$out.a" "$out.b"
done
go vet ./...
# Production is Ubuntu and development is Windows, so vet both.
GOOS=linux go vet ./...
# The image is built from this tree BEFORE the tests: TestImageSmoke inspects whatever
# ctrlz/panel:dev is on the machine, and an image left from an earlier run (built by an
# older Go, say) failed it in the full run after the Go bump while the code was right.
# The Compose smoke below reuses the same image.
image="${CTRLZ_IMAGE:-ctrlz/panel:dev}"
if [ -z "$short" ]; then
  docker build -q ${GOPROXY:+--build-arg GOPROXY="$GOPROXY"} -f "$here/deploy/docker/Dockerfile" -t "$image" "$here" >/dev/null
  export CTRLZ_IMAGE="$image"
fi
# -count=1: container tests must run, not be replayed from the cache.
# -timeout: catalogtest alone took 19 minutes on a loaded machine, past the
# default 10 minutes per package, and a killed package reads as a test failure.
# The budget is a variable because the biggest package keeps growing: internal/api took
# 33 minutes alone (round 9, 14 oracle states of about 100 s each, which sit in real
# time floors and the Argon2 gate) and ran into 40 minutes at -p 4 on a loaded machine,
# panicking with a test that was only 6 s in. Nothing hung; the budget was too small.
# Raise it again here, not per test: the oracle states must not be made parallel, as
# they compare durations and contention would manufacture differences.
# -p: each container package starts its own Postgres (and Valkey); at the default
# of one package per CPU Docker Desktop timed out starting them (A7). Raise it on
# a bigger machine with CTRLZ_TEST_PACKAGES.
# CTRLZ_CI makes a test that needs something of the host (a second address) fail and not skip, so a
# host that lacks it cannot read as a pass (rule 28, admin-r12-2).
export CTRLZ_CI=1
go test -count=1 -timeout "${CTRLZ_TEST_TIMEOUT:-100m}" -p "${CTRLZ_TEST_PACKAGES:-4}" $short ./...

# Rule tests-that-cannot-fail (P1 auth review, round 5): break the code with each edit of
# mutants.yaml in a scratch copy of the tree and require the named tests to fail. A mutant
# that survives, does not apply or does not compile fails the build. With -short the
# mutants whose tests start containers are left out, as the container tests are above.
go run ./tools/mutants -j "${CTRLZ_MUTANT_JOBS:-3}" $short

# The Compose smoke (spec 18.4) is the one run of compose-net-test.sh and of the secret canary on a
# real production-mode stack. Neither script ran in CI, and compose-net-test.sh could not pass at
# all for a round (admin-r8-5) without anybody noticing. It needs Docker and the image, so with
# -short it is left out, as the container tests are.
if [ -z "$short" ]; then
  CTRLZ_IMAGE="$image" sh "$here/scripts/compose-smoke.sh"
fi

# Neither gate is optional: a missing tool must not read as a clean result.
"$gobin/gitleaks" git --no-banner --redact --log-level=warn "$here"
"$gobin/govulncheck" -C "$here" ./...
"$gobin/govulncheck" -C "$here/shared" ./...
