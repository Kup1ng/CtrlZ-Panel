#!/bin/sh
# The static half of scripts/ci.sh: everything that runs before the image is built.
# Same checks, same failure messages. It is a copy, so a change to that part of ci.sh must
# be made here too; the generator versions are the exception, read from ci.sh itself.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
gobin=$(go env GOPATH)/bin
export PATH="$gobin:$PATH"

# The host compiler must be the one go.mod pins, before anything is judged with it.
"$here/scripts/go-pin-check.sh"

# The shared module, which both repositories carry an identical copy of. Only one copy is
# here: the equality of the two is checked by the local run, which has both repositories.
"$here/scripts/shared-verify.sh"
# A _test.go file of shared that go leaves out on this runner (a _windows_test.go name, a build
# tag) is run by no job: the planner proves the test files of the root module only, and
# `shardrun module shared` judges only what `go list ./...` lists, so such a test would run
# nowhere and the run would stay green (CI review round 7, ci-r7-2). gofiles.sh is one file in both
# overlays (identical_overlay_files in ci/publish.json).
sh "$here/.github/ci/gofiles.sh" "$here/shared" "$here"
go -C "$here/shared" build ./...
go -C "$here/shared" vet ./...
# Not a bare `go test`: shardrun reads the -json result, so a test of shared that skips (the
# linear-time guard of shared/quarantine gives up on a noisy host) is repeated and, if it
# still cannot measure, fails the job instead of reading as a pass. Only the regeneration
# switches may skip.
(cd "$here" && go run ./.github/ci/shardrun module shared)

want_protoc_gen_go=$(sed -n 's/^want_protoc_gen_go="\(.*\)"$/\1/p' "$here/scripts/ci.sh")
want_protoc_gen_go_grpc=$(sed -n 's/^want_protoc_gen_go_grpc="\(.*\)"$/\1/p' "$here/scripts/ci.sh")
[ -n "$want_protoc_gen_go" ] && [ -n "$want_protoc_gen_go_grpc" ] || { echo "ci: cannot read the generator versions from scripts/ci.sh"; exit 1; }
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
have=$(buf --version)
[ "$have" = "1.75.0" ] || { echo "ci: buf is $have, want 1.75.0"; exit 1; }

(cd "$here/shared" && buf lint)

# Generate into a temporary directory and compare with what is committed.
gen_tmp=$(mktemp -d)
trap 'rm -rf "$gen_tmp"' EXIT
(cd "$here/shared" && buf generate --output "$gen_tmp")
diff -r "$gen_tmp/gen" "$here/shared/gen" >"$gen_tmp/diff.txt" || {
  echo "ci: shared/gen differs from what buf generate writes; run 'buf generate' in shared and commit the result"
  head -n 40 "$gen_tmp/diff.txt"
  exit 1
}

# Breaking changes, against the committed image of the released contract.
baseline="$here/scripts/proto-baseline/image.binpb"
[ -s "$baseline" ] || {
  echo "ci: $baseline is missing or empty; buf breaking has nothing to compare with (see README, Before the first commit)"
  exit 1
}
[ -n "$(cd "$here/shared" && buf ls-files ../scripts/proto-baseline/image.binpb)" ] || {
  echo "ci: the baseline image holds no proto files"
  exit 1
}
(cd "$here/shared" && buf breaking --against ../scripts/proto-baseline/image.binpb)

# The Panel module.
cd "$here"
test -z "$(gofmt -l cmd internal tools migrations)" || { echo "gofmt: run gofmt -w"; gofmt -l cmd internal tools migrations; exit 1; }
go run ./tools/genmig -check
# A published migration is frozen (rules.md rule 27, db-r16-28): the manifest may only grow against the copy the
# last published snapshot carried. scripts/ci.sh runs this when CTRLZ_EARLIER_MANIFEST is set, because it is the
# publisher that passes it there. Here the snapshot has no history, so the publisher always writes the copy as
# .github/ci/earlier-applied.sum and publishes nothing without one (scripts/publish.mjs, earlierManifest); a run
# that lacks the file fails and does not skip, since a guard that quietly looks at nothing is what db-r16-28 was.
earlier="$here/.github/ci/earlier-applied.sum"
[ -s "$earlier" ] || { echo "static: $earlier is missing or empty, so the manifest cannot be compared with an earlier copy"; exit 1; }
go run ./tools/genmig -against "$earlier"
go build ./...
# The server code of both APIs is generated from the OpenAPI documents (spec 2.2).
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
# Production is Ubuntu and development is Windows, so vet both. The runner is Ubuntu, so
# the plain vet is the linux one.
go vet ./...
GOOS=windows go vet ./...
echo "static: ok"
