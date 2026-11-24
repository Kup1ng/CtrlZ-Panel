#!/bin/sh
# Installs the pinned tools the CI needs, by name:  install-tools.sh buf proto gitleaks govulncheck
#
# Every version is exact. buf and the two protobuf generators must match what scripts/ci.sh
# demands, because a generator of another version writes other bytes and shows up as a
# diff that is not a contract change; the generators' versions are read FROM scripts/ci.sh
# so the two cannot drift apart. gitleaks and govulncheck are the versions installed on the
# development machine. Installed from the repository root's parent (a temp directory) so
# that `go install pkg@version` never reads the module of the checkout.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
BUF_VERSION=v1.75.0
GITLEAKS_VERSION=v8.30.1
GOVULNCHECK_VERSION=v1.9.0

cd "${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
for tool in "$@"; do
  case "$tool" in
    buf) go install "github.com/bufbuild/buf/cmd/buf@$BUF_VERSION" ;;
    proto)
      gen=$(sed -n 's/^want_protoc_gen_go="\(.*\)"$/\1/p' "$here/scripts/ci.sh")
      grpc=$(sed -n 's/^want_protoc_gen_go_grpc="\(.*\)"$/\1/p' "$here/scripts/ci.sh")
      [ -n "$gen" ] && [ -n "$grpc" ] || { echo "install-tools: cannot read the generator versions from scripts/ci.sh" >&2; exit 1; }
      go install "google.golang.org/protobuf/cmd/protoc-gen-go@$gen"
      go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v$grpc"
      ;;
    gitleaks) go install "github.com/zricethezav/gitleaks/v8@$GITLEAKS_VERSION" ;;
    govulncheck) go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ;;
    *) echo "install-tools: unknown tool $tool" >&2; exit 1 ;;
  esac
done
gobin=$(go env GOPATH)/bin
# A later step of the same job finds the tools without a path of its own.
[ -z "${GITHUB_PATH:-}" ] || echo "$gobin" >> "$GITHUB_PATH"
echo "install-tools: ok ($*)"
