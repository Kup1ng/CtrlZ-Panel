#!/bin/sh
# Writes /deps-lock.sha256 into a deps image that `deps-fresh` of deploy/docker/web.Dockerfile did not make (merge-r4-2).
#
#   CTRLZ_WEB_DEPS_IMAGE=ctrlz/web-deps:local sh scripts/web-deps-stamp.sh
#
# The build stage of web.Dockerfile runs `sha256sum -c /deps-lock.sha256` and refuses an image without that file (merge-r3-1). The image
# `deps-fresh` builds has it; an image installed another way (`pnpm install --ignore-scripts` plus the package files of an installed
# @heroui-pro/react, on a machine whose token is not a CDN token) has not. Running this script says: "this image was installed from the
# pnpm-lock.yaml of this checkout". Nothing here can check that, so it is for the operator's own image only, and it never writes over a
# hash that is already there: an image with another lockfile's hash is refused, not re-stamped. The image keeps its name; a layer is added.
# scripts/ci-web.sh calls it for CTRLZ_WEB_SKIP_DEPS=1, the setting that already says the deps stage is not built here.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
export MSYS_NO_PATHCONV=1
image="${CTRLZ_WEB_DEPS_IMAGE:-ctrlz/web-deps:ci}"
fail() { printf 'web-deps-stamp: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker is not on the path"
# Never a pull: a missing name would be looked up on Docker Hub and the stamp would sit on whatever is published there.
docker image inspect "$image" >/dev/null 2>&1 || fail "the image $image is not on this machine"

want=$(sha256sum pnpm-lock.yaml | cut -d' ' -f1)
have=$(docker run --rm --pull never --network none --entrypoint cat "$image" /deps-lock.sha256 2>/dev/null | cut -d' ' -f1 || true)
if [ -n "$have" ]; then
  [ "$have" = "$want" ] || fail "$image was installed from another pnpm-lock.yaml: rebuild it with --target deps-fresh (scripts/ci-web.sh does)"
  printf 'web-deps-stamp: %s already carries the hash of this pnpm-lock.yaml\n' "$image"
  exit 0
fi

# The lockfile alone is the build context; the file name inside the image is the one the build stage checks against (web.Dockerfile).
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
cp pnpm-lock.yaml "$ctx/pnpm-lock.yaml"
printf 'FROM %s\nCOPY pnpm-lock.yaml /stamp/pnpm-lock.yaml\nRUN cd /stamp && sha256sum pnpm-lock.yaml > /deps-lock.sha256 && rm -r /stamp\n' "$image" > "$ctx/Dockerfile"
docker build --pull=false -q -t "$image" "$(cd "$ctx" && pwd -W 2>/dev/null || pwd)" >/dev/null
printf 'web-deps-stamp: %s now carries the hash of this pnpm-lock.yaml\n' "$image"
