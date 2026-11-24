#!/bin/sh
# Judges the container images that a job pulled or started (CI review round 13, ci-r13-2; Plan.md D64,
# test-images-unpinned).
#
#   sh .github/ci/images.sh before     records the images the runner has
#   sh .github/ci/images.sh after      fails for any image that appeared since, unless it is a reviewed one
#
# Why it is a check of what happened and not a lint of what is written. The Panel's own lint judges the
# references that its sources spell (the Compose file, the Dockerfiles, the Go tests that read an image through
# deploy.Image). It cannot judge a library that starts an image of its own (the testcontainers reaper, a floating
# tag with the Docker socket mounted), a variable, a script or a document that names one. The runner is
# asked instead: whatever image is on it after the tests, and was not before, must be an image that the tree
# pins by digest, so a tag that moved upstream or a mirror that swapped it shows here as a digest nobody
# reviewed. The reaper is switched off on the runner (TESTCONTAINERS_RYUK_DISABLED in the workflow), and this
# step is the proof that the switch worked and that nothing else took its place.
#
# A new image is accepted when
#   - its digest is one of the digests that the tree pins: those of the Compose file and the Dockerfiles, where the
#     Panel's lint requires every image of the stack and of its tests to be named (a reference is
#     `tag@sha256:<index digest>`, and Docker reports that digest for an image pulled by it), and the digest
#     constants of the non-test Go files under deploy/ (ReaperDigest, which deploy.PinReaper pulls and tags on every
#     runner that starts a container test, whether or not the reaper itself is switched off: ci-r14-1); or
#   - it has the same image ID as a new image that passes by its digest: a name given to reviewed bytes (PinReaper
#     tags the digest pull as testcontainers/ryuk:0.14.0, and a Docker with the containerd image store may list
#     that row with no digest) is the bytes that were reviewed, so the judge is the bytes and not the row; or
#   - it is the Panel's own image, built from the Dockerfile of the tree (ctrlz/panel:dev has no registry
#     digest), the one exemption of the lint; or
#   - it is a layer left by a build: no name and no digest, so nothing was pulled for it.
# Anything else is named by repository and tag and fails the step. The digests are read from the tree, not typed
# here, so a bump of a pin in the Compose file needs no edit of this script.
#
# A check that looked at nothing must not read as clean: no pin found, no state of the first call and a docker
# that fails are all failures.
set -eu

mode="${1:-}"
state="${RUNNER_TEMP:?images: RUNNER_TEMP is not set, so there is nowhere to keep the list of images}/ctrlz-images-before"
list() {
  docker image ls --no-trunc --digests --format '{{.ID}} {{.Repository}} {{.Tag}} {{.Digest}}' > "$1" \
    || { echo "images: docker image ls failed, so the images cannot be judged" >&2; exit 1; }
  sort -u "$1" -o "$1"
}

case "$mode" in
before)
  list "$state"
  echo "images: $(wc -l < "$state" | tr -d ' ') image(s) were on the runner before the job's containers"
  ;;
after)
  [ -f "$state" ] || { echo "images: no list of the images from before the job (run 'images.sh before' first), so the new ones cannot be told" >&2; exit 1; }
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  list "$work/after"
  # The digests the tree pins, from the places that name them.
  : > "$work/pins"
  [ -f deploy/compose/docker-compose.yml ] || { echo "images: deploy/compose/docker-compose.yml is missing, so there is no pin to compare with" >&2; exit 1; }
  find . -name 'Dockerfile*' -not -path './.git/*' -not -path '*/node_modules/*' > "$work/dockerfiles"
  { cat deploy/compose/docker-compose.yml; while read -r f; do cat "$f"; done < "$work/dockerfiles"; } \
    | grep -oE '@sha256:[0-9a-f]{64}' | sed 's/^@//' | sort -u > "$work/pins" || true
  # A test file is not a pin: it may spell any digest it likes for a fake.
  if [ -d deploy ]; then
    find deploy -name '*.go' -not -name '*_test.go' > "$work/gofiles"
    while read -r f; do grep -oE 'sha256:[0-9a-f]{64}' "$f" || true; done < "$work/gofiles" >> "$work/pins"
    sort -u "$work/pins" -o "$work/pins"
  fi
  [ -s "$work/pins" ] || { echo "images: the Compose file and the Dockerfiles pin no image by digest, so every new image would be unreviewed" >&2; exit 1; }
  comm -13 "$state" "$work/after" > "$work/new"
  # The image IDs that pass by their digest; another name for the same bytes passes with them.
  : > "$work/okids"
  while read -r id repo tag digest; do
    case "$digest" in
      sha256:*) if grep -qxF "$digest" "$work/pins"; then echo "$id" >> "$work/okids"; fi ;;
    esac
  done < "$work/new"
  bad=0
  while read -r id repo tag digest; do
    case "$digest" in
      sha256:*) if grep -qxF "$digest" "$work/pins"; then continue; fi ;;
    esac
    if grep -qxF "$id" "$work/okids"; then continue; fi
    # Built here: the Panel's own image, and the layers a build leaves, none of which was pulled.
    if [ "$digest" = '<none>' ] && { [ "$repo:$tag" = ctrlz/panel:dev ] || [ "$repo:$tag" = '<none>:<none>' ]; }; then continue; fi
    echo "images: $repo:$tag ($digest, image $(printf '%.19s' "$id")) appeared during the job and is not an image that the tree pins by digest" >&2
    bad=1
  done < "$work/new"
  [ "$bad" = 0 ] || { echo "images: an unreviewed image ran on the runner; pin it in deploy/compose/docker-compose.yml (through deploy.Image) or stop the library that starts it" >&2; exit 1; }
  echo "images: $(wc -l < "$work/new" | tr -d ' ') new image(s), all pinned by digest in the tree or built from it"
  ;;
*)
  echo "usage: images.sh before|after" >&2
  exit 2
  ;;
esac
