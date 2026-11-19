#!/bin/sh
# Checks the image against spec 17.2: the ctrlz-admin link survived COPY, the
# entrypoint reaches the admin command line under both spellings, and the CA
# bundle is present. Needs Docker and the image (default ctrlz/panel:dev); builds
# nothing and needs no network. A TLS dial to a server signed by a public root
# cannot be made without the internet, so the bundle is checked by content: it
# must be a real root store, not an empty file.
set -eu
image="${CTRLZ_IMAGE:-ctrlz/panel:dev}"
export MSYS_NO_PATHCONV=1   # Git Bash on Windows rewrites /usr/... arguments otherwise
fail() { echo "image-smoke: $*" >&2; exit 1; }

docker image inspect "$image" >/dev/null 2>&1 || fail "image $image not found; build it first (docker build -f deploy/docker/Dockerfile -t $image .)"

# 1. `docker run ... ctrlz-admin --help` goes through the entrypoint (ctrlz).
out=$(docker run --rm --network none "$image" ctrlz-admin --help 2>&1) || fail "ctrlz-admin --help failed"
echo "$out" | grep -q 'usage: ctrlz-admin' || fail "ctrlz-admin --help printed no usage"

# 2. The link itself: started under the name ctrlz-admin the binary is the admin
# command line, so the symbolic link must still be a link to ctrlz.
out=$(docker run --rm --network none --entrypoint /usr/local/bin/ctrlz-admin "$image" --help 2>&1) || fail "the ctrlz-admin link does not run (COPY lost it; use a hard link)"
echo "$out" | grep -q 'usage: ctrlz-admin' || fail "the ctrlz-admin link prints no usage"

# 3. The CA bundle: present and a real root store (the SMS drivers verify the
# gateways' certificates with it).
cid=$(docker create "$image")
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
# "-" streams the file as a tar archive to stdout, so no host path is involved
# (a Windows host path would not survive the shell).
n=$(docker cp "$cid:/etc/ssl/certs/ca-certificates.crt" - 2>/dev/null | grep -c 'BEGIN CERTIFICATE' || true)
[ "$n" -ge 100 ] || fail "the CA bundle holds $n certificates"

# 4. The image runs as a numeric user and has no shell.
user=$(docker image inspect --format '{{.Config.User}}' "$image")
[ "$user" = "65532:65532" ] || fail "image user is $user"
if docker run --rm --network none --entrypoint /bin/sh "$image" -c true >/dev/null 2>&1; then fail "the image has a shell"; fi

# 5. The compiler that built the shipped binary is the one go.mod pins. The CI
# gates (vet, govulncheck) judge source with the host compiler; only the bytes in
# the image say what actually ships (review round 8, go-bump finding s2). The
# binary is streamed out as a tar so no host path is involved, then read with
# `go version <file>`, which needs no network.
here=$(cd "$(dirname "$0")/.." && pwd)
want=$(awk '$1=="go" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ {print $2; exit}' "$here/go.mod")
[ -n "$want" ] || fail "no go X.Y.Z line in go.mod"
bin=$(mktemp)
trap 'rm -f "$bin"; docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
docker cp "$cid:/usr/local/bin/ctrlz" - 2>/dev/null | tar -xO > "$bin" || fail "could not copy /usr/local/bin/ctrlz out of the image"
[ -s "$bin" ] || fail "the binary copied out of the image is empty"
# A native Windows go.exe cannot open a Git Bash /tmp path (path conversion is off above).
native=$bin; command -v cygpath >/dev/null 2>&1 && native=$(cygpath -w "$bin")
built=$(GOTOOLCHAIN=local go version "$native" 2>/dev/null | awk '{print $2}')
[ "$built" = "go$want" ] || fail "the image binary was built by ${built:-an unreadable toolchain}, go.mod pins go$want (rebuild the image)"

echo "image-smoke: ok ($image, $n root certificates, $built)"
