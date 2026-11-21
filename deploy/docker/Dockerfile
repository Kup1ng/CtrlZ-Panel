# The one image of the Panel's Go roles: api, admin, worker, hub and migrate,
# plus the ctrlz-admin command line, the key tools and rekey.
# Build from the repository root:
#   docker build -f deploy/docker/Dockerfile -t ctrlz/panel:dev .
#
# The final stage is empty (scratch) on purpose. The binary is static and
# carries its own time zone data. Nothing in the image can be exec'd into a
# shell, and there is no package manager to download from (rule 9: nothing at
# runtime depends on international internet).
#
# The CA bundle is the one file besides the binary. The worker dials the two
# Iranian SMS gateways over TLS (spec 9.3) and a scratch image has no root
# certificates to verify them with. The bundle comes from the build stage and
# adds no network access of its own: the drivers dial their fixed hosts only,
# and the egress network is the only one with a route out (spec 17.2).

# Tag and digest (round 16, admin-r16-1): the tag says what it is, the digest is what is built.
FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
WORKDIR /src
# The module proxy is a build argument: from some networks (the owner's, for one) the
# default proxy answers 403 and the image cannot be built. go.sum still pins every
# module, so a mirror cannot change what is built. Default is Go's own.
ARG GOPROXY=https://proxy.golang.org,direct
# The module cache layer: only go.mod, go.sum and the shared module change it.
COPY go.mod go.sum ./
COPY shared/go.mod shared/go.sum shared/
RUN go mod download
COPY . .
# ctrlz-admin is the same binary under a second name (spec 17.1): the binary
# chooses the admin command line from the name it was started under, so
# `docker compose exec admin ctrlz-admin ...` needs no second build. COPY of a
# directory keeps a symbolic link as a link, which the image smoke check
# (scripts/image-smoke.sh) confirms.
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/ctrlz ./cmd/ctrlz \
 && mkdir -p /out/bin \
 && mv /out/ctrlz /out/bin/ctrlz \
 && ln -s ctrlz /out/bin/ctrlz-admin

FROM scratch
COPY --from=build /out/bin/ /usr/local/bin/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# Numeric ids: scratch has no /etc/passwd.
USER 65532:65532
# The runtime prints the arguments of every frame when the process dies of an unrecovered panic or a
# fatal error, and a value passed by value (the ten bytes of a recovery code, a 16-byte key) is printed
# as its words into the container log (round 17, primitives-r17-9). debug.SetTraceback cannot lower the
# level below the default, so the setting has to be in the environment of the process. The panic or fatal
# message and the exit status are still printed; a recovered panic is logged by logattr.Stack, which has
# no arguments to print. internal/lint TestTheImageSilencesGoCrashTracebacks holds this line and the
# Compose file that must not undo it.
ENV GOTRACEBACK=none
# The entrypoint stays ctrlz, so `docker run ... ctrlz-admin` reaches the
# "ctrlz-admin" subcommand of cmd/ctrlz (spec 17.1 step 2).
ENTRYPOINT ["/usr/local/bin/ctrlz"]
