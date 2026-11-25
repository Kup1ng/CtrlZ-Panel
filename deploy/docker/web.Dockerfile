# Built by the Docker Engine's own Dockerfile frontend, with no `# syntax=` line on purpose: that line makes BuildKit pull docker/dockerfile from Docker Hub by tag, in
# the very build that holds the install token (merge-r1-10). Engine 29 already reads `--mount=type=secret,env=`.
#
# One image per web app (spec 3.2), from the repository root:
#
#   docker build -f deploy/docker/web.Dockerfile --build-arg APP=panel --build-arg CTRLZ_VERSION="$(node scripts/ctrlz-version.mjs)" \
#     --secret id=heroui_auth_token,env=HEROUI_AUTH_TOKEN -t ctrlz/web-panel:dev .
#
# CTRLZ_VERSION is the version the logo menu shows (T-124). The context has no .git, so it comes from outside, from the one script
# that computes it (the CTRLZ_VERSION variable of a release job, else git describe). Left out, the image says "dev".
#
# HeroUI Pro installs from its own CDN with a token (spec 3.1, 3.3). The token exists in exactly one
# place, the install step of `deps-fresh`, as a BuildKit secret: never a build argument, an ENV, a file
# or a layer. Each build of that stage spends one of HeroUI's daily downloads, so it is built once per
# lockfile and saved as an image (scripts/ci-web.sh step 10a). Every later build starts from that image
# and needs no token and no CDN:
#
#   docker image inspect ctrlz/web-deps:ci > /dev/null && docker build -f deploy/docker/web.Dockerfile --build-arg APP=admin \
#     --build-arg CTRLZ_VERSION="$(node scripts/ctrlz-version.mjs)" --build-arg DEPS_STAGE=ctrlz/web-deps:ci -t ctrlz/web-admin:dev .
#
# (The `&&` matters: a name that is not on this machine would otherwise be looked up on Docker Hub by the build.)
#
# The final stage has Next's standalone server and the files it does not copy itself. Nothing in it
# fetches anything at run time (fixed rule 9).
#
# Next's private minimal-mode switch must never be set here. It makes Next trust headers that only a platform in
# front of it may set, and the headers of spec 15 rely on Next stripping them; packages/ui/src/proxy/nextRequests.test.ts
# scans deploy/ for it by name.
ARG DEPS_STAGE=deps-fresh

# Tag and digest, as every image of this repository: the tag says what it is, the digest is what is built.
FROM node:26.13-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS deps-fresh
ENV NEXT_TELEMETRY_DISABLED=1
# The Node 26.13 image has no corepack (checked with docker run, 2026-11-06).
RUN npm install -g pnpm@12.18.0 && test "$(pnpm -v)" = "12.18.0"
WORKDIR /src
# Only manifests: this layer is rebuilt when the lockfile changes, and each rebuild spends one of
# HeroUI's daily CDN downloads.
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json .npmrc ./
COPY apps/panel/package.json apps/panel/
COPY apps/admin/package.json apps/admin/
COPY packages/ui/package.json packages/ui/
COPY packages/icons/package.json packages/icons/
COPY packages/api-client/package.json packages/api-client/
COPY packages/i18n/package.json packages/i18n/
COPY tools/web-lint/package.json tools/web-lint/
RUN --mount=type=secret,id=heroui_auth_token,env=HEROUI_AUTH_TOKEN pnpm install --frozen-lockfile
# What the node_modules above were installed from. The build stage compares it with the lockfile of ITS context, so an image
# saved before a lockfile bump (a security fix of Next, say) cannot be reused by name and ship the old dependencies (merge-r3-1).
RUN sha256sum pnpm-lock.yaml > /deps-lock.sha256

FROM ${DEPS_STAGE} AS build
ARG APP
ARG CTRLZ_VERSION=dev
# A missing or misspelled APP would build nothing useful and name the failure far from its cause.
RUN test "$APP" = panel || test "$APP" = admin
COPY . .
# DEPS_STAGE is a name, and a name proves nothing: the image under it may be older than the lockfile in this context. The hash was
# written outside /src, so `COPY . .` cannot replace it. This catches an image that is older than the lockfile, and an image made some other way
# (scripts/web-deps-stamp.sh says how to stamp one). It does not catch a hostile image under the same name: the check runs inside it, with its own
# sha256sum and its own hash file (merge-r4-5). What keeps a foreign image out is that the name is never pulled: README.md and scripts/ci-web.sh
# look for the image on this machine first, and a build is only started when that succeeds.
RUN sha256sum -c /deps-lock.sha256 || { echo "the deps image was not installed from this pnpm-lock.yaml: rebuild it with --target deps-fresh" >&2; exit 1; }
RUN NEXT_PUBLIC_CTRLZ_VERSION="$CTRLZ_VERSION" pnpm --filter "@ctrlz/$APP" build

FROM node:26.13-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072
ARG APP
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
WORKDIR /app
COPY --from=build /src/apps/$APP/.next/standalone ./
# Next's standalone output does not copy these two on purpose (it expects a CDN or the host to serve
# them). Without them every chunk, /logo.png and /icon.png would be a 404 (spec 15.1: the files of
# public/ skip the proxy, and only the Caddy run can show it).
COPY --from=build /src/apps/$APP/.next/static ./apps/$APP/.next/static
COPY --from=build /src/apps/$APP/public ./apps/$APP/public
# Monorepo standalone output keeps server.js under the app's own path.
WORKDIR /app/apps/$APP
USER 65532:65532
CMD ["node", "server.js"]
