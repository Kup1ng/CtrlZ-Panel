#!/bin/sh
# Local CI for the web tier: both Next.js apps and the packages they share (spec 16.2). Fails on the
# first problem. GitHub has no web job (its runs cover the Go lanes, D69), so this script is where the web tier is checked.
#
#   scripts/ci-web.sh                       steps 1 to 9, Playwright in mock mode against `next start`
#   CTRLZ_WEB_STACK=1 scripts/ci-web.sh     also builds the images and runs the stack mode (needs Docker)
#
# scripts/ci.sh does not call this yet: the orchestrator hooks it in when the frontend branch merges,
# because that file and Docker belong to the Go side's CI until then.
#
# Steps, as in spec 16.2:
#   1  pnpm install --frozen-lockfile        (HEROUI_AUTH_TOKEN is needed only on a cold cache)
#   2  generated files are current           (API types, radius, icons)
#   3  tsc --noEmit in every package
#   4  ESLint, check-css, check-rounded-field
#   5  unit tests in every package
#   6  next build of both apps, one at a time
#   7  scripts/check-web-bundle.mjs          (WP5's, and its own tests; a missing script fails the step), then
#                                            tools/web-lint/check-built-uris.mjs (no data: or blob: URI in the built CSS and JS)
#   8  licences against tools/web-lint/licences.allow.txt
#   9  Playwright, mock mode: panel on 3410, admin on 3411, at most two workers
#   10 (CTRLZ_WEB_STACK=1 only) token check of the deps image, images, offline run, then the full stack: Caddy run, 502, healthcheck, flows
#
# Escape hatches for working on the script itself. Either one makes the run NOT a gate run, and the
# last line says so:
#   CTRLZ_WEB_SKIP_INSTALL=1    skip step 1 (the install is already right and the machine is offline)
#   CTRLZ_WEB_SKIP_E2E=1        skip step 9
#   CTRLZ_WEB_SKIP_DEPS=1       step 10: skip 10a (the deps stage build and its token scan) and build the two images from the
#                               image named by CTRLZ_WEB_DEPS_IMAGE (default ctrlz/web-deps:ci), for a machine whose
#                               HEROUI_AUTH_TOKEN is not a CDN token. The token is then not needed either.
#                               An image without /deps-lock.sha256 is stamped with the hash of this pnpm-lock.yaml first (scripts/web-deps-stamp.sh, merge-r4-2).
#   CTRLZ_WEB_PROJECTS=a,b      step 10d: run only those Playwright projects of each app through Caddy (the full set takes about
#                               4.5 hours). Keep `functional`: headers.spec.ts, the Caddy cases, is in it. Steps 10d2, 10d3 and 10f are not affected.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
# Git Bash on Windows rewrites arguments that look like paths: Docker's `-v host:/out` must reach it as is.
export MSYS_NO_PATHCONV=1
export NEXT_TELEMETRY_DISABLED=1

skipped=""
step() { printf '\n== ci-web: step %s: %s\n' "$1" "$2"; }
skip() { printf 'ci-web: step %s SKIPPED: %s\n' "$1" "$2"; skipped="$skipped $1"; }
fail() { printf 'ci-web: %s\n' "$*" >&2; exit 1; }

command -v pnpm >/dev/null 2>&1 || fail "pnpm is not on the path"

# --- 1 ---------------------------------------------------------------------
step 1 "pnpm install --frozen-lockfile"
if [ "${CTRLZ_WEB_SKIP_INSTALL:-0}" = 1 ]; then
  skip 1 "CTRLZ_WEB_SKIP_INSTALL=1"
else
  # Never --force, never a deleted node_modules, never a cleared store: HeroUI's postinstall has a
  # daily download limit (spec 3.3). On an install that is already right this changes nothing.
  pnpm install --frozen-lockfile
fi

# --- 2 ---------------------------------------------------------------------
step 2 "generated files are current"
# A generator that changes a byte of what is on disk fails the step, committed or not: the files
# are hashed before and after. (`git diff --exit-code` says the same once the result is committed,
# and says nothing useful about a tree that is dirty for other reasons.)
generated_hash() {
  {
    find packages/api-client/src/generated -type f 2>/dev/null
    echo packages/ui/styles/radius.generated.css
    # The icons are src/generated/**/*.tsx and registry.ts; build:check below stays a second guard.
    find packages/icons/src/generated -type f 2>/dev/null
  } | sort | while read -r f; do [ -f "$f" ] && cat "$f"; done | cksum
}
before=$(generated_hash)
pnpm -r gen
node packages/ui/scripts/gen-radius.mjs
pnpm --filter @ctrlz/icons build:check
after=$(generated_hash)
[ "$before" = "$after" ] || fail "a generator changed a file: run it and commit the result (pnpm -r gen; node packages/ui/scripts/gen-radius.mjs)"

# --- 3 ---------------------------------------------------------------------
step 3 "tsc --noEmit"
pnpm -r exec tsc --noEmit

# --- 4 ---------------------------------------------------------------------
step 4 "eslint, check-css, check-rounded-field"
pnpm eslint .
node tools/web-lint/check-css.mjs
node tools/web-lint/check-rounded-field.mjs

# --- 5 ---------------------------------------------------------------------
step 5 "unit tests"
pnpm -r test

# --- 6 ---------------------------------------------------------------------
step 6 "next build, one app at a time"
pnpm --filter "./apps/*" --workspace-concurrency=1 build

# --- 7 ---------------------------------------------------------------------
step 7 "bundle check"
# No existence test: a missing or renamed script must fail here (node: cannot find module, and set -e stops),
# never skip the gate and still exit 0 (wp5-r20-1). Only a CTRLZ_WEB_SKIP_* variable may turn a step off.
node scripts/check-web-bundle.mjs
# The gate's own tests. `pnpm -r test` runs them too, but tools/web-lint's script passes with no test files
# (--passWithNoTests), so a move of that folder would end them silently. Named here, vitest fails when none match.
(cd tools/web-lint && pnpm exec vitest run test/check-web-bundle)
# The CSP has no data: or blob: in img-src and font-src, and the guard of 17.2 sees a refusal only in a state that a test renders, so what shipped is
# read for such a URI (gate-r13-2). Same rule as above: no condition, so a missing script fails the step.
node tools/web-lint/check-built-uris.mjs
(cd tools/web-lint && pnpm exec vitest run test/check-built-uris)

# --- 8 ---------------------------------------------------------------------
step 8 "licences"
node tools/web-lint/check-licences.mjs

# --- 9 ---------------------------------------------------------------------
step 9 "Playwright, mock mode"
if [ "${CTRLZ_WEB_SKIP_E2E:-0}" = 1 ]; then
  skip 9 "CTRLZ_WEB_SKIP_E2E=1"
else
  # Playwright starts `next start` itself (E2E_START_SERVER=1, packages/ui/src/testing/config.ts) on
  # 3410 and 3411 and stops it when the run ends, so no server is left behind. The browser is the
  # installed Chrome: `playwright install` is never run (it downloads from a CDN).
  for app in panel admin; do
    printf 'ci-web: %s\n' "playwright, apps/$app"
    (cd "apps/$app" && E2E_START_SERVER=1 pnpm exec playwright test)
  done
  # Spec 15.3: with CTRLZ_VERIFY_ORIGIN set, the panel's connect-src has exactly one extra source and the
  # admin's has none. The server and the test process both read the variable (Playwright hands its
  # environment to `next start`), so this run is the only one that proves the server reads it at run time.
  for app in panel admin; do
    printf 'ci-web: %s\n' "playwright, apps/$app, headers with CTRLZ_VERIFY_ORIGIN"
    (cd "apps/$app" && CTRLZ_VERIFY_ORIGIN='https://*.verify.dns.example.test' E2E_START_SERVER=1 pnpm exec playwright test headers.spec.ts --project=functional)
  done
fi

# --- 10 --------------------------------------------------------------------
if [ "${CTRLZ_WEB_STACK:-0}" = 1 ]; then
  step 10 "stack: images, Caddy, stack mode and the offline run"
  # Everything below needs Docker, which the auth review's CI owned while the frontend was built.
  # First run: P1 web merge (the Caddy run, the flow tests and the offline run). Spec 17.4 and 17.7 say what each part proves.
  command -v docker >/dev/null 2>&1 || fail "CTRLZ_WEB_STACK=1 needs Docker"
  deps_image="${CTRLZ_WEB_DEPS_IMAGE:-ctrlz/web-deps:ci}"
  if [ "${CTRLZ_WEB_SKIP_DEPS:-0}" != 1 ]; then
  [ -n "${HEROUI_AUTH_TOKEN:-}" ] || fail "CTRLZ_WEB_STACK=1 needs the install token in the environment (a CI/CD token, spec 3.3)"
  # HeroUI's CDN validates the token as a UUID (measured 2026-11-23: a value with one character too many gets a 400
  # "Invalid request body" from the challenge call, and the postinstall then fails with an unreadable "[object Object]").
  # Said now, by length only and never with the value, instead of after a two-minute install.
  [ "${#HEROUI_AUTH_TOKEN}" = 36 ] || fail "HEROUI_AUTH_TOKEN is ${#HEROUI_AUTH_TOKEN} characters, not the 36 of a UUID: the CDN refuses it (Invalid request body) and the deps stage fails"
  fi
  [ -f deploy/docker/web.Dockerfile ] || fail "deploy/docker/web.Dockerfile (WP5, spec 3.2) is not in this tree"

  # The image the e2e stack and gen-secrets.sh need is built by scripts/ci.sh (docker build of
  # deploy/docker/Dockerfile), not here. Said now, instead of as a failure in the middle of 10c.
  image="${CTRLZ_IMAGE:-ctrlz/panel:dev}"
  docker image inspect "$image" >/dev/null 2>&1 || fail "the image $image is not built: run  docker build -f deploy/docker/Dockerfile -t $image .  first (scripts/ci.sh does), then CTRLZ_WEB_STACK=1 scripts/ci-web.sh again"

  # Every path below reaches native programs (docker, node), and under Git Bash on Windows
  # MSYS_NO_PATHCONV=1 hands them `/tmp/...` unconverted, which they resolve against the current
  # drive. cygpath -m gives `C:/Users/...`, which Git Bash and the native tools both read, as
  # scripts/compose-smoke.sh does for the same reason (wp12-r1-2). On Linux the path is unchanged.
  host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }
  work=$(host_path "$(mktemp -d)")
  project=ctrlz-e2e
  files="-f deploy/compose/docker-compose.yml -f deploy/compose/e2e.yml -f deploy/compose/e2e-stack.yml"
  cleanup() {
    # shellcheck disable=SC2086
    docker compose -p "$project" $files --env-file "$work/env" down -v --remove-orphans >/dev/null 2>&1 || true
    # The noop SMS driver wrote the run's login, reset and registration codes and the phone numbers here, and the invite flow of the stack run
    # wrote its token (D67: an invite is never texted), in a folder that every user may write (the worker is uid 65532). A failed step must not
    # leave them on a shared host (merge-r1-11).
    rm -rf "$work" "$here/deploy/compose/e2e-out"
  }
  trap cleanup EXIT

  # Every Playwright run below goes through Caddy at https://<app>.localhost. Chrome resolves *.localhost itself, but the
  # request context and node:http of the test process use the system resolver, which on Windows does not (ENOTFOUND).
  # The preload answers .localhost names only, so no hosts file, certificate store or other system setting is touched.
  # The quotes are for NODE_OPTIONS, since the path may hold a space (a Windows drive path needs the third slash of a file URL). A pre-set NODE_OPTIONS is kept.
  lookup_url="file://$(host_path "$here/scripts/e2e-localhost-lookup.mjs")"
  case "$lookup_url" in file://[A-Za-z]:*) lookup_url="file:///${lookup_url#file://}" ;; esac
  NODE_OPTIONS="${NODE_OPTIONS:-} --import \"$lookup_url\""
  export NODE_OPTIONS

  # 10a. The token must be in no layer of the deps stage (spec 3.3). The tar goes to a file first so
  # that the exit status of the scan is the one that counts, and only found / not found is printed.
  if [ "${CTRLZ_WEB_SKIP_DEPS:-0}" = 1 ]; then
    docker image inspect "$deps_image" >/dev/null 2>&1 || fail "CTRLZ_WEB_SKIP_DEPS=1 needs the local image $deps_image (CTRLZ_WEB_DEPS_IMAGE)"
    skip 10a "CTRLZ_WEB_SKIP_DEPS=1: the deps stage was not built here, so no token scan"
    # An image that `deps-fresh` did not make (installed by hand on a machine whose token is not a CDN token) has no /deps-lock.sha256, and
    # the build stage of web.Dockerfile refuses it (merge-r3-1). Whoever sets CTRLZ_WEB_SKIP_DEPS=1 says it was installed from this
    # pnpm-lock.yaml; the script writes that down once, and never over a hash that is already there (merge-r4-2).
    CTRLZ_WEB_DEPS_IMAGE="$deps_image" sh scripts/web-deps-stamp.sh
  else
    docker build -f deploy/docker/web.Dockerfile --target deps-fresh \
      --secret id=heroui_auth_token,env=HEROUI_AUTH_TOKEN -t ctrlz/web-deps:ci .
    docker save -o "$work/deps.tar" ctrlz/web-deps:ci
    printf 'ci-web: token in the deps image layers: '
    node scripts/ci-web-token-scan.mjs HEROUI_AUTH_TOKEN < "$work/deps.tar" || fail "the install token is in a layer, or the scan could not decide"
    rm -f "$work/deps.tar"
  fi

  # 10b. The two images, from the deps image, so no further CDN download happens (spec 3.4).
  for app in panel admin; do
    docker build -f deploy/docker/web.Dockerfile --build-arg APP="$app" \
      --build-arg DEPS_STAGE="$deps_image" -t "ctrlz/web-$app:e2e" .
  done

  # 10c. Environment of the e2e project: the profile and the example file, a private secrets
  # directory, and an output directory the worker (uid 65532) can write.
  { grep -hv '^#' deploy/compose/.env.example deploy/compose/profiles/small.env | grep -v '^$' \
      | grep -v '^CTRLZ_SECRETS_DIR' ; printf 'CTRLZ_SECRETS_DIR=%s\n' "$work/secrets"; } > "$work/env"
  # The secrets directory is in the env file as a host path; every compose call and the seed take that file.
  scripts/gen-secrets.sh "$work/secrets"
  rm -rf deploy/compose/e2e-out
  mkdir -p deploy/compose/e2e-out
  chmod 0777 deploy/compose/e2e-out
  # The noop SMS driver creates its file mode 0600 as uid 65532, which a non-root host user cannot read on a Linux host (Docker Desktop hides
  # it), and the stack specs and step 10f1 read the codes from it on the host. A file that exists is only appended to, so it is made here by
  # the host user, readable and writable by all, in the folder that is removed with the run (merge-r4-9).
  : > deploy/compose/e2e-out/noop.jsonl
  chmod 0666 deploy/compose/e2e-out/noop.jsonl

  # The order is 10e, then 10d to 10f. The offline run changes the networks (e2e-offline.yml), and Compose refuses to change a network that
  # has containers on it, so it runs first, on the web tier alone, and its stack goes down before the full stack comes up.

  # 10e. The offline run (spec 17.4). First prove the network is closed from inside Caddy, since a
  # smoke set that passes on an open network proves nothing, then run the panel's mock set again.
  offline_compose() {
    # shellcheck disable=SC2086
    docker compose -p "$project" -f deploy/compose/docker-compose.yml -f deploy/compose/e2e.yml -f deploy/compose/e2e-offline.yml --env-file "$work/env" "$@"
  }
  offline_compose up -d --wait caddy-init caddy web-panel web-admin
  # The route of Caddy is cut by a one-shot container in its network namespace (e2e-offline.yml says why the network flags are not enough).
  # "up --wait" counts a container that exited as a failure, so it is started on its own and its exit status is read.
  offline_compose up -d offline-cut
  [ "$(docker wait "$(offline_compose ps -aq offline-cut)")" = 0 ] || fail "offline-cut did not cut Caddy's route"
  if offline_compose exec -T caddy wget -q -T 5 -O /dev/null http://1.1.1.1/ 2>/dev/null; then
    fail "the offline network is not closed: Caddy reached a public address"
  fi
  (cd apps/panel && E2E_BASE_URL=https://panel.localhost pnpm exec playwright test --project=w1280-fa-light)
  offline_compose down -v --remove-orphans

  # 10d. The full stack behind the real Caddy, and the mock set of each app over HTTPS, so `__Host-` cookies exist and Caddy's
  # headers are in the path of every request. The API must be up: headers.spec.ts asks Caddy's API handle for 401 and 404 (a 502
  # there would mean the handle is broken), and the PATCH, PUT and DELETE calls must reach it (gate-r4-7). The web tier alone
  # answers those with Caddy's own 502, so a run without the API fails two Caddy cases (measured by the first run).
  web_compose() {
    # shellcheck disable=SC2086
    docker compose -p "$project" $files --env-file "$work/env" "$@"
  }
  web_compose up -d --wait
  # Every project of both apps runs through Caddy by default, which takes hours on a busy host (merge-r1-23). The switch
  # names fewer (CTRLZ_WEB_PROJECTS=functional, a comma list), and the run is then not a gate run.
  projects=""
  if [ -n "${CTRLZ_WEB_PROJECTS:-}" ]; then
    for name in $(printf '%s' "$CTRLZ_WEB_PROJECTS" | tr ',' ' '); do projects="$projects --project=$name"; done
    skip 10d "CTRLZ_WEB_PROJECTS=$CTRLZ_WEB_PROJECTS: only those Playwright projects ran through Caddy"
  fi
  for app in panel admin; do
    # shellcheck disable=SC2086
    (cd "apps/$app" && E2E_BASE_URL="https://$app.localhost" pnpm exec playwright test $projects)
  done

  # 10d1. No web container line holds a request URI (R21, spec 15.6, merge-r2-5). headers.spec.ts sends a body over the cap with
  # `?next=CANARYTOKEN` in the query: the edge must answer it, and if it ever reached Next the canary would be in Next's own
  # "Request body exceeded" line, which prints the whole request target. It also catches a target that is not origin-form
  # (`GET *`, `x:*?t=CANARYTOKEN`: a TypeError that names the input) and a body cut in the middle (an aborted or reset body),
  # the other ways an anonymous client could make Next write a block per request (merge-r3-4, merge-r3-6). The one deliberate cut body
  # of the suite (the stalled POST) runs in 10d1b, after this scan, because Next does log that one (merge-r4-1).
  # The logs go to a private file first, so that a failed `docker compose logs` or an empty log is a failure and not "nothing found" (merge-r4-8).
  # Next prints its start line, so a log with no line at all means the scan read nothing.
  (umask 077; : > "$work/web.log")
  web_compose logs --no-color --no-log-prefix web-panel web-admin > "$work/web.log" 2>&1 || fail "10d1: could not read the logs of the web containers"
  [ -s "$work/web.log" ] || fail "10d1: the logs of the web containers are empty, so the scan would prove nothing"
  leak='CANARYTOKEN|Request body exceeded|Invalid URL|ECONNRESET|aborted'
  if grep -Eq "$leak" "$work/web.log"; then
    grep -E "$leak" "$work/web.log" | cut -c1-200 | head -5
    fail "a web container logged a request that the edge should have refused (a body over the cap, a target that is not origin-form, or a request URI)"
  fi
  rm -f "$work/web.log"

  # 10d1b. A body that is announced and never finished is ended by Caddy's read deadline (merge-r3-5). Caddy passes on what it had read and
  # aborts, so Next logs one aborted-body block for it; that is why the case is not part of the run above (E2E_STALLED_POST=1 enables it).
  for app in panel admin; do
    (cd "apps/$app" && E2E_STALLED_POST=1 E2E_BASE_URL="https://$app.localhost" pnpm exec playwright test headers.spec.ts --project=functional -g "never finished")
  done

  # 10d2. Caddy's own 502 or 504 carries the headers while the web upstream is down (merge item A13). Only this
  # run can stop the upstream, so it says so with E2E_UPSTREAM_STOPPED=1 and runs that one case; the others of
  # the file expect no error status and have run above, with the upstream up.
  web_compose stop web-panel web-admin
  for app in panel admin; do
    (cd "apps/$app" && E2E_UPSTREAM_STOPPED=1 E2E_BASE_URL="https://$app.localhost" pnpm exec playwright test headers.spec.ts --project=functional -g "own 502 or 504")
  done
  web_compose up -d --wait web-panel web-admin

  # 10d3. A web container whose proxy is broken must report unhealthy (merge item A14). A wrong
  # CTRLZ_VERIFY_ORIGIN makes the panel answer 500 to every page while its process stays up and /logo.png stays 200,
  # so only a healthcheck that asks for a page sees it. e2e.yml passes the variable on; every other run leaves it empty.
  CTRLZ_VERIFY_ORIGIN='https://not-a-verify-host.example' web_compose up -d --force-recreate --no-deps web-panel
  panel_cid=$(web_compose ps -q web-panel)
  health=starting
  for _ in $(seq 1 60); do
    health=$(docker inspect -f '{{.State.Health.Status}}' "$panel_cid")
    [ "$health" = starting ] || break
    sleep 5
  done
  [ "$health" = unhealthy ] || fail "web-panel with a wrong CTRLZ_VERIFY_ORIGIN is $health, not unhealthy: its healthcheck does not ask for a page"
  web_compose up -d --wait --force-recreate --no-deps web-panel

  # 10f. The flow tests of spec 17.7 on the same stack: the seed, then the panel's and the admin's `*.stack.spec.ts`.
  # The seed is not repeatable (it bootstraps the first admin), so it runs once per stack.
  node scripts/e2e-seed.mjs --env-file "$work/env" --out "$work/seed" > /dev/null
  E2E_SEED_FILE="$work/seed/seed.json"
  E2E_PHONE=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).user.phone)' "$E2E_SEED_FILE")
  E2E_PASSWORD=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).user.password)' "$E2E_SEED_FILE")
  export E2E_SEED_FILE E2E_PHONE E2E_PASSWORD
  for app in panel admin; do
    (cd "apps/$app" && E2E_MODE=stack pnpm exec playwright test)
  done

  # 10f1. The real sign-ins above sent passwords, TOTP codes, SMS codes and cookies through Caddy and Next. None of them may be in a log of the
  # front tier (merge-r3-10). The values are the ones the seed made, the codes the noop driver recorded and the invite tokens the stack run wrote (scripts/ci-web-leak-patterns.mjs). They go
  # to grep through private files and only a count per container is printed, so a leak is not copied into the CI log. A log that cannot be read, or
  # is empty, fails the step: a scan of nothing is not a pass (merge-r4-8).
  (umask 077; : > "$work/leak-fixed"; : > "$work/leak-regex"; : > "$work/front.log")
  node scripts/ci-web-leak-patterns.mjs "$E2E_SEED_FILE" deploy/compose/e2e-out/noop.jsonl "$work/leak-fixed" "$work/leak-regex" deploy/compose/e2e-out/invite-tokens.txt || fail "10f1: the patterns of the scan could not be made"
  for service in caddy web-panel web-admin; do
    web_compose logs --no-color --no-log-prefix "$service" > "$work/front.log" 2>&1 || fail "10f1: could not read the log of $service"
    [ -s "$work/front.log" ] || fail "10f1: the log of $service is empty, so the scan would prove nothing"
    hits=$(grep -c -F -f "$work/leak-fixed" "$work/front.log" || true)
    codes=0
    if [ -s "$work/leak-regex" ]; then codes=$(grep -c -E -f "$work/leak-regex" "$work/front.log" || true); fi
    [ "$hits" = 0 ] && [ "$codes" = 0 ] || fail "the log of $service holds $hits line(s) with a seeded phone, password, TOTP secret, an Authorization or a Cookie and $codes line(s) with an SMS code after the real sign-in flows"
  done
  rm -f "$work/leak-fixed" "$work/leak-regex" "$work/front.log"
  rm -rf deploy/compose/e2e-out
fi

printf '\n'
if [ -n "$skipped" ]; then
  printf 'ci-web: passed, but step(s)%s were SKIPPED: this is not a gate run\n' "$skipped"
else
  printf 'ci-web: all steps passed\n'
fi
