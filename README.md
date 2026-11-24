# Ctrl Z Panel

Go API, workers and hub of Ctrl Z, a multi-tenant DNS filtering service. The plan is `Plan.md` in the workspace root; the data model and isolation rules are `docs/specs/postgres-schema.md` there.

This repository is at P0: the shared module, the database foundation, and a Compose stack whose Go roles start as stubs.

## Layout

| Path | What |
|---|---|
| `shared/` | The Go module shared with the Node repository. Canonical copy; do not edit it here without `scripts/shared-sync`. |
| `cmd/ctrlz/` | The one binary. `ctrlz {api,admin,worker,hub,migrate}`, plus `ctrlz healthcheck URL`. |
| `internal/store/` | The only door to Postgres: `WithTenant`, `WithGlobal`, `Auth()`. The pool is unexported. |
| `internal/store/catalogtest/` | The catalog tests, the two-tenant harness and the mutation tests. |
| `internal/secret/` | `secret.String`: redacts itself in every formatting path. |
| `internal/migrate/` | Runs the embedded migrations with goose. |
| `internal/app/` | Start-up shared by the five roles. |
| `internal/lint/` | Source rules as tests: where pgx may be imported, no dynamic SQL, no package-level state. |
| `migrations/postgres/` | Schema, roles' grants, policies, functions. See its README. |
| `migrations/catalog/` | Expected catalog state, compared with the live database. |
| `migrations/clickhouse/` | Placeholder until P5. |
| `deploy/compose/` | `docker-compose.yml`, Caddy, Postgres, ClickHouse and Valkey config, the RAM profiles. |
| `api/openapi.yaml` | Skeleton of the tenant API. |
| `scripts/` | `ci.sh`, `gen-secrets.sh`, `select-profile.sh`, `gen-migrations.sh`, the shared-module scripts. |

## Before the first commit

```sh
git config core.hooksPath .githooks
```

Every commit then passes a `gitleaks` scan of what is staged. `scripts/ci.sh` scans the whole history and runs `govulncheck`. Install both with `go install`: `github.com/zricethezav/gitleaks/v8@latest` and `golang.org/x/vuln/cmd/govulncheck@latest`. A missing tool fails the run, because it must not read as a clean result.

The wire contract has its own gate in `scripts/ci.sh`, and it needs `buf` and the two protobuf generators, all three mandatory:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
npm install -g @bufbuild/buf@1.75.0      # or any other way to get buf 1.75.0
```

The generator versions are pinned to what the headers of `shared/gen` say. The script fails if the installed version differs, because another version writes other bytes and that would show up as a diff that is not a contract change. After editing a `.proto` file run `buf generate` in `shared/` and `sharedtool hash`, and commit the three together. The script then runs `buf lint`, generates into a temporary directory and compares it with `shared/gen`, and runs `buf breaking` (rule set `WIRE_JSON` plus the five `*_NO_DELETE` rules in `shared/buf.yaml`) against `scripts/proto-baseline/image.binpb`. That file is a committed Buf image of the released contract, so the check works in a shallow checkout, does not depend on tags, and gives the same answer on a clean tree and a dirty one. It does not move with ordinary commits: a break committed once stays a break in every later run. A missing or empty image fails the run; there is no skip.

The image moves only on purpose. At a phase gate, after the owner has accepted the contract, run `scripts/proto-baseline/move.sh` and commit the new image in a commit of its own, so the move is visible in the history and nothing else rides along with it. Never run it to make a failing `ci.sh` pass: that forgives the break for good. The image lives outside `shared/`, so nothing of it is synced to the Node repository. The Node repository regenerates nothing, so its CI has no such step.

## Tests

```sh
scripts/ci.sh            # everything; the container tests need Docker
scripts/ci.sh -short     # skips the tests that start Postgres
go test ./...            # same as above without the shared module
```

The database tests start a real Postgres 18 with testcontainers, create the roles with the same bootstrap SQL the installer uses, and apply the real migrations. There is no mock of Postgres anywhere. A missing Docker fails the run; `-short` is the explicit way to skip.

After changing a file under `migrations/postgres/src/`, run `scripts/gen-migrations.sh` and commit both the source and the expansion.

## Running the stack

```sh
docker build -f deploy/docker/Dockerfile -t ctrlz/panel:dev .   # first: gen-secrets runs the image to derive the key files
scripts/gen-secrets.sh                 # once; never overwrites, fails on a secret it cannot make or one that is empty
scripts/select-profile.sh              # writes deploy/compose/.env from the RAM it finds
# The two dashboard images (spec 3.2). Compose never builds or pulls them (pull_policy: never), so they must exist before up.
# HeroUI Pro installs from its own CDN with a token, and every build of the deps stage spends one of its daily downloads: build it
# once per lockfile, keep the image, and build the apps from it. The token goes in only as the BuildKit secret below, never as a
# build argument, an ENV or a file.
# Each line goes on only if the one before it worked: a missing ctrlz/web-deps:ci would otherwise be looked up on Docker Hub by the builds below.
docker build -f deploy/docker/web.Dockerfile --target deps-fresh --secret id=heroui_auth_token,env=HEROUI_AUTH_TOKEN -t ctrlz/web-deps:ci . \
  && docker image inspect ctrlz/web-deps:ci >/dev/null \
  && docker build -f deploy/docker/web.Dockerfile --build-arg APP=panel --build-arg DEPS_STAGE=ctrlz/web-deps:ci -t ctrlz/web-panel:dev . \
  && docker build -f deploy/docker/web.Dockerfile --build-arg APP=admin --build-arg DEPS_STAGE=ctrlz/web-deps:ci -t ctrlz/web-admin:dev .
docker compose -f deploy/compose/docker-compose.yml up -d
```

`HEROUI_AUTH_TOKEN` is read from the environment by name and is never written to a file. A rebuilt web image takes the same two `docker build` lines again; the deps image is rebuilt only when `pnpm-lock.yaml` changes, and an app build from a deps image made from another lockfile stops at a hash check (merge-r3-1). The hash detects a stale image, not a hostile one (the check runs inside the image), so never build from a name that is not on this machine. A deps image that `deps-fresh` did not make (installed by hand because the token is not a CDN token) has no hash and is refused: `CTRLZ_WEB_DEPS_IMAGE=<name> sh scripts/web-deps-stamp.sh` adds the hash of this checkout's `pnpm-lock.yaml` to it, and `CTRLZ_WEB_SKIP_DEPS=1 scripts/ci-web.sh` does the same for you. Both state that the image was installed from this lockfile, and neither overwrites a hash that is already there.

The image comes first because `gen-secrets.sh` creates `secrets/kek_root` (32 random bytes, 0400, host only, never mounted) and then runs `ctrlz keys derive` in a throw-away container (no network, read-only, all capabilities dropped, the host user) to write one `kek_<domain>` file per key domain. Every run derives the existing key files again from `kek_root` and compares them, so a deleted root, a wrong backup or a root made again is refused by proof and not by a file being there. Copy `kek_root` off the server and keep it apart from the database backups; the host copy may then be deleted (spec 8.3). Plain `docker build` reads no Compose secrets, so the image can exist before any secret does.

Networks (spec 17.2): `ingress` (Caddy), `hub_ingress` (hub), `web`, `app` and `backend` (internal, no route out) and `egress` (worker, for the SMS gateways). Only Caddy shares a network with the web containers and with `api` and `admin`; `api` and `admin` have no route out. `scripts/compose-net-test.sh` checks that on a running stack, `scripts/image-smoke.sh` checks the image (the `ctrlz-admin` link, the CA bundle), and `scripts/compose-smoke.sh` brings a throw-away production-mode stack up, runs `ctrlz-admin bootstrap` and `reset-password`, and greps every container log, the audit rows and the admin sessions for the printed one-time passwords (spec 18.4). Run the last one once per phase; it needs the image and Docker, and takes a few minutes.

Only Caddy (80, 443) is published in P1; the hub publishes nothing until its node channel exists (P4). The database, ClickHouse and Valkey are on an internal network. Passwords are Docker secrets, files under `secrets/`, which is not tracked.

**Upgrading an install of the earlier layout (one `valkey` service).** The stack now has two Valkey servers, `valkey-api` and `valkey-admin`, one for each trust zone. Bring the new file up with `--remove-orphans`:

Build the two web images first (the lines above): `up -d` does not build them, and stops on a missing `ctrlz/web-panel:dev` or `ctrlz/web-admin:dev`.

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --remove-orphans
docker volume rm ctrlz_valkey_data      # the old server's data; only rate-limit buckets, which are made again
```

Also write the `.env` again (`scripts/select-profile.sh --force`, which keeps the old file as `.env.bak`: copy your host names, ports and secret directory back from it): Compose refuses to run with an `.env` from before the pins, because such a file still holds floating image names and a Valkey memory size sized for one server that would now apply to each of the two. A plain `up -d` leaves the old `valkey` container running beside the new ones, still on `backend` with its password-less `health` user and one `maxmemory` for both services. Any container on `backend` can reach it, which is the hole the split closes, so it must go. The two zone volumes are new and start empty; a volume made by an earlier version of the zone files is owned by root and has to be removed once (`docker volume rm`).

`secrets/proof_key` is the key the hub derives UDP proof codes from (contract 3.5). It is mounted into the `hub` service only, shared with the nodes through `NodeConfig`, and never stored in Postgres; `TestProofKeyIsMountedIntoTheHubOnly` pins that.

No secret is a command-line argument or the environment of a long-running process; `TestComposeSecretsStayOutOfArgumentsAndEnvironments` pins that by the shape of the line, not by spellings to avoid: a line of a command, entrypoint or healthcheck that mentions a secret must be one of the lines in `allowedSecretLines` (`internal/lint/compose_test.go`), character for character (the Valkey start file `deploy/compose/valkey/start.sh` is judged by the same list), and anything else fails. A line counts as a mention when it names `secrets` or `/run`, expands a variable called `*_FILE` or containing `PASSWORD`, or holds a glob in a path word and reads a file. Only the readers on the list in `globReader` count as reading a file (a redirection, a command substitution, backticks, and `cat`, `head`, `tr`, `xargs`, `rev`, `cp`, `nl`, `tee` and the like), and a plain URL is not a path word, so the query string of a `wget` healthcheck is not a glob: only `http` or `https`, a host, an optional port, and a path and query in ordinary characters are skipped, with a variable allowed as the host or the port. Anything else stays in the line and is examined, so a URL with a brace expansion, a nested variable or a command in it, or one that names `IFS`, needs a listed line. A line that does none of these is not examined, so a path assembled from pieces at run time gets past the lint, and so does a glob read by a tool that is not on the list, or a variable named without its dollar sign. In the other direction the lint fails closed on a line that only looks like a glob path, such as a `sed` or `awk` expression with `/…*` in it; put such a line on the list with the reason it is safe. A new use of a secret therefore needs a new line on that list, with the reason it is safe. Valkey has no password in its healthcheck and no user without one: each trust zone (api, admin) is a server of its own (`valkey-api`, `valkey-admin`) with one service user, and the healthcheck reads a heartbeat that the container's maintenance loop touches after each PONG; the start file refuses to start unless the service secret is one line of 32 or more letters and digits (what `gen-secrets.sh` makes), with at most one CR before its end, so a secret saved with CR LF still logs in, and a secret that is empty, holds a space or a second line stops the start (a space would turn the rest of the secret into ACL rules, and an empty one is a user that accepts any client). Every third-party image is pinned by tag and digest in `docker-compose.yml`, as a literal and the one place that names it (`deploy.Image` reads it for the Go tests; no variable of an `.env` overrides it); the Panel image is built here and never pulled (`pull_policy: never`, and `--pull never` in every script that runs it); a Go test starts a container only through `deploy.DockerRun`, which refuses an image that is not pinned; no variable of a long-running process holds a credential, and `TestNoPasswordIsAnEnvironmentOfALongRunningProcess` refuses any assignment before a command, `export` or `env` in `deploy/` or `scripts/` that is not on its list. ClickHouse gets a `users.d` file with the SHA-256 of its password, written by the entrypoint wrapper, and the official entrypoint's own user setup is switched off. Because of that the wrapper is the only thing between the server and a user without a password, so it runs under `set -eu`, stops with a message on stderr and a non-zero exit when the secret is empty (a file of only CR LF counts as empty, as it does for the Go services), and stops when it cannot write `users.d`. CR and LF are removed before the hash so the shell and `secret.FromFile` agree on the password. `TestClickHouseWrapper*` runs the real `clickhouse-server:26.2` container for each of these cases and needs Docker. For that reason the compose file does not set `CLICKHOUSE_DB`: the entrypoint would put the password on the command line of `clickhouse-client` to create it, so the `ctrlz` database is created by the ClickHouse migrations in P5.

**SMS gateway credentials need the console (spec 10.8).** Credentials entered on the admin SMS page are only pending: they carry no login code. On the server, `ctrlz-admin sms pending` lists what waits (provider and hint, never the credentials), and `ctrlz-admin sms confirm <provider> --hint H` makes them the active ones. After a lost `sms_cred` key (`ctrlz-admin keys declare-lost sms_cred --key-number N --yes`) the steps are: make a new key, enter the credentials again on the SMS page, then confirm them at the console, or every OTP login keeps failing.
