import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

// Merge items A14 and A15 (web-merge-items.md): what the base Compose file and deploy/docker/web.Dockerfile must say about the two
// web containers. Starting them is the Caddy run's job (an unhealthy container with a wrong CTRLZ_VERIFY_ORIGIN, scripts/ci-web.sh
// step 10); these tests keep the text from drifting before that run can see it.
const root = fileURLToPath(new URL("../../../", import.meta.url));
const compose = readFileSync(`${root}deploy/compose/docker-compose.yml`, "utf8");
const dockerfile = readFileSync(`${root}deploy/docker/web.Dockerfile`, "utf8");
const code = (text: string) => text.replace(/^\s*#.*$/gm, "");

/** One service of the Compose file: from `  name:` to the next two-space key. */
function service(name: string): string {
  const start = compose.indexOf(`\n  ${name}:\n`);
  expect(start, `service ${name}`).toBeGreaterThan(0);
  const rest = compose.slice(start + 1);
  const end = rest.slice(1).search(/\n {2}[a-z][a-z0-9-]*:\n|\n[a-z]/);
  return code(end < 0 ? rest : rest.slice(0, end + 1));
}

describe.each([
  ["web-panel", "PANEL"],
  ["web-admin", "ADMIN"],
])("%s in docker-compose.yml (A14)", (name, upper) => {
  const body = service(name);

  it("asks a page for its health, never a file of public/ (a wrong CTRLZ_VERIFY_ORIGIN leaves those at 200)", () => {
    const test = /test: (\[.*\])/.exec(body)?.[1] ?? "";
    expect(test, "a healthcheck").not.toBe("");
    expect(test).toContain("/fa/login");
    expect(test).not.toMatch(/logo\.png|icon\.png/);
    expect(test, "only a 200 is healthy: a 500 from the proxy must fail it").toContain("r.status===200");
  });

  it("runs the image of the web Dockerfile, built here and never pulled, with a read-only root and its own network only", () => {
    expect(body).toMatch(new RegExp(`image: \\$\\{CTRLZ_WEB_${upper}_IMAGE:-ctrlz/web-${name.slice(4)}:[a-z0-9.-]+\\}`));
    expect(body).toContain("pull_policy: never");
    expect(body).toContain("<<: *hardened");
    expect(body).toContain("networks: [web]");
    expect(body).not.toMatch(/busybox|web-placeholder|volumes:|secrets:|build:|command:|ports:/);
  });
});

describe("deploy/docker/web.Dockerfile (A15)", () => {
  const text = code(dockerfile);

  it("copies public/ and .next/static next to the standalone server.js, which Next does not copy itself", () => {
    expect(text).toMatch(/COPY --from=build \/src\/apps\/\$APP\/\.next\/standalone \.\//);
    expect(text).toMatch(/COPY --from=build \/src\/apps\/\$APP\/\.next\/static \.\/apps\/\$APP\/\.next\/static/);
    expect(text).toMatch(/COPY --from=build \/src\/apps\/\$APP\/public \.\/apps\/\$APP\/public/);
    expect(text).toMatch(/WORKDIR \/app\/apps\/\$APP\n/);
    expect(text).toContain('CMD ["node", "server.js"]');
  });

  it("never sets NEXT_PRIVATE_MINIMAL_MODE, and runs as the unprivileged user", () => {
    expect(text).not.toContain("NEXT_PRIVATE_MINIMAL_MODE");
    expect(text).toContain("USER 65532:65532");
  });

  it("hands the install token to the install step as a BuildKit secret only", () => {
    expect(text).toContain("RUN --mount=type=secret,id=heroui_auth_token,env=HEROUI_AUTH_TOKEN pnpm install --frozen-lockfile");
    // The name may appear in that one line and nowhere else: not as ARG, ENV, a COPY of a file or a second RUN.
    const mentions = text.split("\n").filter((line) => line.includes("HEROUI_AUTH_TOKEN"));
    expect(mentions).toHaveLength(1);
    expect(text).not.toMatch(/^\s*(ARG|ENV)\s+HEROUI/m);
  });

  it("can start from a saved deps image, so a rebuild needs no token and no CDN, and checks which app it builds", () => {
    expect(text).toMatch(/^ARG DEPS_STAGE=deps-fresh$/m);
    expect(text).toMatch(/^FROM \$\{DEPS_STAGE\} AS build$/m);
    expect(text).toContain('test "$APP" = panel || test "$APP" = admin');
  });

  // merge-r1-10: a syntax directive makes BuildKit pull docker/dockerfile from Docker Hub by tag, in the build that holds the install token.
  it("has no syntax directive, so no unpinned frontend image runs with the install token", () => {
    expect(text).not.toMatch(/^#\s*syntax\s*=/im);
    expect(text).toContain("--mount=type=secret,id=heroui_auth_token,env=HEROUI_AUTH_TOKEN");
  });

  it("pins its base image by digest, and switches Next's telemetry off in the final image", () => {
    const from = text.split("\n").filter((line) => /^FROM node:/.test(line));
    expect(from).toHaveLength(2);
    for (const line of from) expect(line).toMatch(/^FROM node:26\.13-slim@sha256:[0-9a-f]{64}/);
    expect(text.split("FROM ").at(-1)).toContain("NEXT_TELEMETRY_DISABLED=1");
  });

  it("has its own ignore file, since the root one excludes the web workspaces", () => {
    const ignore = readFileSync(`${root}deploy/docker/web.Dockerfile.dockerignore`, "utf8");
    for (const entry of ["**/node_modules", "**/.next", "secrets", ".git"]) expect(ignore).toContain(entry);
    // merge-r1-6: Next's standalone output copies the app's loaded .env files into the image.
    for (const entry of ["**/.env", "**/.env.*"]) expect(ignore.split("\n")).toContain(entry);
    for (const dir of ["apps", "packages", "content", "tools"]) expect(ignore).not.toMatch(new RegExp(`^${dir}$`, "m"));
  });
});

// merge-r4-5. The hash check runs inside the image it judges, so it cannot stop a foreign image; what does is that the name is never pulled.
describe("the deps image name is never looked up on Docker Hub (merge-r4-5)", () => {
  const readme = readFileSync(`${root}README.md`, "utf8");

  it("the README builds the apps only after the image is found on this machine, in one chained command", () => {
    const start = readme.indexOf("--target deps-fresh");
    expect(start).toBeGreaterThan(-1);
    const block = readme.slice(readme.lastIndexOf("docker build", start), readme.indexOf("docker compose -f deploy/compose/docker-compose.yml up -d", start));
    const inspect = block.indexOf("docker image inspect ctrlz/web-deps:ci");
    expect(inspect).toBeGreaterThan(-1);
    for (const app of ["APP=panel", "APP=admin"]) expect(block.indexOf(app), `${app} comes after the inspect`).toBeGreaterThan(inspect);
    // Every line that starts a docker command but the first is joined to the one before it.
    const commands = block.split("\n").filter((l) => /^\s*(&& )?docker /.test(l));
    for (const line of commands.slice(1)) expect(line.trim().startsWith("&&"), line).toBe(true);
  });

  it("the Dockerfile says what its check does not do, and no longer claims that a foreign image fails it", () => {
    expect(dockerfile).toContain("It does not catch a hostile image");
    expect(dockerfile).not.toContain("A deps image from another source has no such file and fails here too");
  });
});
