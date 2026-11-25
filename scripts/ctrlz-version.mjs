#!/usr/bin/env node
// The one place that says which version a web image is (T-124). The Dockerfile takes it as `--build-arg CTRLZ_VERSION=...`
// and bakes it into the bundle as NEXT_PUBLIC_CTRLZ_VERSION, which the logo menu shows; every `docker build` of
// deploy/docker/web.Dockerfile (scripts/ci-web.sh, and the commands in the compose files and the Dockerfile header) takes the
// value from here, so no script spells its own.
//
//   node scripts/ctrlz-version.mjs
//
// Order: CTRLZ_VERSION from the environment (a release job names the tag), else `git describe --tags --always --dirty` of the tree
// the image is built from (a tag when one exists, else the short commit, with `-dirty` for uncommitted changes), else `dev`.
// `dev` is also what a developer's plain `next build` shows, since nothing sets the variable there. The value is checked,
// because it ends up in a page: anything but letters, digits and `._+-` (up to 64) is refused and falls through to the next source.
//
// The Docker context has no `.git` (web.Dockerfile.dockerignore), so the value is computed on the host and passed in, never in the image.
import {spawnSync} from "node:child_process";
import {fileURLToPath, pathToFileURL} from "node:url";

export const FALLBACK = "dev";
const SAFE = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/;

/** `value` when it is a safe, non-empty version string, else undefined. */
export function cleanVersion(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  return SAFE.test(trimmed) ? trimmed : undefined;
}

function gitDescribe(cwd) {
  const run = spawnSync("git", ["describe", "--tags", "--always", "--dirty"], {cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"]});
  return run.status === 0 ? run.stdout : undefined;
}

/** The version to build with. `env` and `describe` are parameters for the test. */
export function ctrlzVersion({env = process.env, describe = gitDescribe, cwd = fileURLToPath(new URL("..", import.meta.url))} = {}) {
  return cleanVersion(env.CTRLZ_VERSION) ?? cleanVersion(describe(cwd)) ?? FALLBACK;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.stdout.write(`${ctrlzVersion()}\n`);
}
