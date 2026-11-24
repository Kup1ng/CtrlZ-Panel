import {existsSync, readdirSync, readFileSync, statSync} from "node:fs";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

// scripts/ci-web.sh step 10 needs Docker and has not run (the auth review's CI owns it until the merge).
// What can be pinned without Docker is the shape of the script, so the three mistakes the first review
// round found cannot come back unseen: a seed without the stack's env file (wp12-r1-1), a temporary
// directory that is not a host path (wp12-r1-2), and a missing image found in the middle of 10c (wp12-r1-3).

const root = fileURLToPath(new URL("../../../", import.meta.url));
const script = readFileSync(`${root}scripts/ci-web.sh`, "utf8");
const code = script
  .split("\n")
  .filter((l) => !/^\s*#/.test(l))
  .join("\n");
const step10 = code.slice(code.indexOf('if [ "${CTRLZ_WEB_STACK:-0}" = 1 ]'));

describe("ci-web.sh step 2: the generated-files hash", () => {
  const body = code.slice(code.indexOf("generated_hash() {"), code.indexOf("before=$(generated_hash)"));

  it("hashes only paths that exist, and each directory holds files (a dead find hashes nothing)", () => {
    const dirs = [...body.matchAll(/find (\S+) .*-type f/g)].map((m) => m[1]);
    const files = [...body.matchAll(/^\s*echo (\S+)$/gm)].map((m) => m[1]);
    expect(dirs.length).toBeGreaterThan(0);
    for (const d of dirs) {
      expect(existsSync(`${root}${d}`), d).toBe(true);
      const names = readdirSync(`${root}${d}`, {recursive: true}).filter((n) => statSync(`${root}${d}/${String(n)}`).isFile());
      expect(names.length, `${d} holds no file, so the hash covers nothing`).toBeGreaterThan(0);
    }
    for (const f of files) expect(existsSync(`${root}${f}`), f).toBe(true);
  });

  it("covers the generated icons, the API types and the radius file", () => {
    expect(body).toContain("packages/api-client/src/generated");
    expect(body).toContain("packages/icons/src/generated");
    expect(body).toContain("packages/ui/styles/radius.generated.css");
  });
});

describe("ci-web.sh step 10", () => {
  it("keeps its temporary directory as a host path, since native docker and node get it unconverted", () => {
    expect(step10).toMatch(/host_path\(\) \{[^}]*cygpath -m/);
    expect(step10).toMatch(/work=\$\(host_path "\$\(mktemp -d\)"\)/);
    expect(step10, "a bare mktemp -d for work would be an MSYS path").not.toMatch(/work=\$\(mktemp/);
  });

  it("gives the e2e seed the env file of the stack (CTRLZ_SECRETS_DIR lives there)", () => {
    const calls = step10.split("\n").filter((l) => l.includes("scripts/e2e-seed.mjs"));
    expect(calls.length).toBeGreaterThan(0);
    for (const c of calls) expect(c).toContain('--env-file "$work/env"');
  });

  it("gives every docker compose call of the e2e project the env file", () => {
    // A call can span lines with a backslash, so read each logical command.
    const logical = step10.replace(/\\\n/g, " ").split("\n").filter((l) => /docker compose -p "\$project"/.test(l));
    // cleanup() and the two helpers (offline_compose, web_compose) that every other call goes through.
    expect(logical.length).toBeGreaterThanOrEqual(3);
    for (const l of logical) expect(l, l).toContain('--env-file "$work/env"');
  });

  it("writes the secrets directory into the env file and reads the file back by the same path", () => {
    expect(step10).toMatch(/printf 'CTRLZ_SECRETS_DIR=%s\\n' "\$work\/secrets"/);
    expect(step10).toMatch(/> "\$work\/env"/);
  });

  it("checks that the image exists before it makes anything, with a message that says what to run", () => {
    const check = step10.indexOf('docker image inspect "$image"');
    expect(check).toBeGreaterThan(-1);
    expect(check).toBeLessThan(step10.indexOf("mktemp -d"));
    expect(check).toBeLessThan(step10.indexOf("gen-secrets.sh"));
    expect(step10).toMatch(/image="\$\{CTRLZ_IMAGE:-ctrlz\/panel:dev\}"/);
    expect(script).toMatch(/docker build -f deploy\/docker\/Dockerfile -t \$image/);
  });
});

// wp5-r20-1: a step that is skipped because a file is missing makes the gate fail open, and the run still
// exits 0. The class: a skip is allowed only as an explicit opt-in variable, so it is never a consequence
// of the tree's own state.
describe("ci-web.sh skips", () => {
  const lines = code.split("\n");

  it("skips a step only under a CTRLZ_WEB_SKIP_* opt-in, never because a file is missing", () => {
    const calls = lines.map((l, i) => ({l, i})).filter(({l}) => /^\s*skip \d+ /.test(l));
    expect(calls.length).toBeGreaterThan(0);
    for (const {l, i} of calls) {
      // The nearest `if` above the call, at a shallower indent, is the condition that guards it.
      const indent = l.search(/\S/);
      let guard = "";
      for (let j = i - 1; j >= 0; j--) {
        const above = lines[j] ?? "";
        if (above.trim() !== "" && above.search(/\S/) < indent && /^\s*if /.test(above)) {
          guard = above;
          break;
        }
      }
      expect(guard, `${l.trim()} is not under an if`).not.toBe("");
      expect(guard, `${l.trim()} must be guarded by an opt-in variable`).toMatch(/CTRLZ_WEB_SKIP_[A-Z0-9_]+:-0\}" = 1/);
    }
  });

  it("runs the bundle gate and its named tests with no condition, so a missing script fails step 7", () => {
    const step7 = code.slice(code.indexOf('step 7 "'), code.indexOf('step 8 "'));
    expect(step7).toMatch(/^node scripts\/check-web-bundle\.mjs$/m);
    expect(step7).toMatch(/^\(cd tools\/web-lint && pnpm exec vitest run test\/check-web-bundle\)$/m);
    expect(step7).not.toMatch(/\bif\b|\bskip\b|\[ -f /);
    expect(existsSync(`${root}scripts/check-web-bundle.mjs`)).toBe(true);
  });

  // gate-r13-2
  it("also runs the data: and blob: URI check of the built files, and its tests, with no condition", () => {
    const step7 = code.slice(code.indexOf('step 7 "'), code.indexOf('step 8 "'));
    expect(step7).toMatch(/^node tools\/web-lint\/check-built-uris\.mjs$/m);
    expect(step7).toMatch(/^\(cd tools\/web-lint && pnpm exec vitest run test\/check-built-uris\)$/m);
    expect(step7).not.toMatch(/\bif\b|\bskip\b|\[ -f /);
    expect(existsSync(`${root}tools/web-lint/check-built-uris.mjs`)).toBe(true);
  });
});

// merge-r4-1, -7, -8, -9, -2: the log scans, the one case that makes Next log on purpose, the noop file and the deps stamp. Step 10 needs Docker, so what
// can be pinned is where each line is and what it does not do.
// The comments name the steps (10d1, 10f1), so positions are read from the full text and what is judged is the code between them.
const full10 = script.slice(script.indexOf('if [ "${CTRLZ_WEB_STACK:-0}" = 1 ]'));
const section = (from: string, to?: string) => {
  const start = full10.indexOf(from);
  expect(start, from).toBeGreaterThan(-1);
  const end = to ? full10.indexOf(to, start) : -1;
  return full10
    .slice(start, end > 0 ? end : undefined)
    .split("\n")
    .filter((l) => !/^\s*#/.test(l))
    .join("\n");
};

describe("ci-web.sh step 10, the log scans (merge-r4-8)", () => {
  it("reads the web logs into a file and fails when they cannot be read or are empty, instead of scanning an error message", () => {
    const scan = section("# 10d1. ", "# 10d1b.");
    expect(scan).toMatch(/web_compose logs [^\n]*> "\$work\/web\.log" 2>&1 \|\| fail/);
    expect(scan).toMatch(/\[ -s "\$work\/web\.log" \] \|\| fail/);
    expect(scan, "a swallowed status is a scan that passes on nothing").not.toMatch(/logs [^\n]*\|\| true/);
    expect(scan).toContain("ECONNRESET|aborted");
  });

  it("scans each front log from a file, fails on an unreadable or empty one, and looks for the codes of the noop file as well as the seed", () => {
    const scan = section("# 10f1. ");
    expect(scan).toMatch(/web_compose logs [^\n]*> "\$work\/front\.log" 2>&1 \|\| fail/);
    expect(scan).toMatch(/\[ -s "\$work\/front\.log" \] \|\| fail/);
    expect(scan).toContain("scripts/ci-web-leak-patterns.mjs");
    expect(scan).toContain("deploy/compose/e2e-out/noop.jsonl");
    expect(scan, "no status of the log read may be dropped").not.toMatch(/logs [^\n]*\|\| true|logs [^\n]*\| grep/);
    expect(scan).toMatch(/grep -c -E -f "\$work\/leak-regex"/);
  });
});

describe("ci-web.sh step 10, the stalled POST (merge-r4-1, merge-r4-7)", () => {
  it("runs after the scan of the web logs, alone and with E2E_STALLED_POST=1, and the main run never sets it", () => {
    const scan = full10.indexOf("# 10d1. ");
    const stalled = full10.indexOf("# 10d1b.");
    expect(scan).toBeGreaterThan(-1);
    expect(stalled, "10d1b is after 10d1").toBeGreaterThan(scan);
    const after = section("# 10d1b.", "# 10d2.");
    expect(after).toContain("E2E_STALLED_POST=1");
    expect(after).toContain('-g "never finished"');
    const main = section("  # Every project of both apps", "# 10d1. ");
    expect(main, "the main Caddy run must not enable the case").not.toContain("E2E_STALLED_POST");
    expect(main).toContain("playwright test $projects");
  });
});

describe("ci-web.sh step 10, the files the containers write (merge-r4-9)", () => {
  it("makes the noop SMS file readable by the host user before the stack starts, since the driver appends to an existing file and creates it 0600", () => {
    const made = step10.indexOf(": > deploy/compose/e2e-out/noop.jsonl");
    expect(made).toBeGreaterThan(-1);
    expect(step10).toContain("chmod 0666 deploy/compose/e2e-out/noop.jsonl");
    expect(made).toBeLessThan(step10.indexOf("offline_compose up"));
  });
});

describe("ci-web.sh step 10, a deps image that deps-fresh did not make (merge-r4-2)", () => {
  it("stamps it in the CTRLZ_WEB_SKIP_DEPS branch, with a script that exists and never overwrites a hash", () => {
    expect(step10).toContain('CTRLZ_WEB_DEPS_IMAGE="$deps_image" sh scripts/web-deps-stamp.sh');
    const stamp = readFileSync(`${root}scripts/web-deps-stamp.sh`, "utf8");
    // The same file name and format as the Dockerfile writes and checks, or the check in the build stage would still fail.
    expect(stamp).toContain("sha256sum pnpm-lock.yaml > /deps-lock.sha256");
    expect(readFileSync(`${root}deploy/docker/web.Dockerfile`, "utf8")).toContain("sha256sum pnpm-lock.yaml > /deps-lock.sha256");
    expect(stamp).toMatch(/--pull never/);
    expect(stamp, "an image that carries another lockfile's hash is refused, not stamped over").toContain("was installed from another pnpm-lock.yaml");
  });
});
