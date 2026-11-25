// Step 8 of scripts/ci-web.sh (spec 16.2, T-471): the licence of every installed package is a type
// from tools/web-lint/licences.allow.txt, or the package is named there with a reason.
//
//   node tools/web-lint/check-licences.mjs            run `pnpm licenses list -r --json` and compare
//   node tools/web-lint/check-licences.mjs <file>     compare a saved listing (used by the test)
import {spawnSync} from "node:child_process";
import {readFileSync} from "node:fs";
import {fileURLToPath, pathToFileURL} from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));

/** The `type` and `package` lines of the allow file. A line without a reason after " # " is an error. */
export function parseAllow(text) {
  const types = new Set();
  const packages = [];
  const problems = [];
  text.split("\n").forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const [decision, ...reason] = line.split(" # ");
    const m = /^(type|package)\s+(\S.*?)\s*$/.exec(decision ?? "");
    if (!m) return problems.push(`line ${i + 1}: not "type <SPDX>" or "package <name>": ${line}`);
    if (reason.join(" # ").trim() === "") return problems.push(`line ${i + 1}: no reason after " # ": ${line}`);
    if (m[1] === "type") types.add(m[2]);
    else packages.push(m[2]);
  });
  return {types, packages, problems};
}

/** True when every licence named in an SPDX expression is an allowed type. */
export function expressionAllowed(expression, types) {
  if (types.has(expression)) return true;
  const parts = expression
    .replace(/[()]/g, " ")
    .split(/\s+(?:AND|OR)\s+|\s+/)
    .map((s) => s.trim())
    .filter((s) => s && s !== "AND" && s !== "OR");
  return parts.length > 1 && parts.every((p) => types.has(p));
}

const packageAllowed = (name, packages) => packages.some((p) => (p.endsWith("*") ? name.startsWith(p.slice(0, -1)) : name === p));

/**
 * `listing` is the JSON of `pnpm licenses list --json`: licence to the packages that carry it.
 * Returns one line per package that is not allowed, and the allow lines that matched nothing, which
 * keeps the file honest (a stale exception is a hole waiting for the next package of that name).
 */
export function checkLicences(listing, allowText) {
  const allow = parseAllow(allowText);
  const failures = [...allow.problems];
  const seen = new Set();
  for (const [licence, list] of Object.entries(listing)) {
    for (const p of list) {
      seen.add(p.name);
      if (expressionAllowed(licence, allow.types) || packageAllowed(p.name, allow.packages)) continue;
      failures.push(`${p.name}@${(p.versions ?? []).join("/")}: licence "${licence}" is not allowed`);
    }
  }
  for (const pkg of allow.packages) {
    const used = pkg.endsWith("*") ? [...seen].some((n) => n.startsWith(pkg.slice(0, -1))) : seen.has(pkg);
    if (!used) failures.push(`allow file names "${pkg}", which is not installed: remove the line`);
  }
  return failures;
}

function main() {
  const file = process.argv[2];
  let json;
  if (file) json = readFileSync(file, "utf8");
  else {
    // shell: true because pnpm is pnpm.cmd on Windows. The arguments are fixed.
    const run = spawnSync("pnpm licenses list -r --json", {encoding: "utf8", shell: true, maxBuffer: 64 * 1024 * 1024});
    if (run.status !== 0) {
      console.error(`check-licences: pnpm licenses failed (${run.status}): ${(run.stderr ?? "").slice(0, 400)}`);
      process.exit(1);
    }
    json = run.stdout;
  }
  const listing = JSON.parse(json);
  const failures = checkLicences(listing, readFileSync(`${here}licences.allow.txt`, "utf8"));
  const count = Object.values(listing).reduce((n, list) => n + list.length, 0);
  if (failures.length > 0) {
    console.error(`check-licences: ${failures.length} problem(s)\n${failures.map((f) => `  ${f}`).join("\n")}`);
    process.exit(1);
  }
  console.log(`check-licences: ${count} packages, ${Object.keys(listing).length} licence types, all allowed`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
