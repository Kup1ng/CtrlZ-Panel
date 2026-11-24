// The "P1 token test" of DESIGN.md and spec 6.3 (T-474).
//
//   node tools/web-lint/check-rounded-field.mjs
//
// HeroUI rounds a field with `rounded-field`, which is the field radius token. Our rule is that
// no control takes its corner from a token: every control row of packages/ui/tokens/radius.table.ts
// computes it from the control's height. A selector in the installed HeroUI CSS that still uses
// `rounded-field` (or `--radius-field`) and has neither a row in the table nor a line in
// tools/web-lint/radius.unused.txt would keep the stock corner, and nobody would notice. So a
// HeroUI upgrade that adds one, or a new component that we adopt, fails here.
//
// The CSS is read where pnpm put it for packages/ui, which is the only package that depends on
// HeroUI (spec 18, WP0 note).
import {readdirSync, readFileSync, statSync} from "node:fs";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const UI = join(ROOT, "packages/ui");

const FIELD_RADIUS = /rounded-(?:[a-z]{1,2}-)?field\b|--radius-field\b/;

const norm = (s) => s.replace(/\s+/g, " ").trim();

/**
 * The selectors in a stylesheet whose rule uses the field radius.
 * HeroUI's source CSS nests rules by indentation, so the selector of a line is the chain of
 * the block headers above it, with `&` replaced by the parent.
 * @param {string} css
 * @returns {string[]}
 */
export function fieldRadiusSelectors(css) {
  const stack = [];
  const found = new Set();
  const resolveChain = () => {
    let parts = [""];
    for (const {selectors} of stack) {
      parts = parts.flatMap((parent) =>
        selectors.map((sel) => (parent === "" ? sel : sel.includes("&") ? sel.replaceAll("&", parent) : `${parent} ${sel}`)),
      );
    }
    return parts;
  };
  for (const raw of css.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("/*") || line.startsWith("*") || line.startsWith("//")) continue;
    if (line.endsWith("{")) {
      const head = line.slice(0, -1).trim();
      // At-rules (`@media`, `@layer`) do not name an element.
      stack.push({selectors: head.startsWith("@") ? [""] : head.split(",").map(norm)});
      continue;
    }
    if (line === "}") {
      stack.pop();
      continue;
    }
    if (FIELD_RADIUS.test(line)) for (const s of resolveChain()) if (s) found.add(norm(s));
  }
  return [...found];
}

/** Selectors of the rows of the table, one entry per comma-separated part. */
export function tableSelectors(rows) {
  return new Set(rows.flatMap((r) => r.selector.split(",").map(norm)));
}

/** `selector # reason` lines of radius.unused.txt. A line without a reason is itself a finding. */
export function readUnused(text) {
  const selectors = new Set();
  const problems = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (t === "" || t.startsWith("#")) continue;
    const at = t.indexOf(" # ");
    if (at < 0 || t.slice(at + 3).trim() === "") problems.push(`radius.unused.txt: no reason on "${t}"`);
    selectors.add(norm(at < 0 ? t : t.slice(0, at)));
  }
  return {selectors, problems};
}

/** @returns {string[]} one line per selector that has neither a row nor a reason */
export function checkRoundedField(stylesheets, rows, unusedText) {
  const covered = tableSelectors(rows);
  const {selectors: unused, problems} = readUnused(unusedText);
  const findings = [...problems];
  for (const {file, css} of stylesheets) {
    for (const sel of fieldRadiusSelectors(css)) {
      if (!covered.has(sel) && !unused.has(sel)) findings.push(`${file}: ${sel} uses the field radius and has no row in radius.table.ts or reason in radius.unused.txt`);
    }
  }
  return findings;
}

function* cssIn(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) yield* cssIn(full);
    else if (name.endsWith(".css")) yield full;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const dirs = [
    join(UI, "node_modules/@heroui/styles/dist/components"),
    join(UI, "node_modules/@heroui-pro/react/dist/css/components"),
  ];
  const stylesheets = dirs.flatMap((d) => [...cssIn(d)]).map((full) => ({file: full.slice(UI.length + 1).replaceAll("\\", "/"), css: readFileSync(full, "utf8")}));
  const {rows} = await import(pathToFileURL(join(UI, "tokens/radius.table.ts")).href);
  const unused = readFileSync(join(ROOT, "tools/web-lint/radius.unused.txt"), "utf8");
  const findings = checkRoundedField(stylesheets, rows, unused);
  if (findings.length > 0) {
    console.error(`check-rounded-field: ${findings.length} finding(s)\n${findings.join("\n")}`);
    process.exit(1);
  }
  console.log(`check-rounded-field: ${stylesheets.length} stylesheets, every field-radius selector is covered`);
}
