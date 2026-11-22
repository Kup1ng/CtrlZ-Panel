// Validates the SVG sources and generates src/generated/**.
//
//   node scripts/build.mjs           write the generated files
//   node scripts/build.mjs --check   write nothing, fail if a file is missing or out of date (CI)
//
// Spec 7.3 and 7.4. The generated files are committed, so a build of the apps needs
// no step before it, and CI re-runs this with --check.
import {existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {dirname, join, relative} from "node:path";
import {fileURLToPath} from "node:url";
import {METHOD, componentSource, parseProvenance, pascal, registrySource, validateIconSvg, validateLooseSvg} from "./lib.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const check = process.argv.includes("--check");
const problems = [];
const fail = (where, what) => problems.push(`${where}: ${what}`);

const SLUG = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const GROUP = /^[a-z][a-z0-9]*$/;

const list = (dir, ext) => (existsSync(dir) ? readdirSync(dir, {withFileTypes: true}) : []).filter((e) => e.isFile() && e.name.endsWith(ext)).map((e) => e.name).sort();
const read = (p) => readFileSync(p, "utf8").replace(/\r\n/g, "\n");

// 1. Our own icon set.
const provenance = existsSync(join(root, "PROVENANCE.md")) ? parseProvenance(read(join(root, "PROVENANCE.md"))) : new Map();
const out = new Map(); // path relative to the package -> content
const groups = [];
const seenFiles = new Set();

const svgDir = join(root, "svg");
const groupNames = (existsSync(svgDir) ? readdirSync(svgDir, {withFileTypes: true}) : []).filter((e) => e.isDirectory()).map((e) => e.name).sort();
for (const group of groupNames) {
  if (!GROUP.test(group)) fail(`svg/${group}`, "group folder names are lower-case letters and digits");
  const names = [];
  for (const file of list(join(svgDir, group), ".svg")) {
    const rel = `svg/${group}/${file}`;
    const slug = file.slice(0, -4);
    seenFiles.add(rel);
    if (!SLUG.test(slug)) fail(rel, "file names are lower-case kebab-case");
    const source = read(join(svgDir, group, file));
    for (const e of validateIconSvg(source)) fail(rel, e);
    const row = provenance.get(rel);
    if (!row) fail(rel, "has no row in PROVENANCE.md");
    else {
      if (row.method !== METHOD.svg) fail(rel, `PROVENANCE.md method is "${row.method}", expected "${METHOD.svg}"`);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(row.date)) fail(rel, "PROVENANCE.md date is not YYYY-MM-DD");
      if (!row.author) fail(rel, "PROVENANCE.md author is empty");
    }
    names.push(slug);
    if (problems.length === 0) {
      out.set(`src/generated/${group}/${pascal(slug)}.tsx`, componentSource({exportName: pascal(slug), sourcePath: rel, svg: source, brand: false}));
    }
  }
  if (names.length) groups.push([group, names]);
}
if (groups.length) out.set("src/generated/registry.ts", registrySource(groups));

// 2. The brand mark (spec 7.4, D14). Supplied by the owner, so it is validated loosely.
const brandDir = join(root, "brand");
for (const file of list(brandDir, ".svg")) {
  const rel = `brand/${file}`;
  seenFiles.add(rel);
  const source = read(join(brandDir, file));
  for (const e of validateLooseSvg(source)) fail(rel, e);
  const row = provenance.get(rel);
  if (!row) fail(rel, "has no row in PROVENANCE.md");
  else if (row.method !== METHOD.brand) fail(rel, `PROVENANCE.md method is "${row.method}", expected "${METHOD.brand}"`);
  const name = pascal(file.slice(0, -4).toLowerCase());
  if (problems.length === 0) out.set(`src/generated/brand/${name}.tsx`, componentSource({exportName: name, sourcePath: rel, svg: source, brand: true}));
}
if (!existsSync(join(brandDir, "Logo.png"))) fail("brand/Logo.png", "missing; apps/*/public/logo.png and the favicon are made from it");

// A provenance row for a file that is gone is as wrong as a file with no row.
for (const rel of provenance.keys()) if (!seenFiles.has(rel)) fail(rel, "has a row in PROVENANCE.md but no file");

// 3. Service logos (spec 7.4): every file has a manifest entry and the reverse.
const logoDir = join(root, "logos");
const manifestPath = join(logoDir, "manifest.json");
if (!existsSync(manifestPath)) fail("logos/manifest.json", "missing");
else {
  let manifest;
  try {
    manifest = JSON.parse(read(manifestPath));
  } catch (e) {
    fail("logos/manifest.json", `is not JSON: ${e.message}`);
  }
  if (manifest !== undefined && !Array.isArray(manifest)) fail("logos/manifest.json", "must be an array");
  else if (manifest) {
    const files = new Set(list(logoDir, ".svg").map((f) => f.slice(0, -4)));
    const slugs = new Set();
    for (const [i, entry] of manifest.entries()) {
      const where = `logos/manifest.json[${i}]`;
      if (typeof entry?.slug !== "string" || !/^[a-z0-9-]+$/.test(entry.slug)) fail(where, "slug must match ^[a-z0-9-]+$");
      for (const k of ["source", "licence", "licenceUrlAsText"]) if (typeof entry?.[k] !== "string" || entry[k] === "") fail(where, `${k} is required`);
      if (slugs.has(entry?.slug)) fail(where, `repeats slug ${entry.slug}`);
      slugs.add(entry?.slug);
      if (!files.has(entry?.slug)) fail(where, `has no logos/${entry?.slug}.svg`);
    }
    for (const f of files) {
      if (!slugs.has(f)) fail(`logos/${f}.svg`, "has no entry in logos/manifest.json");
      for (const e of validateLooseSvg(read(join(logoDir, `${f}.svg`)))) fail(`logos/${f}.svg`, e);
    }
  }
}

if (problems.length) {
  console.error(`icons: ${problems.length} problem${problems.length === 1 ? "" : "s"}\n` + problems.map((p) => `  ${p}`).join("\n"));
  process.exit(1);
}

// 4. Write, or compare.
const genRoot = join(root, "src", "generated");
const onDisk = new Set();
const walkDir = (dir) => {
  if (!existsSync(dir)) return;
  for (const e of readdirSync(dir, {withFileTypes: true})) {
    if (e.isDirectory()) walkDir(join(dir, e.name));
    else onDisk.add(relative(root, join(dir, e.name)).replaceAll("\\", "/"));
  }
};
walkDir(genRoot);

const stale = [];
for (const [rel, content] of out) {
  const p = join(root, rel);
  const current = existsSync(p) ? read(p) : null;
  if (current !== content) {
    stale.push(rel);
    if (!check) {
      mkdirSync(dirname(p), {recursive: true});
      writeFileSync(p, content);
    }
  }
}
const extra = [...onDisk].filter((rel) => !out.has(rel));
if (!check) for (const rel of extra) rmSync(join(root, rel));

if (check && (stale.length || extra.length)) {
  console.error(
    "icons: src/generated is out of date. Run `pnpm --filter @ctrlz/icons build` and commit the result.\n" +
      [...stale.map((s) => `  changed or missing: ${s}`), ...extra.map((s) => `  not generated any more: ${s}`)].join("\n"),
  );
  process.exit(1);
}
const total = [...groups].reduce((n, [, names]) => n + names.length, 0);
console.log(`icons: ${total} icons in ${groups.length} groups, ${check ? "generated files are current" : `${stale.length} written, ${extra.length} removed`}`);
