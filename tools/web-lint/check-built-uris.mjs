// The built half of the img-src / font-src rule of spec 15.2 (gate-r13-2).
//
//   node tools/web-lint/check-built-uris.mjs      after `next build` of each app; exit 1 on a finding
//
// The policy has `img-src 'self'` and `font-src 'self'`, with no `data:` and no `blob:`. The browser guard of 17.2 only notices a refusal when
// a test renders the state that needs the image, so a library bump (HeroUI, HeroUI Pro, Tailwind) that adds `mask-image: url("data:image/svg+xml,...")`
// to a rarely seen state (an invalid-field mark, a disabled chevron, a checked box) keeps every test green and drops that icon in production.
// This script reads what ships, so the first such string is a review item: it fails, and a reviewed reason in inline-uri-allow.txt is the way out.
//
// Scanned per app: the CSS and JS of `.next/static` (what a browser downloads), the CSS, JS and SVG of `public/`, and what the server renders from
// (gate-r14-2): `.next/server/chunks` (the compiled Server Components, layouts and not-found pages, none of whose strings reach `.next/static`) and
// `.next/server/app` (the prerendered .html, .rsc and .body: the markup and the flight payload that a browser receives). Matched:
//   - `url(` followed by `data:` or `blob:` (a quote, a backslash-quote from CSS inside a JS string, and white space may sit between);
//   - a string literal that starts with `data:image/`, `data:font/` or `data:application/font`, which is how a script builds an image or a font.
// Not matched: a bare `data:` in a comment or a MIME check, which an image or font request does not make.
import {existsSync, readdirSync, readFileSync, statSync} from "node:fs";
import {join, relative, resolve, sep} from "node:path";
import {fileURLToPath} from "node:url";

const ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)), "../..");
const APPS = ["panel", "admin"];

const PATTERNS = [
  [/url\(\s*\\?["'`]?\s*(?:data|blob):/gi, "url(data:) or url(blob:)"],
  // The lookbehind keeps a quote that belongs to a url( from being reported twice.
  [/(?<!url\(\s*\\?)["'`]data:(?:image\/|font\/|application\/(?:x-)?font)/gi, "a data: image or font string"],
  [/(?<!url\(\s*\\?)["'`]blob:/gi, "a blob: string"],
];

/**
 * @param {{path: string, text: string}[]} files  path relative to the repository root, forward slashes
 * @param {string} allowText  inline-uri-allow.txt: `<path part>  # reason`, one per line
 * @returns {{found: string[], allowed: string[], stale: string[], problems: string[]}}
 */
export function findInlineUris(files, allowText = "") {
  const rules = [];
  const problems = [];
  allowText.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const [part, ...reason] = line.split("#");
    if (!part.trim() || reason.join("#").trim() === "") problems.push(`inline-uri-allow.txt:${i + 1}: a line is "<path part> # reason", and the reason is required`);
    else rules.push({part: part.trim(), line: i + 1, used: false});
  });
  const found = [];
  const allowed = [];
  for (const {path, text} of files) {
    for (const [re, what] of PATTERNS) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        const at = text.slice(0, m.index).split("\n").length;
        const rule = rules.find((r) => path.includes(r.part));
        // The snippet is short on purpose: a data URI can carry anything, and nothing of it is needed to find the place.
        const label = `${path}:${at}: ${what} (${JSON.stringify(m[0].slice(0, 24))})`;
        if (rule) {
          rule.used = true;
          allowed.push(label);
        } else found.push(label);
      }
    }
  }
  const stale = rules.filter((r) => !r.used).map((r) => `inline-uri-allow.txt:${r.line}: "${r.part}" explains nothing`);
  return {found, allowed, stale, problems};
}

function* walk(dir, extensions) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules") continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) yield* walk(full, extensions);
    else if (extensions.some((e) => name.endsWith(e))) yield full;
  }
}

/**
 * What ships from one app, or an error when there is no build: a missing build must not pass as "nothing found". A Server Component is compiled
 * into `.next/server/chunks` and reaches the browser as HTML and flight data, so a `data:` image written in one never appears under `.next/static`.
 * Source maps are skipped: they hold sources, not what runs, and every string in them would be reported twice.
 */
export function builtFiles(root, app) {
  const appDir = join(root, "apps", app);
  const staticDir = join(appDir, ".next", "static");
  if (!existsSync(staticDir)) throw new Error(`apps/${app}/.next/static does not exist: run next build first`);
  const out = [...walk(staticDir, [".css", ".js", ".mjs"])];
  const css = out.filter((f) => f.endsWith(".css")).length;
  const js = out.filter((f) => f.endsWith(".js")).length;
  if (css === 0 || js === 0) throw new Error(`apps/${app}: found ${css} CSS and ${js} JS files under .next/static, so the scan would check nothing`);
  const serverDir = join(appDir, ".next", "server");
  const chunksDir = join(serverDir, "chunks");
  const renderedJs = existsSync(chunksDir) ? [...walk(chunksDir, [".js", ".mjs"])] : [];
  if (renderedJs.length === 0) throw new Error(`apps/${app}: found no JS under .next/server/chunks, so the scan of the server half would check nothing`);
  out.push(...renderedJs);
  const appRenders = join(serverDir, "app");
  if (existsSync(appRenders)) out.push(...walk(appRenders, [".html", ".rsc", ".body"]));
  const publicDir = join(appDir, "public");
  if (existsSync(publicDir)) out.push(...walk(publicDir, [".css", ".js", ".mjs", ".svg"]));
  return out.map((full) => ({path: relative(root, full).split(sep).join("/"), text: readFileSync(full, "utf8")}));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const allow = readFileSync(join(ROOT, "tools/web-lint/inline-uri-allow.txt"), "utf8");
  const files = APPS.flatMap((app) => builtFiles(ROOT, app));
  const {found, allowed, stale, problems} = findInlineUris(files, allow);
  for (const line of allowed) console.log(`check-built-uris: allowed ${line}`);
  for (const line of stale) console.warn(`check-built-uris: stale ${line}`);
  if (found.length > 0 || problems.length > 0) {
    console.error(`check-built-uris: ${found.length + problems.length} finding(s)\n${[...problems, ...found].join("\n")}`);
    process.exit(1);
  }
  console.log(`check-built-uris: ${files.length} files, no data: or blob: URI`);
}
