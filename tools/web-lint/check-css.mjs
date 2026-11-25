// The CSS half of the bans in spec 16.1. ESLint cannot read a .css file, so this script does.
//
//   node tools/web-lint/check-css.mjs        scan our own CSS, exit 1 on a finding
//
// It covers what the product writes itself: packages/*/styles, and any .css under a src folder
// of an app or package. HeroUI's CSS in node_modules is not ours and is not scanned.
//
// Bans, with the reason each one exists:
//   - a physical edge (left, right, margin-left, text-align: left ...): wrong in RTL, and
//     Persian is the default language;
//   - http(s), a protocol-relative url(//), or @import url(): nothing loads from outside;
//   - a hex colour outside tokens.css and flat.css: colours are tokens (DESIGN.md);
//   - text-shadow and drop-shadow(): DESIGN.md allows no glow;
//   - a gradient outside tokens.css and flat.css: DESIGN.md allows one, the faint page wash;
//   - an animation or a transition in a file with no prefers-reduced-motion rule (T-465).
import {readdirSync, readFileSync, statSync} from "node:fs";
import {dirname, join, relative, resolve, sep} from "node:path";
import {fileURLToPath} from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

/** Files where a hex colour or a gradient is the definition of a token, not a use of one. */
const TOKEN_FILES = new Set(["tokens.css", "flat.css"]);

/** Blank out comments but keep the line breaks, so a finding still reports the right line. */
export function stripComments(css) {
  return css.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
}

const PHYSICAL = [
  [/(^|[\s;{])(left|right)\s*:/, "a bare left or right (use inset-inline-start or -end)"],
  [/\b(margin|padding|scroll-margin|scroll-padding)-(left|right)\b/, "a physical margin or padding (use the -inline-start or -end form)"],
  [/\bborder-(left|right)(-[a-z]+)?\s*:/, "a physical border side (use border-inline-start or -end)"],
  [/\btext-align\s*:\s*(left|right)\b/, "text-align: left or right (use start or end)"],
  [/\bfloat\s*:\s*(left|right)\b/, "float: left or right (use inline-start or inline-end)"],
];

const REMOTE = [
  // A scheme is case-insensitive in a browser, so HTTPS://host loads as well.
  [/https?:\/\//i, "an http(s) URL"],
  [/url\(\s*["']?\/\//, "a protocol-relative url(//)"],
  [/@import\s+url\(/i, "@import url()"],
  // The string form of an import has no url(), and //host keeps the page scheme: as remote as https.
  [/@import\s+["']\/\//i, "a protocol-relative @import string"],
];

/**
 * @param {{path: string, text: string}[]} files  path is relative to the repository root, with forward slashes
 * @returns {string[]} one line per finding: `path:line: what`
 */
export function checkCss(files) {
  const found = [];
  for (const {path, text} of files) {
    const base = path.split("/").pop();
    const isToken = TOKEN_FILES.has(base);
    const css = stripComments(text);
    const lines = css.split("\n");
    const hit = (i, what) => found.push(`${path}:${i + 1}: ${what}`);

    lines.forEach((line, i) => {
      for (const [re, what] of PHYSICAL) if (re.test(line)) hit(i, what);
      for (const [re, what] of REMOTE) if (re.test(line)) hit(i, what);
      if (/\btext-shadow\s*:/.test(line)) hit(i, "text-shadow (no glow, DESIGN.md)");
      if (/\bdrop-shadow\(/.test(line)) hit(i, "drop-shadow() (no glow, DESIGN.md)");
      if (!isToken) {
        if (/#[0-9a-fA-F]{3,8}\b/.test(line)) hit(i, "a hex colour outside tokens.css and flat.css (use a token)");
        if (/\b(linear|radial|conic)-gradient\(/.test(line)) hit(i, "a gradient outside tokens.css and flat.css (DESIGN.md allows only the page wash)");
      }
    });

    // `transition: none` and `animation: none` are the absence of motion, so they need no partner.
    const moves =
      /@keyframes\b/.test(css) ||
      /\b(transition|animation)(-[a-z-]+)?\s*:(?!\s*none\b)[^;}]+/.test(css);
    if (moves && !/prefers-reduced-motion/.test(css)) {
      const at = lines.findIndex((l) => /@keyframes\b|\b(transition|animation)(-[a-z-]+)?\s*:(?!\s*none\b)/.test(l));
      hit(Math.max(at, 0), "an animation or a transition with no prefers-reduced-motion rule in the same file (T-465)");
    }
  }
  return found;
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".next" || name.startsWith(".")) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) yield* walk(full);
    else if (name.endsWith(".css")) yield full;
  }
}

/** Every .css of ours: a styles/ folder of a package or app, and any .css under a src/ folder. */
export function ourCssFiles(root = ROOT) {
  const out = [];
  for (const group of ["packages", "apps"]) {
    const groupDir = join(root, group);
    for (const name of readdirSync(groupDir)) {
      for (const sub of ["styles", "src"]) {
        const dir = join(groupDir, name, sub);
        try {
          if (statSync(dir).isDirectory()) out.push(...walk(dir));
        } catch {
          // a package without that folder
        }
      }
    }
  }
  return out;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const files = ourCssFiles().map((full) => ({
    path: relative(ROOT, full).split(sep).join("/"),
    text: readFileSync(full, "utf8"),
  }));
  const found = checkCss(files);
  if (found.length > 0) {
    console.error(`check-css: ${found.length} finding(s)\n${found.join("\n")}`);
    process.exit(1);
  }
  console.log(`check-css: ${files.length} files, no findings`);
}
