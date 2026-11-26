import {existsSync, readdirSync, readFileSync} from "node:fs";
import {join} from "node:path";

// The proxy's `config.matcher` is a literal in each app (Next reads it from the file), so it cannot be
// built from a list. This file is what keeps the literal honest (spec 15.4, open question 23): it is
// used by tests only, and never imported by an app.
//
// The rule it enforces: the matcher excludes FILES, never a folder. A path under an excluded folder that
// is not a real file still reaches the App Router and answers with an HTML 404 that the proxy never
// touched, so it has no CSP, no frame-ancestors, and a nonce that the client picked (wp5-r1-9). `_next/static/`
// is not excluded either: its files have hashed names that no list can hold, so createProxy lets that prefix
// through untouched by next-intl but with the headers, and a missing name there gets a 404 with the CSP too.

/** Next compiles a matcher source with path-to-regexp. For the one shape we use, a single group, it is this. */
export function matcherRegExp(source: string): RegExp {
  return new RegExp(`^${source}$`);
}

// Root metadata files that Next serves at `/<name>` from `src/app` without a page, as a static file.
const ROOT_METADATA = /^(favicon\.ico|(icon|apple-icon|opengraph-image|twitter-image)\d*\.(png|jpe?g|gif|svg|ico)|robots\.txt|sitemap\.xml|manifest\.(webmanifest|json))$/;

// The same routes written as code: `robots.ts` answers `/robots.txt`, `icon.tsx` answers `/icon`, and so on.
// They have no file under `public/` and no page, so only the file name in `src/app` says that a path exists.
const DYNAMIC_METADATA = /^(robots|sitemap|manifest|(?:icon|apple-icon|opengraph-image|twitter-image)\d*)\.(?:ts|tsx|js|jsx|mjs|mts)$/;
const DYNAMIC_PATH: Record<string, string> = {robots: "/robots.txt", sitemap: "/sitemap.xml", manifest: "/manifest.webmanifest"};

const PLACEHOLDERS = new Set([".gitkeep", ".gitignore", ".gitattributes", ".DS_Store", "Thumbs.db", "desktop.ini"]);

function* files(dir: string, prefix: string): Generator<string> {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir, {withFileTypes: true})) {
    // Only the known placeholders are skipped: they keep a folder in git or in a file manager and are not
    // served. A dot FOLDER is served as any other (`public/.well-known/security.txt` answers at
    // `/.well-known/security.txt`), so it is walked, or the guard would be blind to the paths where a missing
    // matcher line matters most.
    if (PLACEHOLDERS.has(entry.name)) continue;
    if (entry.isDirectory()) yield* files(join(dir, entry.name), `${prefix}${entry.name}/`);
    else yield `${prefix}${entry.name}`;
  }
}

/** URL paths of everything that Next serves without a page: all of `public/`, and the root metadata routes of `src/app`. */
export function staticPaths(appDir: string): string[] {
  const fromPublic = [...files(join(appDir, "public"), "/")];
  const fromApp: string[] = [];
  if (existsSync(join(appDir, "src/app"))) {
    for (const entry of readdirSync(join(appDir, "src/app"), {withFileTypes: true})) {
      if (!entry.isFile()) continue;
      if (ROOT_METADATA.test(entry.name)) fromApp.push(`/${entry.name}`);
      const dynamic = DYNAMIC_METADATA.exec(entry.name)?.[1];
      if (dynamic) fromApp.push(DYNAMIC_PATH[dynamic] ?? `/${dynamic}`);
    }
  }
  return [...fromPublic, ...fromApp];
}

/** Paths that must reach the proxy: pages in every shape, names that look like a file but are not one, and every folder that was once excluded. */
export const MUST_RUN = [
  "/",
  "/fa",
  "/en/login",
  "/de",
  "/fa/profiles",
  "/fa/profiles/x.y",
  "/fa/logo.png",
  "/fa/favicon.ico",
  "/logos",
  "/logos/nothing",
  "/logos/nothing.svg",
  "/logoXpng",
  "/iconXpng",
  "/logo.pngx",
  "/x/logo.png",
  "/apix",
  "/api",
  "/api/v1/me",
  "/api/x",
  "/favicon.ico",
  "/_nextx/static",
  "/_next",
  "/_next/nothing",
  "/_next/image",
  "/_next/data/x.json",
  "/_next/staticx/a.js",
  "/_next/static",
  "/_next/static/chunks/a.js",
  "/_next/static/chunks/nothing-here.js",
  "/_next/static/media/x.woff2",
];

/**
 * Paths that must skip it. None: every folder reaches the proxy and only named files do not. The list stays so
 * that a path can be added the day a file needs it, with the test that proves it.
 */
export const MUST_SKIP: string[] = [];

// One excluded file: letters, digits, `_`, `-`, an escaped dot and slashes, ended by `$`.
const LITERAL_FILE = /^(?:[A-Za-z0-9_-]|\\\.|\/)+\$$/;

/** The alternatives of the first `(?!...)` group of a matcher source. */
export function excludedNames(source: string): string[] {
  const group = /\(\?!([^()]*)\)/.exec(source)?.[1];
  return group === undefined ? [] : group.split("|");
}

/**
 * Problems with one matcher source, as lines: a file of the app that the proxy would still run on (next-intl
 * would redirect it to `/fa/...`), a page path that it would skip, an excluded name that no file of the app
 * matches (it would only hide an HTML 404 from the proxy), and a name in the source that is not escaped, which
 * turns a dot into "any character".
 */
export function checkMatcher(source: string, appDir: string): string[] {
  return [...checkMatcherPaths(matcherRegExp(source), appDir), ...checkMatcherSource(source, appDir)];
}

/**
 * The path half of checkMatcher: which paths the regular expression runs the proxy on. It takes the expression, so the same checks run on the
 * model above (`^source$`) and on the one that Next compiled (checkCompiledMatcher).
 */
export function checkMatcherPaths(re: RegExp, appDir: string): string[] {
  const problems: string[] = [];
  const statics = staticPaths(appDir);
  for (const path of statics) {
    if (re.test(path)) problems.push(`${path} is a static file but the proxy runs on it: add its name to the matcher`);
  }
  // Probes made from every real file (wp5-r5-4): the file itself is skipped by name, but a longer name, a path
  // below it and a sibling that is no file are not. If a name is written as a prefix, a wildcard or a folder, it
  // skips them too, and each reaches the App Router as a [locale] with an HTML 404 that has no CSP.
  for (const path of statics) {
    const dir = path.slice(0, path.lastIndexOf("/"));
    for (const probe of [`${path}x`, `${path}/x`, `${dir}/nothing`]) {
      if (!re.test(probe)) problems.push(`${probe} is no file but the matcher skips it, so ${path} is excluded too widely: name each file and end it with a dollar sign`);
    }
  }
  for (const path of MUST_RUN) {
    if (!re.test(path)) problems.push(`${path} must reach the proxy but the matcher skips it`);
  }
  for (const path of MUST_SKIP) {
    if (re.test(path)) problems.push(`${path} must skip the proxy but the matcher runs on it`);
  }
  return problems;
}

/** The source half of checkMatcher: each excluded name is one literal file that a file of the app has, and every dot is escaped. */
function checkMatcherSource(source: string, appDir: string): string[] {
  const problems: string[] = [];
  const statics = staticPaths(appDir);
  for (const name of excludedNames(source)) {
    // A name is one file: literal characters, an escaped dot, slashes, and a closing `$`. A folder, a wildcard or
    // a prefix with no `$` skips paths that are no file (wp5-r5-4).
    if (!LITERAL_FILE.test(name)) problems.push(`"${name}" is not a literal file name that ends in $: name each file, never a folder or a pattern`);
    let nameRe: RegExp;
    try {
      nameRe = new RegExp(`^/${name}`);
    } catch {
      problems.push(`"${name}" is not a regular expression`);
      continue;
    }
    if (!statics.some((path) => nameRe.test(path))) {
      problems.push(`"${name}" is excluded but no file of the app matches it: remove it, so that the path reaches the proxy and its 404 has the CSP`);
    }
  }
  // A dot in a file name has to be `\.` in the regular expression, so two backslashes in the source literal.
  // The first name follows `(?!` and the others follow `|`. Every dot of a name is tested: one escaped dot must
  // not vouch for a second one that is not (`logo\.min.png$` also matches `/logo.minXpng`).
  const names = /(?:\(\?!|\|)([^|()]*\.[^|()]*)/g;
  for (const m of source.matchAll(names)) {
    if (/(?<!\\)\./.test(m[1]!)) problems.push(`"${m[1]}" has an unescaped dot`);
  }
  return problems;
}

// What Next compiled from the literal, read from the build (gate-r6-2). The model above (`^source$`) is how Next is expected to compile it, not
// what it did: the real expression has a `/_next/data/<id>` prefix, three optional suffixes and an optional trailing character, and a Next that
// compiles a lookahead or a literal differently would pass every check on the model and skip or run on other paths.
const MANIFEST = ".next/server/functions-config-manifest.json";

/** One matcher as Next wrote it into the build: the literal it read, and the regular expression it will run. */
export type CompiledMatcher = {originalSource: string; regexp: string};

/** Every matcher of the proxy in the build of an app. Throws when there is no build, so a test cannot pass by skipping it. */
export function compiledMatchers(appDir: string): CompiledMatcher[] {
  const file = join(appDir, MANIFEST);
  if (!existsSync(file)) throw new Error(`${file} does not exist: run next build first`);
  const manifest = JSON.parse(readFileSync(file, "utf8")) as {functions?: Record<string, {matchers?: CompiledMatcher[]}>};
  return Object.values(manifest.functions ?? {}).flatMap((fn) => fn.matchers ?? []);
}

/** The literal of `config.matcher` in an app's proxy.ts, read from the text (importing the file would run the proxy's imports). */
export function matcherLiteral(proxyFile: string): string {
  const m = /matcher:\s*\[\s*("(?:[^"\\]|\\.)*")\s*\]/.exec(readFileSync(proxyFile, "utf8"));
  if (!m) throw new Error(`no single matcher literal in ${proxyFile}`);
  return JSON.parse(m[1]!) as string;
}

/**
 * Problems with the matcher of a build: it is the one literal of proxy.ts, and the regular expression that Next compiled from it runs the
 * proxy on every path that is no file (the probes of checkMatcher, and the suffixes that Next's own routing adds) and on no file.
 */
export function checkCompiledMatcher(appDir: string): string[] {
  const source = matcherLiteral(join(appDir, "src/proxy.ts"));
  const compiled = compiledMatchers(appDir);
  if (compiled.length !== 1) return [`the build holds ${compiled.length} proxy matchers, expected 1`];
  const {originalSource, regexp} = compiled[0]!;
  const problems: string[] = [];
  if (originalSource !== source) problems.push(`the build was made from the matcher ${originalSource} but proxy.ts holds ${source}: build again`);
  let re: RegExp;
  try {
    re = new RegExp(regexp);
  } catch {
    return [...problems, `the compiled matcher is not a regular expression: ${regexp}`];
  }
  problems.push(...checkMatcherPaths(re, appDir));
  // Spellings that Next adds to a path (its data, flight and segment suffixes, a trailing slash): a file written so is no file, and the proxy
  // has to answer it.
  for (const path of staticPaths(appDir)) {
    for (const probe of [`${path}.json`, `${path}.rsc`, `${path}.segments/a.segment.rsc`, `${path}/`]) {
      if (!re.test(probe)) problems.push(`${probe} is no file but the compiled matcher skips it`);
    }
  }
  return problems;
}
