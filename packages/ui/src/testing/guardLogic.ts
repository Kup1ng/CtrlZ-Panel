// The decisions of the guard of spec 17.2, apart from Playwright so that a unit test can drive them.

import {parseVerifyOrigins} from "../proxy/csp.ts";

/**
 * Only the origin is ever kept: a URL may hold a token, a ticket or a phone number, and the list
 * goes into a failure message that ends up in a log (fixed rule 8).
 */
export function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return "invalid-url";
  }
}

// A URL inside a message: a scheme, `://`, then everything up to a space, a quote or a bracket that cannot be part of it.
const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"<>`)\]}]+/gi;

/**
 * Text of a console or page error, as it may be kept and printed. Chrome writes the whole URL into a CSP violation ("Connecting to
 * 'https://x/collect?ticket=...' violates ...") and into a failed fetch, and the failure message of a test ends up in a CI log, so
 * every URL in it is cut to its origin, the same rule as originOf (fixed rule 8, gate-r4-5). The length limit comes after, so a long
 * query can never push the cut off. A sentence with no URL is unchanged.
 */
export function redactUrls(text: string, limit = 200): string {
  return text.replace(URL_IN_TEXT, (url) => {
    const origin = originOf(url);
    return origin === "invalid-url" || origin === "null" ? "<url>" : origin;
  }).slice(0, limit);
}

/**
 * True for the one console error that the guard itself causes: Chrome's "Failed to load resource ... 404" for its own navigation to the
 * take-back path. Only that status, and only for a message located at that path, so a 500 or a script error there is still judged.
 */
export function isForwardPathNoise(type: string, text: string, url: string, forwardPath: string): boolean {
  if (type !== "error" || !/status of 404\b/.test(text)) return false;
  try {
    return new URL(url).pathname === forwardPath;
  } catch {
    return false;
  }
}

/**
 * The directive named by the message that Chrome writes to the console for an enforced CSP violation, or undefined for any other text.
 * A violation raised while a page unloads reaches Node only as this message: the `securitypolicyviolation` event is a queued task and
 * does not run before the document is gone (measured, gate-r15-2). A report-only policy is not enforcement and is left out.
 */
export function cspDirectiveOfConsole(text: string): string | undefined {
  if (text.startsWith("[Report Only]")) return undefined;
  // Chrome writes two shapes. A resource refusal has a colon and double quotes (`directive: "connect-src 'self'"`). The nonce class, an inline
  // style, script or event handler without the nonce, has neither colon nor double quotes (`directive 'style-src-elem 'self' 'nonce-x''`). Both
  // are enforcement, and the second is the one a library that restores styles on unload would raise (gate-r27-2).
  return /Content Security Policy directive:? ["']([a-z-]+)/i.exec(text)?.[1]?.toLowerCase();
}

const NETWORK = new Set(["http:", "https:", "ws:", "wss:"]);

/** `data:` and `blob:` live in the page, so they are not a request that leaves it (spec 17.2). */
export function isNetworkUrl(url: string): boolean {
  try {
    return NETWORK.has(new URL(url).protocol);
  } catch {
    return false;
  }
}

/** The origins of CTRLZ_VERIFY_ORIGIN as the test process sees them: the same list, read by the same parser as the policy (p4-nodes 10.3, T-238). A wrong value allows nothing. */
function verifyOriginsFromEnv(): readonly string[] {
  try {
    return parseVerifyOrigins(process.env.CTRLZ_VERIFY_ORIGIN);
  } catch {
    return [];
  }
}

/**
 * The one designed exception to "no request leaves the origin" (spec 17.2): the setup page's probe of `<label>.verify.dns.<zone>`, and only for a
 * zone of CTRLZ_VERIFY_ORIGIN (the current one and, during a transition, the previous one). Plain https on the default port, since the
 * CSP source carries no port; any other host, scheme or port of the same zone is still a request that leaves.
 */
export function isVerifyProbe(url: URL, origins: readonly string[] = verifyOriginsFromEnv()): boolean {
  if (url.protocol !== "https:" || url.port !== "") return false;
  return origins.some((origin) => {
    // `https://*.verify.dns.<zone>` -> `.verify.dns.<zone>`: one or more labels must stand before it.
    const suffix = origin.slice("https://*".length);
    return url.hostname.length > suffix.length && url.hostname.endsWith(suffix) && !url.hostname.startsWith(".");
  });
}

/** True when a request to `url` leaves the origins the test may talk to. */
export function isExternal(url: string, allowed: ReadonlySet<string>): boolean {
  if (!isNetworkUrl(url)) return false;
  const parsed = new URL(url);
  return !allowed.has(parsed.origin) && !isVerifyProbe(parsed);
}

/** A console error is a failure unless a test said, with a pattern, that it causes that one on purpose. */
export function isUnexpectedConsoleError(text: string, allowed: readonly RegExp[]): boolean {
  return !allowed.some((re) => re.test(text));
}

/**
 * The `rel` values that make a browser contact another origin before, or without, a request of the page's own. The CSP has
 * no directive for `preconnect` and `dns-prefetch` (CSP 3 dropped prefetch-src), and Playwright's browser never acts on a hint,
 * so no request event, no violation and no connection shows one. A real visitor's browser would open it (gate-r2-4).
 */
export const HINT_RELS = ["preconnect", "dns-prefetch", "prefetch", "preload", "modulepreload", "prerender"] as const;

/** True when a `rel` attribute or a Link header parameter holds one of the hint tokens. */
export function isHintRel(rel: string): boolean {
  return rel
    .toLowerCase()
    .split(/\s+/)
    .some((token) => (HINT_RELS as readonly string[]).includes(token));
}

/**
 * The origins that the hints of a `Link` response header point at and the test may not talk to. A browser acts on the header
 * of a document as it acts on a `<link>` element, and the header never reaches the page's script, so the guard reads it
 * from the response. A target that is not a network URL, and one that cannot be read, counts for nothing.
 */
export function externalHintOrigins(linkHeader: string, base: string, allowed: ReadonlySet<string>): string[] {
  const out: string[] = [];
  for (const entry of linkHeader.split(/,\s*(?=<)/)) {
    const match = /^\s*<([^>]*)>(.*)$/s.exec(entry);
    if (!match) continue;
    const rel = /;\s*rel\s*=\s*(?:"([^"]*)"|([^;\s]*))/i.exec(match[2]!);
    if (!rel || !isHintRel(rel[1] ?? rel[2] ?? "")) continue;
    try {
      const target = new URL(match[1]!, base).href;
      if (isExternal(target, allowed)) out.push(originOf(target));
    } catch {
      // A target that does not parse is no connection.
    }
  }
  return out;
}

/**
 * What a `Speculation-Rules` response header names: the JSON files whose rules the browser then applies (gate-r26-1). Chrome starts the
 * prefetches and prerenders of such a rule set outside every check the guard has: no `request` event, no CSP violation (connect-src does not
 * cover them and CSP 3 dropped prefetch-src), and a document rule holds no URL at all. P1 sends the header nowhere, so any value is a failure,
 * and the answer is never empty: a header that does not parse as a list of quoted URLs is `["header"]`. Only origins are kept, as for a hint.
 */
export function speculationHeaderTargets(header: string, base: string): string[] {
  const out = new Set<string>();
  for (const match of header.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
    try {
      out.add(new URL(match[1]!.replace(/\\(.)/g, "$1"), base).origin);
    } catch {
      // A target that does not parse still means the header was sent.
    }
  }
  return out.size ? [...out] : ["header"];
}

/** The pages that the guard's own self-tests serve from a mock route, with a policy of their own making. */
const SELFTEST_PAGE = /^\/(guard|axe)-selftest(\/|$)/;

/**
 * True for an HTML document of the app that arrived with no Content-Security-Policy, or with one that has no nonce (gate-r3-4). The
 * violation check can only see what a policy blocks: a page with no policy raises none, so a document that skipped the proxy would be
 * green. A redirect has no document. The self-test pages are exempt only when a mock route answered them (`answeredByRoute`: Playwright
 * reports no server address for a response that route.fulfill made), so the exemption follows who served the page and not its path: a
 * real server or a Caddy file at /axe-selftest/x with no policy is still recorded (gate-r5-2).
 *
 * A policy that has a nonce is not enough: next dev's policy has one on script-src and also `'unsafe-inline'` for styles and `'unsafe-eval'`, and
 * under it a style element with no nonce raises no violation, so a run against next dev is green on a page that next start breaks (gate-r9-3).
 * So the script and style directives must hold nothing but `'self'`, `'none'` and nonces (weakDirectives).
 */
export function documentWithoutPolicy(status: number, contentType: string | undefined, csp: string | undefined, pathname: string, answeredByRoute: boolean): boolean {
  if (status >= 300 && status < 400) return false;
  if (!/^text\/html\b/i.test(contentType ?? "")) return false;
  if (answeredByRoute && SELFTEST_PAGE.test(pathname)) return false;
  return !/'nonce-[^']+'/.test(csp ?? "") || weakDirectives(csp ?? "").length > 0 || unrestrictedCode(csp ?? "").length > 0;
}

/** The directives that decide what code and styles may run. Anything they list besides 'self', 'none' and a nonce is a way round the nonce. */
// script-src-attr is in the list because it is the one directive that governs inline event handlers: 'unsafe-inline' or 'unsafe-hashes'
// there lets an onclick run with no nonce while script-src stays strict (gate-r12-1). style-src-attr is not, by design.
const CODE_DIRECTIVES = new Set(["default-src", "script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem"]);
const STRICT_SOURCE = /^(?:'self'|'none'|'nonce-[^']+')$/;

/**
 * The names of the script and style directives of a policy that carry a source other than 'self', 'none' or a nonce: 'unsafe-inline',
 * 'unsafe-eval', 'strict-dynamic', a host, `*`, `data:`, `blob:`, `https:`. `style-src-attr` is not listed: the apps allow inline style attributes by design
 * (spec 15.2). Returns the offending `directive source` pairs, so the failure says what is wrong.
 */
export function weakDirectives(csp: string): string[] {
  const weak: string[] = [];
  for (const part of csp.split(";")) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (!name || !CODE_DIRECTIVES.has(name.toLowerCase())) continue;
    for (const source of sources) if (!STRICT_SOURCE.test(source)) weak.push(`${name.toLowerCase()} ${source}`);
  }
  return weak;
}

/**
 * What a policy fails to restrict at all, as the names of the missing directives. weakDirectives only reads the sources that are written, so
 * `style-src 'nonce-a'; img-src 'self'` has a nonce and no weak source and still puts no limit on scripts (gate-r12-1). A script is limited by
 * `script-src` or by `default-src` (which `script-src-elem` and `script-src-attr` fall back to through script-src); a style element by `style-src`,
 * `style-src-elem` or `default-src`. `script-src-elem` alone is not enough: it leaves inline event handlers and eval unlimited.
 */
export function unrestrictedCode(csp: string): string[] {
  const names = new Set(csp.split(";").map((part) => part.trim().split(/\s+/)[0]?.toLowerCase() ?? ""));
  const has = (...wanted: string[]) => wanted.some((name) => names.has(name));
  const missing: string[] = [];
  if (!has("default-src", "script-src")) missing.push("script-src");
  if (!has("default-src", "style-src", "style-src-elem")) missing.push("style-src");
  return missing;
}

/**
 * One thing a flow wrote on its way, for the secret residue check (gate-r17-5): a `history` call (method, address and state), a frame navigation, a
 * console message of any level, or a page error. The text is raw and stays in the test process.
 */
export type TrailEntry = {kind: "history" | "navigated" | "console" | "pageerror"; text: string};
