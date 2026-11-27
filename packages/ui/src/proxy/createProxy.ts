import createMiddleware from "next-intl/middleware";
import {NextRequest, NextResponse} from "next/server";
import {routing} from "@ctrlz/i18n/routing.ts";

import {buildCsp, checkVerifyOrigins, newNonce} from "./csp.ts";
import {gateRedirect, isCrossSiteNavigation, type GateConfig} from "./gate.ts";
import {securityHeaders, type ProxyApp} from "./headers.ts";
import {isNavigation, refusedByNext} from "./nextRequests.ts";
import {canonicalPath, CONTROL_OR_SPACE} from "./pathSpelling.ts";

export type ProxyConfig = GateConfig & {
  /** Which app this is: the Permissions-Policy differs (passkeys are the panel's only, gate-r2-18). */
  app: ProxyApp;
  /** Panel only, from CTRLZ_VERIFY_ORIGIN through parseVerifyOrigins (at most two). createProxy and buildCsp check the list again: an unchecked string must not reach connect-src (gate-r4-3). */
  verifyOrigins?: readonly string[];
};

// An escape that does not decode (`%zz`, a lone `%`, `%C0`, `%E0%A4%A`) makes next-intl give up and pass the request on,
// and Next then answers a bare 500 that carries none of our headers (wp5-r16-1). Same class as the line above: a path
// that no page has, refused here, before the gate and next-intl, so the answer has the CSP and the three headers.
function undecodable(pathname: string): boolean {
  try {
    decodeURIComponent(pathname);
    return false;
  } catch {
    return true;
  }
}

/**
 * No page, and no body that echoes the path. The caller sets the headers of every answer. `no-store`: a 404 is
 * cacheable by default, and this one is the answer for a path that never names a page, so no cache may keep it
 * (gate-r2-6, pinned in headersSpec.ts).
 */
function notFound(): NextResponse {
  return new NextResponse("Not Found", {status: 404, headers: {"content-type": "text/plain; charset=utf-8", "cache-control": "no-store"}});
}

/**
 * What next-intl's rewrite does to the request path (wp5-r15-2, wp5-r18-1):
 * - "same": the target is the request's pathname and query, character for character.
 * - "respelled": the same page, written differently only because next-intl re-serialises some escapes (`%5B` to `[`,
 *   `%7C` to `|`), and the request itself is in the form `encodeURIComponent` writes, so it is an ordinary link and not a trick.
 * - "other": anything else. `%70rofiles`, `x%2e` and `%28` are not what a link writes and are refused as before, and `50%25`
 *   is refused because the target holds a bare `%`, which no page can be asked for.
 * The set that is refused is pinned by a test, so that a page of P2 does not meet it by accident.
 */
export function rewriteKind(rewrite: string, request: NextRequest): "same" | "respelled" | "other" {
  try {
    const target = new URL(rewrite);
    const asked = request.nextUrl.pathname;
    if (target.search !== request.nextUrl.search) return "other";
    if (target.pathname === asked) return "same";
    return canonicalPath(asked) === asked && canonicalPath(target.pathname) === asked ? "respelled" : "other";
  } catch {
    return "other";
  }
}

/**
 * What next-intl's locale redirect does to the request path (gate-r23-4). It puts `/<locale>` in front of the path, and it runs `decodeURI` on
 * the path first (sanitizePathname), which decodes `%25`: `/%252F%252Fevil.example` becomes `Location: /fa/%2F%2Fevil.example`, a different
 * string from the one that was asked. That is safe while the locale prefix is always there (a relative `/fa/...` cannot leave the origin, and
 * the next hop runs the gate again), and this check keeps it safe if a next-intl release changes the decoding or builds a target without the
 * prefix. As for rewrites (`rewriteKind`), the class is refused and not each spelling: the Location must be `/<locale>` and then the path that
 * was asked for (its own locale prefix, in any case, cut off first), character for character, or respelled only the way a link written by
 * `encodeURIComponent` is, with the same query. Anything else is the proxy's plain 404.
 */
export function redirectKind(location: string, request: NextRequest): "same" | "respelled" | "other" {
  try {
    const target = new URL(location, request.nextUrl.origin);
    if (target.origin !== request.nextUrl.origin || target.search !== request.nextUrl.search || target.hash !== "") return "other";
    const locales: readonly string[] = routing.locales;
    const lead = /^\/([^/]*)/.exec(target.pathname);
    if (!lead || !locales.includes(lead[1]!)) return "other";
    // "/" and "" are the same place: `/` goes to `/fa`, and a trailing slash may or may not be kept.
    const norm = (path: string): string => (path.length > 1 ? path.replace(/\/$/, "") : "");
    const askedPath = request.nextUrl.pathname;
    const first = /^\/([^/]*)/.exec(askedPath)?.[1];
    const asked = norm(first !== undefined && locales.includes(first.toLowerCase()) ? askedPath.slice(first.length + 1) : askedPath);
    const got = norm(target.pathname.slice(lead[0].length));
    if (got === asked) return "same";
    return canonicalPath(asked) === asked && canonicalPath(got) === asked ? "respelled" : "other";
  } catch {
    return "other";
  }
}

/**
 * The request headers that make Next's static server answer a 4xx of its own, which Next then turns into a 500 with no log line: a `Range` it
 * cannot satisfy (a 416, where RFC 9110 14.2 asks for a 416 or a plain 200), and a failed `If-Match` or `If-Unmodified-Since` (a 412). Anyone could
 * raise the web tier's error rate at will with one header (gate-r16-5), and an alert on that rate would be triggered or masked. No asset of either
 * app is fetched by range, and none is edited, so the four headers are dropped before Next reads them. A conditional GET (`If-None-Match`,
 * `If-Modified-Since`, a 304) works and stays: hashed chunks are cached by it. The files of `public/` skip this proxy, so the same four lines are in
 * the Caddy item of the P1 merge.
 */
const STATIC_PRECONDITIONS = ["range", "if-range", "if-match", "if-unmodified-since"] as const;

function withoutPreconditions(headers: Headers): Headers {
  const plain = new Headers(headers);
  for (const name of STATIC_PRECONDITIONS) plain.delete(name);
  return plain;
}

/**
 * What a method other than GET and HEAD gets under `/_next/static/`: Next's static server answers it with a 405 and then turns that into a bare
 * `500 Internal Server Error` (text/plain, no log line), so one POST to a public chunk URL would raise the web tier's 5xx rate at will (gate-r18-1,
 * the same class as gate-r16-5, where the cause was a header). Nothing under that prefix takes any other method. The proxy answers with its own 405,
 * which says what is allowed and has the CSP and the three headers like every other answer it builds. The files of `public/` skip this proxy, so
 * the same rule for `/logo.png` and `/icon.png` is in the Caddy item of the P1 merge.
 */
function methodNotAllowed(): NextResponse {
  return new NextResponse("Method Not Allowed", {
    status: 405,
    headers: {"content-type": "text/plain; charset=utf-8", "cache-control": "no-store", allow: "GET, HEAD"},
  });
}

/**
 * The proxy of one app: a nonce and the CSP on every response, COOP, CORP and
 * Permissions-Policy beside it (spec 15.1), the session gate, and next-intl's
 * locale routing (spec 15.4).
 */
export function createProxy(cfg: ProxyConfig) {
  // Refused when the proxy is made, which for the real apps is when proxy.ts loads: the same time and the same 500 as a wrong variable.
  const verifyOrigins = checkVerifyOrigins(cfg.verifyOrigins);
  if (verifyOrigins.length > 0 && cfg.app !== "panel") throw new Error("only the panel's policy may carry the verify origin (spec 15.3)");
  const i18n = createMiddleware(routing);
  const dev = process.env.NODE_ENV === "development";

  return function proxy(request: NextRequest): NextResponse {
    // next-intl's own answer, except that a locale redirect whose Location is not `/<locale>` and the path that was asked for is the proxy's 404 (gate-r23-4).
    const localeRouted = (req: NextRequest): NextResponse => {
      const answer = i18n(req);
      const location = answer.headers.get("location");
      return location !== null && answer.status >= 300 && answer.status < 400 && redirectKind(location, req) === "other" ? notFound() : answer;
    };

    const nonce = newNonce();
    const csp = buildCsp(nonce, {verifyOrigins, dev});

    // Next reads the nonce from the CSP header of the request while it
    // renders, and the layout reads x-nonce for the theme script.
    const headers = new Headers(request.headers);
    headers.set("x-nonce", nonce);
    headers.set("Content-Security-Policy", csp);
    const forwarded = new NextRequest(request, {headers});

    // The gate must not send a visitor to login with a `next` that this proxy refuses once the visitor has a session.
    // It asks the rules a request gets: decodable, no control character, and a rewrite onto the same text.
    const serves = (localePath: string): boolean => {
      const probe = new NextRequest(new URL(localePath, request.nextUrl.origin), {headers});
      const p = probe.nextUrl.pathname;
      if (undecodable(p) || CONTROL_OR_SPACE.test(p)) return false;
      const rewrite = i18n(probe).headers.get("x-middleware-rewrite");
      return rewrite === null || rewriteKind(rewrite, probe) !== "other";
    };

    // Next's build output is not a page: language rules and the gate must not touch it, or next-intl would redirect
    // every chunk to /fa/_next/... The request still passes through, because a name under it that is not a file
    // gets Next's HTML 404, which has to carry the CSP, and the nonce of the request header that we set above and
    // not one that the client sent (wp5-r1-9).
    const pathname = request.nextUrl.pathname;
    // A data URL of the Pages Router (`/_next/data/<id>/<path>.json`, whatever the id): Next removes the prefix and the suffix before the
    // proxy sees the request, so it looks like the page `<path>`, and Next then serves its prerendered default 404 for it, a document built
    // once, whose inline scripts have no nonce, under the fresh CSP of this request (gate-r3-6). Neither app has a data route, and the router
    // marks exactly these requests with `x-nextjs-data`, so the proxy answers them with its own plain 404. Next sets that header itself, for the
    // data URL alone, and removes one that a client sends on any other URL (measured on next start: a forged header on /fa/login is an ordinary page),
    // so this rule is reached only by the data URLs. (The real build id without `.json` is answered by Next too, but the proxy is asked only after that response has ended, so it cannot change it and
    // Next logs ERR_HTTP_HEADERS_SENT for it: see headers.ts, gate-r3-4 and gate-r7-3.)
    let response = request.headers.has("x-nextjs-data") || undecodable(pathname) || refusedByNext(request)
      ? notFound()
      : pathname.startsWith("/_next/static/")
        // A person who opens a name under it gets the proxy's 404, not Next's built-in page (gate-r9-2, see isNavigation). Asset loads pass.
        ? request.method !== "GET" && request.method !== "HEAD"
          ? methodNotAllowed()
          : isNavigation(request) ? notFound() : NextResponse.next({request: {headers: withoutPreconditions(headers)}})
        : CONTROL_OR_SPACE.test(pathname)
          ? notFound()
          // The admin's cookie is Strict, so a link arrival carries none although the admin is signed in: the page is served and the shell's
          // SessionGate asks `/me` from the page's own origin, where the cookie is sent, and goes to login with `next` on a 401 (gate-r32-1).
          // The panel's cookies are Lax and travel on such a navigation, so its gate is unchanged.
          : ((cfg.app === "admin" && isCrossSiteNavigation(forwarded) ? undefined : gateRedirect(forwarded, cfg, serves)) ?? localeRouted(forwarded));
    // A rewrite to another spelling of the path (`%70rofiles`, `profiles%2e`, a decoded escape) is a path the gate
    // did not judge as written, and Next sends `x-middleware-rewrite` to the client for it, with the internal target
    // and the query. The class is refused, not each spelling: only a rewrite onto the same text goes on (wp5-r15-2).
    const rewrite = response.headers.get("x-middleware-rewrite");
    const kind = rewrite ? rewriteKind(rewrite, request) : "same";
    if (kind === "other") response = notFound();
    // A rewrite onto the page that was asked for changes nothing, and Next hands the header to the client when the
    // page answers 404 (measured on next start for `a%5Bb%5D`, wp5-r18-1). So it becomes what next-intl sends for a path it
    // leaves alone: continue with the request as it is, with the nonce and CSP request headers still on the response.
    if (rewrite && kind !== "other") {
      response.headers.delete("x-middleware-rewrite");
      response.headers.set("x-middleware-next", "1");
    }
    // Set, not append: a value from an earlier layer must not survive next to ours. The redirects of the
    // gate and of next-intl carry them too, so every answer of this proxy has the same set.
    response.headers.set("Content-Security-Policy", csp);
    for (const [name, value] of Object.entries(securityHeaders(cfg.app))) response.headers.set(name, value);
    return response;
  };
}
