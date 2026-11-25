import {NextResponse, type NextRequest} from "next/server";
import {defaultLocale, isLocale, type Locale} from "@ctrlz/i18n/locale.ts";

import {sanitizeNext} from "./safeNext.ts";

export type GateConfig = {
  /** Paths without the locale that need a session. */
  protectedPrefixes: readonly string[];
  /** Any one of these cookies, non-empty, lets the request through. */
  sessionCookies: readonly string[];
  /** Without the locale. */
  loginPath?: string;
};

/**
 * Splits `/fa/profiles/x` into the locale and `/profiles/x`. An unprefixed
 * path gets the default locale, since next-intl will add it. The path is
 * decoded and its slashes collapsed first, so `/fa/%70rofiles` and
 * `/fa//profiles` are the page they will resolve to. A path with a control character or a
 * space never gets here: createProxy refuses it first, because the URL parser would drop that
 * character and resolve to a page this decoded text does not name (wp5-r15-1).
 *
 * `rest` is that decoded text and is only for deciding which page it is. It
 * must never be put into a URL: `%3F` has become `?` in it. `rawRest` is the
 * same page as the request spelled it, still percent-encoded, and is what a
 * return path is built from (wp5-r14-1).
 */
export function splitLocale(pathname: string): {locale: Locale; rest: string; rawRest: string} {
  let path = pathname;
  let decodedOk = true;
  try {
    path = decodeURIComponent(pathname);
  } catch {
    // A malformed escape never resolves to a page. Keep the raw text.
    decodedOk = false;
  }
  path = path.replace(/\/{2,}/g, "/");
  const [, first = "", ...tail] = path.split("/");
  const located = isLocale(first);
  const rest = located ? `/${tail.join("/")}` : path;

  // The same cut on the text as it was written. Where the locale cannot be
  // found there (an escaped slash made it), the decoded rest is encoded again
  // segment by segment, so a reserved character still travels as text.
  const raw = pathname.replace(/\/{2,}/g, "/");
  const [, rawFirst = "", ...rawTail] = raw.split("/");
  let rawRest: string;
  if (!decodedOk || !located) rawRest = raw;
  else if (rawLocale(rawFirst)) rawRest = `/${rawTail.join("/")}`;
  else rawRest = rest.split("/").map(encodeURIComponent).join("/");
  return {locale: located ? first : defaultLocale, rest, rawRest};
}

function rawLocale(segment: string): boolean {
  try {
    return isLocale(decodeURIComponent(segment));
  } catch {
    return false;
  }
}

function isProtected(rest: string, prefixes: readonly string[]): boolean {
  const path = rest.length > 1 ? rest.replace(/\/+$/, "") : rest;
  return prefixes.some((p) => path === p || path.startsWith(`${p}/`));
}

/**
 * A top-level navigation that starts on another site (a link in a chat, an email or a wiki). The browser leaves a
 * `SameSite=Strict` cookie off such a request, and the admin's session cookie is Strict (AUTH 3.2), so "no cookie" proves
 * nothing about a signed-in admin there. Browsers that send Fetch Metadata say so; a client that does not is gated as before.
 */
export function isCrossSiteNavigation(request: NextRequest): boolean {
  return request.headers.get("sec-fetch-site") === "cross-site" && request.headers.get("sec-fetch-mode") === "navigate";
}

/**
 * A convenience, not a control: it saves a round trip for a visitor who has no
 * session cookie at all. A cookie's presence proves nothing, and the API
 * decides on `/me`. Returns a redirect, or undefined to carry on.
 */
export function gateRedirect(
  request: NextRequest,
  cfg: GateConfig,
  /**
   * Whether the proxy would serve this locale-prefixed path as written. The login `next` must never name a page that
   * the proxy itself answers with a 404 after login (`/profiles/50%25`, `/profiles/%70x`: next-intl rewrites them to
   * another spelling, wp5-r17-2). Without it, every next is kept.
   */
  serves?: (localePath: string) => boolean,
): NextResponse | undefined {
  const {locale, rest, rawRest} = splitLocale(request.nextUrl.pathname);
  if (!isProtected(rest, cfg.protectedPrefixes)) return undefined;
  if (cfg.sessionCookies.some((name) => (request.cookies.get(name)?.value ?? "") !== "")) return undefined;

  let next = sanitizeNext(rawRest + request.nextUrl.search, cfg.protectedPrefixes);
  if (next && serves && !serves(`/${locale}${next}`)) next = undefined;
  // Built from nextUrl, like next-intl's own redirects. Next refuses a
  // relative Location from a proxy (Invalid URL, so a 500), and it rewrites a
  // same-origin absolute one back to a relative path on the wire.
  const url = request.nextUrl.clone();
  url.pathname = `/${locale}${cfg.loginPath ?? "/login"}`;
  url.search = next ? `?${new URLSearchParams({next})}` : "";
  return NextResponse.redirect(url, 307);
}
