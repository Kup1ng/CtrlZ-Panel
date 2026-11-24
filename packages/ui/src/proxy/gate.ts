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
 * `/fa//profiles` are the page they will resolve to.
 */
export function splitLocale(pathname: string): {locale: Locale; rest: string} {
  let path = pathname;
  try {
    path = decodeURIComponent(pathname);
  } catch {
    // A malformed escape never resolves to a page. Keep the raw text.
  }
  path = path.replace(/\/{2,}/g, "/");
  const [, first = "", ...tail] = path.split("/");
  if (isLocale(first)) return {locale: first, rest: `/${tail.join("/")}`};
  return {locale: defaultLocale, rest: path};
}

function isProtected(rest: string, prefixes: readonly string[]): boolean {
  const path = rest.length > 1 ? rest.replace(/\/+$/, "") : rest;
  return prefixes.some((p) => path === p || path.startsWith(`${p}/`));
}

/**
 * A convenience, not a control: it saves a round trip for a visitor who has no
 * session cookie at all. A cookie's presence proves nothing, and the API
 * decides on `/me`. Returns a redirect, or undefined to carry on.
 */
export function gateRedirect(request: NextRequest, cfg: GateConfig): NextResponse | undefined {
  const {locale, rest} = splitLocale(request.nextUrl.pathname);
  if (!isProtected(rest, cfg.protectedPrefixes)) return undefined;
  if (cfg.sessionCookies.some((name) => (request.cookies.get(name)?.value ?? "") !== "")) return undefined;

  const next = sanitizeNext(rest + request.nextUrl.search, cfg.protectedPrefixes);
  // Built from nextUrl, like next-intl's own redirects. Next refuses a
  // relative Location from a proxy (Invalid URL, so a 500), and it rewrites a
  // same-origin absolute one back to a relative path on the wire.
  const url = request.nextUrl.clone();
  url.pathname = `/${locale}${cfg.loginPath ?? "/login"}`;
  url.search = next ? `?${new URLSearchParams({next})}` : "";
  return NextResponse.redirect(url, 307);
}
