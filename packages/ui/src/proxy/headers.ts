// The headers the Next server itself sets (spec 15.1), besides the CSP, which has its own file.
// Caddy sets the same three, so a response that skipped this proxy still has them. The values are the ones of this file and only of this file:
// the Permissions-Policy differs per app (permissionsPolicy('panel') has the passkey features, permissionsPolicy('admin') does not, gate-r2-18),
// so the Caddyfile writes one string per site and never one shared string (gate-r8-4). Two kinds
// skip it: the files in `public/` (`logo.png`, and `icon.png`, which is a root metadata route in `src/app` and not a file) and Next's own path-normalisation redirects, a 308
// that Next answers before the proxy runs (`/fa/`, `//evil.example`, `/\evil.example`, `/fa/..//x`,
// `/_next/static//x`). Those 308s carry no CSP, no COOP, no CORP and no Permissions-Policy and render nothing, which
// is harmless, so Caddy must set the three headers and the CSP default on EVERY response and never scope them to
// a path. The proxy also answers `_next/static`, since round 1, so the chunks carry the headers from here and Caddy
// meets them already set. Caddy must *replace* them, on the chunks too, and never add to them: a second
// `Cross-Origin-Opener-Policy` line would make the value a list, which browsers ignore.
// A third kind is Next's own answer for `/_next/data/<the real build id>/<anything not ending in .json>` (the build id is in the
// page source): `handleNextDataRequest` renders the prerendered default 404 inside the invoke and ends the response, a document with
// inline scripts that have no nonce and no CSP, COOP, CORP or Permissions-Policy. The proxy is then asked after the response has ended, not
// before it, so it cannot add anything, and Next logs `ERR_HTTP_HEADERS_SENT` ("Cannot append headers after they are sent") with a stack for
// every such request, measured on next start (gate-r7-3): the build id is public, so any visitor can write one such log entry per request.
// Neither app has a data route and no `next.config` hook reaches it (a redirect source cannot start with /_next, a `headers()` entry is never
// applied to a response that Next finished itself), so Caddy has to answer `/_next/data/*` itself, with the default CSP (gate-r3-4); that also
// removes the log entry. A data URL that does end in `.json` does run the proxy, which answers it with its own 404 (createProxy, gate-r3-6).
// A fourth kind is the 307 of next.config.ts for a path that ends in `.rsc`: redirects run before the proxy, on the raw path, which is the
// only place the suffix can still be seen (Next cuts one before it hands the request over, gate-r7-2). It carries no CSP and renders nothing.
// Nothing else skips it: a path with an escape that does not decode (`/x%C0`, `/fa/%zz`) does run the proxy, and
// createProxy answers it with a 404 that has all four, because Next's own answer for it is a bare 500 (wp5-r16).

/** Cuts the page off from any window it did not open, so a cross-origin popup cannot hold a reference to it. */
export const COOP = "same-origin";

/** The panel and the admin embed nothing from another origin, so nothing from another origin may embed them. */
export const CORP = "same-origin";

export type ProxyApp = "panel" | "admin";

/**
 * Camera, microphone and geolocation are off, the three features that the dashboards never use and that a
 * page can ask the visitor for. Every other feature keeps the browser's own default allowlist, and that is
 * not `self` for all of them: most features default to `self`, but Chrome's advertising and Topics features
 * (browsing-topics, join-ad-interest-group, run-ad-auction, attribution-reporting, shared-storage,
 * private-aggregation) default to `*`. This is not a closed surface. Today `*` and `self` behave the same,
 * because `frame-src 'none'` leaves no cross-origin frame and `script-src 'self'` plus the nonce leaves no
 * third-party script. Whoever relaxes either (P5's map, a framed provider) must list those features with `()`
 * first, as a spec 15.1 change. Spec 15.1 fixes the value, Caddy repeats it, so widening the list is a change
 * made in this file, `headersSpec.ts` and the Caddy line together. `clipboard-write` is for the copy
 * buttons of both apps. `interest-cohort` is not listed: it is obsolete.
 *
 * Passkeys differ per app (gate-r2-18). Only the panel uses them (AUTH 7.5), and the passkey RP ID is the registrable
 * domain of the panel host, so the admin host is a sibling the RP ID also covers: the admin has no passkey screen
 * (spec 11.1), so the browser must refuse a ceremony there and not leave that to the server's allowed_origins alone.
 */
export function permissionsPolicy(app: ProxyApp): string {
  const passkey = app === "panel" ? "(self)" : "()";
  return [
    "camera=()",
    "microphone=()",
    "geolocation=()",
    `publickey-credentials-get=${passkey}`,
    `publickey-credentials-create=${passkey}`,
    "clipboard-write=(self)",
  ].join(", ");
}

export function securityHeaders(app: ProxyApp): Record<string, string> {
  return {
    "Cross-Origin-Opener-Policy": COOP,
    "Cross-Origin-Resource-Policy": CORP,
    "Permissions-Policy": permissionsPolicy(app),
  };
}
