// Requests that Next answers with a thrown error and a stack trace in the log (6 lines each, gate-r4-11), and that no page of ours can
// use. Neither app has a Server Action, so the proxy refuses them with its own 404, which has the CSP and the three headers and costs
// no stack trace.
//
// What the proxy cannot refuse: a malformed `Next-Router-State-Tree` (Next answers 500 with 16 log lines). Next removes the five flight
// headers (rsc, next-router-state-tree, next-router-prefetch, next-hmr-refresh, next-router-segment-prefetch) from the request before
// it hands it to the proxy (web/adapter.js, FLIGHT_HEADERS), so `request.headers` never holds the value, measured on next start. That
// one is the edge's to refuse: see the Caddy case in headersSpec.ts.
//
// The stripping is only for the proxy: Next's renderer still reads them, and Next's own client SENDS one of them. Every Link prefetch carries
// `rsc: 1`, `Next-Router-Prefetch: 1` and `Next-Router-Segment-Prefetch: /_tree` (incremental prefetching is Next 16's default and neither app turns
// it off), and the answer is the route tree, the names of every page under the locale layout, lab pages included, whether or not CTRLZ_LAB is on. So
// the header form is public by design and must not be refused anywhere: a refusal was built (a redirect in next.config.ts, then an edge rule would have
// been the same) and broke every prefetch. What is refused is the path form below, which no client of ours uses. headersSpec.ts pins both halves
// (gate-r22-3).

import type {NextRequest} from "next/server";
import {SEGMENT_PREFETCH_PATH} from "./pathSpelling.ts";

/**
 * Next's segment-prefetch spelling of a page: `<page>.segments/<segment>.segment.rsc`. The compiled matcher lets it through (its suffix group
 * is `(\.json|\.rsc|\.segments\/.+\.segment\.rsc)?`), but Next removes only `.rsc` before the proxy runs, so the gate sees the raw path, which
 * is no protected prefix, and the `[...rest]` catch-all answered 200 with the request path inside the payload (gate-r6-3). Neither app turns on
 * segment prefetching in its path form (no cacheComponents, no clientSegmentCache: the client sends the header form, above), so no page of ours is ever asked for like this and the whole class is a plain
 * 404 before the gate, for every method. That also closes the latent bypass: a gated page that one day became static would not be reachable
 * through this spelling with no cookie.
 */
// The pattern lives in pathSpelling.ts, because sanitizeNext must refuse the same paths (gate-r12-3).
export {SEGMENT_PREFETCH_PATH};

/**
 * Request headers that Next reads as its own routing signals and does not strip from an external request. Next removes most of them (its
 * INTERNAL_HEADERS list in server/lib/server-ipc/utils.js: x-now-route-matches, x-nextjs-data, x-matched-path, x-middleware-*-for-response ...),
 * but not this one, and a client can send it just the same:
 * - `x-middleware-prefetch` (base-server.js, "middleware prefetch"): any request with it, on a route that is not prerendered, gets `{}` with 200,
 *   `x-middleware-skip: 1` and `x-matched-path: <route pattern>`, so the answer maps the route layout and is a soft 200 for an unknown path or a name
 *   under /_next/static/ (gate-r13-3). No page of ours needs it: the App Router's client never sends it, it is the Pages Router's prefetch.
 * `nextRequests.test.ts` reads the headers that this Next version looks at and fails when one is neither stripped by Next, nor listed here, nor
 * decided as harmless, so a bump that starts reading another one is a decision made by a person.
 */
export const INTERNAL_ROUTING_HEADERS = ["x-middleware-prefetch"] as const;

/**
 * True for a request that Next would answer with a thrown error and a stack trace in the log:
 * - `Next-Action`, with any value and any method: it is how a Server Action call starts, and the app has none (`Failed to find Server Action`, 400).
 * - An internal routing header (INTERNAL_ROUTING_HEADERS), with any value.
 * - A segment-prefetch path (SEGMENT_PREFETCH_PATH): no stack trace, but a 200 from the catch-all that echoes the path.
 * - A multipart/form-data body: Next's action handler takes every multipart POST for an action (`Failed to find Server Action`, 409). The sign-in
 *   forms before hydration post urlencoded, which is untouched.
 */
export function refusedByNext(request: NextRequest): boolean {
  const h = request.headers;
  if (SEGMENT_PREFETCH_PATH.test(request.nextUrl.pathname)) return true;
  if (h.has("next-action")) return true;
  for (const name of INTERNAL_ROUTING_HEADERS) if (h.has(name)) return true;
  return (h.get("content-type") ?? "").toLowerCase().startsWith("multipart/form-data");
}

/**
 * A browser navigation. Chunk, style, font, image and worker loads keep their pass-through; a person who types or follows a link to a name under
 * `/_next/static/` is a navigation. Under that prefix there is nothing to show a person, and the name that is not a file would fall to the
 * catch-all with locale `_next`, where the root layout's notFound() gives Next's built-in English 404 with an inline <style> that has no nonce,
 * refused by the CSP, and with no lang, dir or csp-nonce meta (gate-r9-2). The proxy's own 404 has the headers and no markup.
 *
 * Two signals, in this order:
 * 1. `Sec-Fetch-Dest`, which every current browser sends. When it is there it decides alone: document, iframe, frame, embed and object are
 *    navigations, script, style, font, image, worker and the rest are not.
 * 2. Safari on macOS and iOS before 16.4 sends no Fetch Metadata at all, yet it renders the page like any browser (gate-r20-2). Without the header
 *    the request is a navigation when `Accept` names text/html before any all-types wildcard: a navigation says text/html first, while an
 *    old Safari's script, font and worker loads ask for the wildcard alone, its style loads for text/css and then the wildcard, and its images
 *    for image types and then the wildcard.
 *    A client that sends neither is not a browser that renders the page, and still gets Next's 404 with the CSP.
 */
const NAVIGATION_DEST = /^(?:document|iframe|frame|embed|object)$/i;

export function isNavigation(request: NextRequest): boolean {
  const dest = request.headers.get("sec-fetch-dest");
  if (dest !== null) return NAVIGATION_DEST.test(dest);
  for (const range of (request.headers.get("accept") ?? "").split(",")) {
    const type = (range.split(";")[0] ?? "").trim().toLowerCase();
    if (type === "text/html") return true;
    // A wildcard before text/html means the client asked for anything first: a sub-resource load, not a page.
    if (type === "*/*") return false;
  }
  return false;
}
