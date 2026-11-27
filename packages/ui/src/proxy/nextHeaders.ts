import {readFileSync} from "node:fs";
import {createRequire} from "node:module";
import {dirname, join} from "node:path";

// The request headers that this Next version looks at, read from its own files (gate-r13-3, gate-r14-1). It is used by the unit test that fails
// when a Next bump starts reading another header (nextRequests.test.ts) and by the live case that sends every one of them to a real server
// (headersSpec.ts), so the two cannot disagree about what "every header" is.
//
// Next names most of them by a constant (`req.headers[_constants.MATCHED_PATH_HEADER]`) and some without an `x-` prefix (`next-resume`, `next-url`,
// `rsc`), so a scan of `headers["x-..."]` literals sees only a part. The class is therefore three sources, each read from the installed package:
//   1. every `*_HEADER = '...'` and `NEXT_URL` constant of lib/constants.js and client/components/app-router-headers.js (Next's own names for
//      headers; the `*_CONTENT_TYPE_HEADER` ones hold a media type, not a header name);
//   2. every literal `headers['name']` read of the three server files that handle a request (any name, not only `x-`);
//   3. the INTERNAL_HEADERS list of server/lib/server-ipc/utils.js, which Next removes from every external request before it routes it.

export type NextHeaders = {
  /** Header names (lower case) that Next defines or reads. */
  readonly read: ReadonlySet<string>;
  /** The subset that Next deletes from an external request itself. */
  readonly stripped: ReadonlySet<string>;
};

const SERVER_FILES = ["server/base-server.js", "server/next-server.js", "server/app-render/app-render.js"];
const CONSTANT_FILES = ["lib/constants.js", "client/components/app-router-headers.js"];

// Resolved from the working directory and not from this file: Playwright loads headersSpec.ts as CommonJS, where import.meta does not exist, and both
// callers run in a folder that depends on next (packages/ui for vitest, apps/* for Playwright).
export function nextDist(): string {
  return join(dirname(createRequire(join(process.cwd(), "package.json")).resolve("next/package.json")), "dist");
}

export function readNextHeaders(dist: string = nextDist()): NextHeaders {
  const read = new Set<string>();
  for (const file of CONSTANT_FILES) {
    const source = readFileSync(join(dist, file), "utf8");
    for (const m of source.matchAll(/^const ([A-Z0-9_]+) = '([^']*)';/gm)) {
      const [, name, value] = m;
      if (name!.endsWith("_CONTENT_TYPE_HEADER")) continue;
      if (name!.endsWith("_HEADER") || name === "NEXT_URL") read.add(value!.toLowerCase());
    }
  }
  for (const file of SERVER_FILES) {
    const source = readFileSync(join(dist, file), "utf8");
    for (const m of source.matchAll(/headers\[\s*['"]([A-Za-z0-9-]+)['"]\s*\]/g)) read.add(m[1]!.toLowerCase());
  }
  const ipc = readFileSync(join(dist, "server/lib/server-ipc/utils.js"), "utf8");
  const stripped = new Set([...(/INTERNAL_HEADERS = \[([^\]]*)\]/.exec(ipc)?.[1] ?? "").matchAll(/'([a-z0-9-]+)'/g)].map((m) => m[1]!));
  return {read, stripped};
}

/**
 * Headers that Next reads, does not remove, and that the proxy does not refuse, with the reason each one is left alone. A name that is not in
 * Next's list any more is a stale line and fails the test, so this table cannot grow into a list of things nobody reads.
 *
 * "own case" means a live test in headersSpec.ts sends it on purpose and says what must happen.
 */
export const DECIDED: Readonly<Record<string, string>> = {
  // The address the client used. Caddy sets them and the app makes no routing or security decision on them.
  host: "the address the client used; Caddy sets it",
  "x-forwarded-proto": "the address the client used; Caddy sets it",
  "x-forwarded-host": "the address the client used; Caddy sets it",
  "x-forwarded-port": "the address the client used; Caddy sets it",
  "x-forwarded-for": "the address the client used; Caddy sets it",
  "user-agent": "bot detection for how metadata is streamed; changes no routing or policy",
  "sec-fetch-dest": "own case: the proxy reads it too (gate-r9-2, a navigation under /_next/static/)",
  // The flight protocol of the App Router. The client sends these on every client-side navigation, so they cannot be refused. Next removes the
  // five of them that the adapter lists from the request that the proxy sees, so the proxy cannot judge them; each has a refusal or a pin elsewhere.
  rsc: "the flight protocol; the client's own navigations send it",
  "next-router-state-tree": "the flight protocol; a malformed value is a stack trace in the log only, closed at the edge (Caddy, gate-r4-11b)",
  "next-router-prefetch": "the flight protocol; the client's own prefetches send it",
  "next-router-segment-prefetch": "the flight protocol; the segment-shaped paths that use it are refused (gate-r6-3)",
  "next-hmr-refresh": "dev server only; read by the dev render path",
  "next-url": "only part of the cache-busting hash of a flight request",
  // Cache and revalidation. Each needs a value that only the build holds (previewModeId in preview-props.json) or an ISR cache this app does not use.
  "x-prerender-revalidate": "needs the build's previewModeId, which no client has; the apps have no ISR",
  "x-prerender-revalidate-if-generated": "only read together with x-prerender-revalidate",
  "x-next-cache-tags": "read from the cache entry, not from the request",
  "x-next-revalidated-tags": "only honoured with x-next-revalidate-tag-token equal to the previewModeId",
  "x-next-revalidate-tag-token": "must equal the build's previewModeId, which no client has",
  // The rest are headers that Next writes on a response or reads on a path that needs a feature the apps do not turn on.
  "x-nextjs-deployment-id": "a navigation header that the client sends for skew protection; read only when a deployment id is configured",
  "x-nextjs-stale-time": "a response header",
  "x-nextjs-postponed": "a response header",
  "x-nextjs-rewritten-path": "a response header that the client router reads",
  "x-nextjs-rewritten-query": "a response header that the client router reads",
  "x-nextjs-prerender": "a response header",
  "x-nextjs-action-not-found": "a response header",
  "x-nextjs-request-id": "read only for the dev overlay's log relay",
  "x-nextjs-html-request-id": "read only for the dev overlay's log relay",
  "x-action-revalidated": "a response header",
};
