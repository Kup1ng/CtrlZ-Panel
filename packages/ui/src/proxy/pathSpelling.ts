/**
 * One spelling of a path, segment by segment: decode, then encode the way `encodeURIComponent` does (which is how a
 * link built from a name writes it). Null when an escape does not decode. A slash stays a separator, so `%2F` stays one escape.
 */
export function canonicalPath(pathname: string): string | null {
  try {
    return pathname.split("/").map((segment) => encodeURIComponent(decodeURIComponent(segment))).join("/");
  } catch {
    return null;
  }
}

// The URL parser reads a path differently from the gate: it deletes tab, LF and CR anywhere in it and trims C0 controls and spaces from its end,
// so `/profiles%00` and `/pro%0afiles` still resolve to the protected page while the gate sees another name (wp5-r15-1). No page of ours has
// such a name, so any escaped (or literal) C0 control, DEL or space in a path is refused outright, whichever segment and position it is in.
export const CONTROL_OR_SPACE = /[\u0000- \u007f]|%(?:[01][0-9a-f]|20|7f)/i;

/**
 * Next's segment-prefetch spelling of a page, `<page>.segments/<segment>.segment.rsc`. The proxy answers it with its own plain 404 before the
 * gate (gate-r6-3, see nextRequests.ts), so the pattern lives here beside the rest of the path rules: sanitizeNext must refuse every path that
 * the proxy refuses, or a visitor who signs in lands on a bare "Not Found" (gate-r12-3).
 */
export const SEGMENT_PREFETCH_PATH = /\.segments(?:\/|$)|\.segment\.rsc$/i;

const RESPELLED_ESCAPE =/%(?:24|26|2b|2c|3a|3b|3d|40|5b|5d|5e|7c)/i;

/**
 * The part of the proxy's rule for a path that needs no next-intl, so the login page can apply it too (gate-r8-2). Once the visitor
 * has a session the proxy answers a bare 404 for a path that is not written the way a link writes it (`%70rofiles`, `x%2e`, `%28`, a
 * lowercase `%2f`) and for one that holds an escaped percent sign (`50%25`: next-intl's rewrite then holds a bare `%`, which no page
 * can be asked for). `sanitizeNext` refuses what this refuses, so a visitor is never sent, after signing in, to a path that is a dead
 * end. It is stricter than the proxy in a few spellings the proxy would pass on as they are (a literal `[`); a dropped `next` costs one
 * click, a kept one costs a bare "Not Found" page after a successful login.
 */
export function isWrittenLikeALink(pathname: string): boolean {
  // A path the proxy refuses by its shape, whoever asks (nextRequests.ts): one pattern, so a new class there is added once.
  if (SEGMENT_PREFETCH_PATH.test(pathname)) return false;
  if (/%25/i.test(pathname)) return false;
  // The proxy refuses a control character or a space outright, escaped or not (createProxy), and encodeURIComponent writes a space as `%20`.
  if (CONTROL_OR_SPACE.test(pathname)) return false;
  // next-intl writes these escapes as the characters themselves (`%5B` to `[`), which the proxy accepts as the same page, except that it
  // also cuts a trailing slash from that rewrite, so `/profiles/%5Bx/` is a 404 with a session. A fuzz over the pieces found it (gate-r8-2).
  if (pathname.endsWith("/") && RESPELLED_ESCAPE.test(pathname)) return false;
  return canonicalPath(pathname) === pathname;
}
