import {isWrittenLikeALink} from "./pathSpelling.ts";

/**
 * Validates the `next` query value of the login redirect (spec 15.4). It is
 * used by the proxy and by the login page, so a value that one accepts is a
 * value the other accepts.
 *
 * `next` is a path without a locale, for example `/profiles?tab=1`. It must
 * start with one `/`, hold no `//`, no backslash, no scheme and no control
 * character, no `.` or `..` segment (however it is written), and begin with a
 * known path prefix, and the path must be written the way a link writes it (isWrittenLikeALink), because the proxy refuses the
 * other spellings with a 404 once there is a session. Anything else is dropped, and the caller falls back to
 * the home page.
 */
export function sanitizeNext(raw: string | null | undefined, knownPrefixes: readonly string[]): string | undefined {
  if (typeof raw !== "string" || raw === "" || raw.length > 2048) return undefined;
  if (!raw.startsWith("/") || raw.startsWith("//")) return undefined;

  // Check the text the browser will actually follow, so %5c and %2f cannot
  // smuggle in what the literal check refuses.
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return undefined;
  }
  for (const text of [raw, decoded]) {
    if (text.includes("\\") || text.includes("//") || text.includes("://")) return undefined;
    // C0 and C1 controls, DEL, and the line and paragraph separators.
    if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(text)) return undefined;
    // Zero-width and bidi override characters hide where a link goes.
    if (/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(text)) return undefined;
  }

  // The URL parser strips leading and trailing C0 controls and spaces before it folds dot segments, so a last
  // segment written `.. ` is no dot segment here and becomes one there (wp4-r18-1). Controls are refused above;
  // edge whitespace is refused here, on the raw text and on its decode.
  if (hasEdgeSpace(raw) || hasEdgeSpace(decoded)) return undefined;

  const path = raw.split(/[?#]/, 1)[0]!;
  if (hasDotSegment(path)) return undefined;
  if (!hasKnownPrefix(path, knownPrefixes)) return undefined;

  // Last line of defence: read the value the way router.push will, and require that it stays on the origin and
  // under a known prefix. A spelling the lists above did not think of is caught here, because this is the
  // browser's own reading and not ours.
  let resolved: URL;
  try {
    resolved = new URL(raw, RESOLVE_BASE);
  } catch {
    return undefined;
  }
  if (resolved.origin !== RESOLVE_ORIGIN) return undefined;
  if (!hasKnownPrefix(resolved.pathname, knownPrefixes)) return undefined;
  // A path that the proxy would answer with a bare 404 once the visitor has a session is no place to send them after sign-in (gate-r8-2).
  if (!isWrittenLikeALink(resolved.pathname)) return undefined;
  return raw;
}

// A reserved host name (RFC 2606): only a yardstick for the origin comparison, never fetched.
const RESOLVE_BASE = "https://ctrlz.invalid";
const RESOLVE_ORIGIN = new URL(RESOLVE_BASE).origin;

function hasKnownPrefix(path: string, knownPrefixes: readonly string[]): boolean {
  return knownPrefixes.some((p) => path === p || path.startsWith(`${p}/`));
}

/** True when the text starts or ends with whitespace, which the URL parser trims before it reads the path. */
function hasEdgeSpace(text: string): boolean {
  return /^\s|\s$/.test(text);
}

/**
 * A prefix check on the raw text is not a check on where the browser lands: it resolves `/profiles/../x` to
 * `/x`, and reads `%2e` as a dot. So every segment of the path, as written and after each decode the page or
 * a server may apply, must not be `.` or `..` (wp8-r2-7).
 */
function hasDotSegment(path: string): boolean {
  let text = path;
  for (let round = 0; round < 3; round += 1) {
    // trim(): a segment such as `.. ` is a dot segment once the parser has cut the space off its end.
    if (text.split("/").some((segment) => segment.trim() === "." || segment.trim() === "..")) return true;
    const next = decodeLeniently(text);
    if (next === text) return false;
    text = next;
  }
  return false;
}

/**
 * One more decode, as a server would apply it. A text that is not decodable as a whole (a literal `%` left by
 * an earlier round, as in `50%25`) is decoded segment by segment, and a segment that cannot be decoded stays
 * as it is. Refusing it instead would turn every path with an escaped percent sign into "no next" (wp5-r14-1),
 * and the segments that can be decoded are still checked.
 */
function decodeLeniently(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text
      .split("/")
      .map((segment) => {
        try {
          return decodeURIComponent(segment);
        } catch {
          return segment;
        }
      })
      .join("/");
  }
}
