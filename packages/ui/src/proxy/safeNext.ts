/**
 * Validates the `next` query value of the login redirect (spec 15.4). It is
 * used by the proxy and by the login page, so a value that one accepts is a
 * value the other accepts.
 *
 * `next` is a path without a locale, for example `/profiles?tab=1`. It must
 * start with one `/`, hold no `//`, no backslash, no scheme and no control
 * character, and begin with a known path prefix. Anything else is dropped,
 * and the caller falls back to the home page.
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

  const path = raw.split(/[?#]/, 1)[0]!;
  const known = knownPrefixes.some((p) => path === p || path.startsWith(`${p}/`));
  return known ? raw : undefined;
}
