import {describe, expect, it} from "vitest";

import {PANEL_PROTECTED_PREFIXES} from "./prefixes.ts";
import {sanitizeNext} from "./safeNext.ts";

const ok = (v: string) => sanitizeNext(v, PANEL_PROTECTED_PREFIXES);

describe("sanitizeNext", () => {
  it.each(["/profiles", "/profiles/abc", "/profiles/a.b", "/profiles/...", "/profiles/x?next=/../y", "/profiles#/../y", "/profiles?tab=1", "/analytics/statistics", "/preferences/account#x", "/endpoints/", "/profiles/a%3Fb", "/profiles/a%23b", "/profiles/a%2Fb", "/profiles/%D8%B3%D9%84%D8%A7%D9%85", "/profiles/a-b_c~d(e)!*", "/profiles/a%5Bb%5D", "/profiles/a%7Cb"])(
    "keeps %s",
    (v) => expect(ok(v)).toBe(v),
  );

  it.each([
    ["empty", ""],
    ["no slash", "profiles"],
    ["protocol relative", "//evil.example/profiles"],
    ["scheme", "https://evil.example/profiles"],
    ["scheme in path", "/profiles/https://evil.example"],
    ["javascript", "javascript:alert(1)"],
    ["backslash", "/\\evil.example"],
    ["backslash after prefix", "/profiles\\..\\x"],
    ["encoded backslash", "/%5cevil.example"],
    ["encoded double slash", "/profiles%2f%2fevil"],
    ["encoded slash start", "/%2fevil.example"],
    ["newline", "/profiles\n"],
    ["encoded newline", "/profiles%0d%0aSet-Cookie:x"],
    ["tab", "/pro\tfiles"],
    ["nul", "/profiles\u0000"],
    ["rtl override", "/profiles‮"],
    ["zero width", "/profiles​"],
    ["unknown prefix", "/unknown"],
    ["login loop", "/login"],
    ["locale prefixed", "/fa/profiles"],
    ["prefix lookalike", "/profilesx"],
    ["prefix lookalike 2", "/profiles-evil"],
    ["bad escape", "/profiles%zz"],
    ["root", "/"],
    ["dot-dot after prefix", "/profiles/../x"],
    ["dot-dot escapes the prefix", "/profiles/../../api/v1/me"],
    ["encoded dot-dot", "/profiles/%2e%2e/x"],
    ["encoded dot-dot upper case", "/profiles/%2E%2E/x"],
    ["half-encoded dot-dot", "/profiles/.%2e/x"],
    ["single dot", "/profiles/./x"],
    ["encoded single dot", "/profiles/%2e/x"],
    ["encoded slash between dots", "/profiles/..%2f..%2fx"],
    ["double-encoded dot-dot", "/profiles/%252e%252e/x"],
    // A literal percent sign left after a decode must not hide a dot segment in the next one (wp5-r14-1).
    ["double-encoded dot-dot next to an escaped percent", "/profiles/%252e%252e/x%25"],
    ["double-encoded dot-dot after an escaped percent", "/profiles/50%25/%252e%252e/x"],
    ["trailing dot-dot", "/profiles/.."],
    ["dot-dot before the query", "/profiles/..?x=1"],
    // The URL parser trims a trailing space, then folds the dot segment (wp4-r18-1).
    ["dot-dot with a trailing space", "/profiles/.. "],
    ["encoded dot-dot with a trailing space", "/profiles/%2e%2e "],
    ["mixed dot-dot with a trailing space", "/preferences/.%2E "],
    ["single dot with a trailing space", "/profiles/. "],
    ["encoded trailing space after a dot-dot", "/profiles/..%20"],
    ["trailing space after a plain path", "/profiles/abc "],
    ["trailing no-break space", "/profiles/abc "],
    ["dot-dot with a space before the query", "/profiles/.. ?x=1"],
    // The proxy answers these with a bare 404 once there is a session, so a login must not end there (gate-r8-2).
    ["an escaped percent sign", "/profiles/50%25"],
    ["an escaped percent sign before a query", "/profiles/50%25?tab=1"],
    ["an escaped letter", "/profiles/%70x"],
    ["an escaped prefix letter", "/%70rofiles"],
    ["an escaped dot", "/profiles/x%2e"],
    ["an escaped parenthesis", "/profiles/a%28b"],
    ["a lowercase escaped slash", "/profiles/a%2fb"],
    // Found by the fuzz in createProxy.test.ts: the proxy refuses a space outright, and cuts the trailing slash of next-intl's rewrite.
    ["an escaped space", "/profiles/a%20b"],
    ["an escaped bracket before a trailing slash", "/profiles/%5Bx/"],
    // The segment-prefetch class of gate-r6-3: the proxy's plain 404 for every method (gate-r12-3).
    ["a .segments/ path", "/profiles/a.segments/b"],
    ["a .segments/ path in capitals", "/profiles/a.SEGMENTS/b"],
    ["a trailing .segments", "/profiles/a.segments"],
    ["a segment file", "/profiles/a.segments/_tree.segment.rsc"],
    ["a trailing .segment.rsc", "/profiles/a.segment.rsc"],
    ["a .segments/ path with a query", "/profiles/a.segments/b?x=1"],
  ])("drops %s", (_name, v) => expect(ok(v)).toBeUndefined());

  it("keeps only what the browser reads as the same origin and a known prefix", () => {
    // A small deterministic fuzz over the pieces that have mattered: the verdict must agree with new URL().
    const pieces = ["/", "..", ".", "%2e", "%2E%2e", " ", "%20", "\\", "profiles", "preferences", "x", "?", "#", "%2f", "\t"];
    let seed = 7;
    const next = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
    let kept = 0;
    for (let i = 0; i < 20000; i += 1) {
      let value = "/";
      for (let n = next() % 7; n > 0; n -= 1) value += pieces[next() % pieces.length];
      if (ok(value) === undefined) continue;
      kept += 1;
      const url = new URL(value, "https://ctrlz.invalid");
      expect(url.origin, value).toBe("https://ctrlz.invalid");
      expect(PANEL_PROTECTED_PREFIXES.some((p) => url.pathname === p || url.pathname.startsWith(`${p}/`)), value).toBe(true);
    }
    expect(kept).toBeGreaterThan(0);
  });

  it("drops non-strings and long values", () => {
    expect(sanitizeNext(null, PANEL_PROTECTED_PREFIXES)).toBeUndefined();
    expect(sanitizeNext(undefined, PANEL_PROTECTED_PREFIXES)).toBeUndefined();
    expect(ok(`/profiles?${"a".repeat(3000)}`)).toBeUndefined();
  });

  it("follows the prefix list it is given", () => {
    expect(sanitizeNext("/users", ["/users"])).toBe("/users");
    expect(sanitizeNext("/profiles", ["/users"])).toBeUndefined();
  });
});
