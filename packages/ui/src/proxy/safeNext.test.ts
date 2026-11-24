import {describe, expect, it} from "vitest";

import {PANEL_PROTECTED_PREFIXES} from "./prefixes.ts";
import {sanitizeNext} from "./safeNext.ts";

const ok = (v: string) => sanitizeNext(v, PANEL_PROTECTED_PREFIXES);

describe("sanitizeNext", () => {
  it.each(["/profiles", "/profiles/abc", "/profiles?tab=1", "/analytics/statistics", "/preferences/account#x", "/endpoints/"])(
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
  ])("drops %s", (_name, v) => expect(ok(v)).toBeUndefined());

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
