import {describe, expect, it} from "vitest";

import {ADMIN_RULE, hintFor, USER_RULE} from "./passwordStrength.ts";

// AUTH 4.2: an admin password is 14 code points with a score of 4, a user's 10 with a score of 3. The meter only words the hint
// by the rule it is given; the server decides.

describe("the admin rule of the password meter", () => {
  it("is 14 code points and a score of 4", () => {
    expect(ADMIN_RULE).toEqual({minLength: 14, enoughScore: 4});
    expect(USER_RULE).toEqual({minLength: 10, enoughScore: 3});
  });
  it("calls 13 characters short and 14 long enough for the length", () => {
    expect(hintFor("a".repeat(13), 4, ADMIN_RULE)).toBe("short");
    expect(hintFor("a".repeat(14), 4, ADMIN_RULE)).toBe("advisory");
    // The same text is long enough for a user.
    expect(hintFor("a".repeat(13), 4)).toBe("advisory");
  });
  it("asks for a score of 4 from an admin where 3 is enough for a user", () => {
    expect(hintFor("a".repeat(20), 3, ADMIN_RULE)).toBe("weak");
    expect(hintFor("a".repeat(20), 3)).toBe("advisory");
    expect(hintFor("a".repeat(20), 4, ADMIN_RULE)).toBe("advisory");
  });
  it("counts a code point once, as the server does", () => {
    expect(hintFor("😀".repeat(13), 4, ADMIN_RULE)).toBe("short");
    expect(hintFor("😀".repeat(14), 4, ADMIN_RULE)).toBe("advisory");
  });
});
