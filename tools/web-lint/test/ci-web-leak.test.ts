import {describe, expect, it} from "vitest";

import {asToken, leakPatterns, phoneTail} from "../../../scripts/ci-web-leak-patterns.mjs";

// Step 10f1 of scripts/ci-web.sh looks for these values in the logs of the front tier (merge-r4-8). The step itself needs the stack; what it looks
// for is decided here, so a spelling of the phone or a recorded code that the scan misses cannot go unseen.
const seed = {user: {phone: "09121234567", password: "user-secret-pass"}, admin: {password: "admin-secret-pass", totp_secret: "JBSWY3DPEHPK3PXP"}};
const noop = [
  JSON.stringify({to: "+989121234567", template: "otp", values: {code: "482913"}}),
  JSON.stringify({to: "+989121234567", template: "invite", values: {code: "AB12CD34", locale: "en"}}),
  "",
].join("\n");

describe("the phone", () => {
  it("is searched by its last ten digits, which are in the local form, the +98 form the API stores and a %2B98 URL", () => {
    expect(phoneTail("09121234567")).toBe("9121234567");
    expect(phoneTail("+989121234567")).toBe("9121234567");
    const {fixed} = leakPatterns(seed, noop);
    expect(fixed).toContain("9121234567");
    for (const spelling of ["09121234567", "+989121234567", "%2B989121234567"]) expect(spelling).toContain("9121234567");
  });
});

describe("leakPatterns", () => {
  const {fixed, regex, records} = leakPatterns(seed, noop);

  it("holds the seed's secrets and the header names", () => {
    for (const value of ["user-secret-pass", "admin-secret-pass", "JBSWY3DPEHPK3PXP", "Authorization", "Cookie"]) expect(fixed).toContain(value);
  });

  it("holds every code the noop driver recorded, and not a short value such as a locale", () => {
    expect(records).toBe(2);
    expect(regex).toHaveLength(2);
    expect(regex.some((p: string) => new RegExp(p).test('GET /x?code=482913 HTTP'))).toBe(true);
    expect(regex.some((p: string) => new RegExp(p).test("invite AB12CD34"))).toBe(true);
    expect(regex.some((p: string) => new RegExp(p).test("locale en"))).toBe(false);
  });

  it("matches a code as a whole token, so a timestamp or a longer number that contains it is not a hit", () => {
    const code = new RegExp(asToken("482913"));
    expect(code.test('{"ts":1732412123.482913,"msg":"x"}')).toBe(false);
    expect(code.test("took 14829135 bytes")).toBe(false);
    expect(code.test('"msg":"482913"')).toBe(true);
    expect(code.test("482913")).toBe(true);
  });

  it("escapes what a value holds, so a code with a dot or a bracket cannot widen the pattern", () => {
    expect(new RegExp(asToken("a.b+c")).test("a.b+c")).toBe(true);
    expect(new RegExp(asToken("a.b+c")).test("aXbbc")).toBe(false);
  });

  it("counts no record for an empty file, which the command line refuses", () => {
    expect(leakPatterns(seed, "\n").records).toBe(0);
  });
});
