import {readFileSync} from "node:fs";
import {describe, expect, it} from "vitest";

import {otpChallengeId} from "./fixtures.ts";

// A mock answers whatever its author typed, so the id it hands the screens has to be one the API can give. The
// shape is read from main's OpenAPI file, not copied here: a change of the schema fails this test (P1 web merge, B1).
const spec = readFileSync(new URL("../../../../api/openapi.yaml", import.meta.url), "utf8");
const schema = (name: string) => spec.match(new RegExp(`^    ${name}:\n      type: object\n(?:      .*\n)+`, "m"))?.[0] ?? "";

describe("otpChallengeId", () => {
  it("is 64 characters of base64url, as OtpIssued says", () => {
    expect(schema("OtpIssued")).toMatch(/challenge_id: \{type: string, minLength: 64, maxLength: 64, pattern: \*b64url\}/);
    for (let seed = 1; seed < 40; seed++) expect(otpChallengeId(seed)).toMatch(/^[A-Za-z0-9_-]{64}$/);
  });

  it("holds - and _ and differs per seed", () => {
    expect(otpChallengeId(3)).toMatch(/-/);
    expect(otpChallengeId(3)).toMatch(/_/);
    expect(otpChallengeId(3)).not.toBe(otpChallengeId(4));
  });
});
