import {describe, expect, it} from "vitest";

import {isPhonePrefix} from "./phonePrefix.ts";

describe("isPhonePrefix", () => {
  it("accepts every form of the start of a mobile number", () => {
    for (const text of ["", "0", "09", "0912", "912", "98912", "+98912", "+98", "+", "0098912", "۰۹۱۲", "0912 345-67", "(0912)", "09123456789", "+989123456789"]) {
      expect(isPhonePrefix(text), text).toBe(true);
    }
  });

  it("refuses what the API refuses with 400: a letter, a first digit other than 9, more than ten digits, a misplaced plus", () => {
    for (const text of ["1", "ali", "09A", "08", "0812", "912345678901", "0912345678901", "9+1", "++98", "98+912", "12", "٣"]) {
      expect(isPhonePrefix(text), text).toBe(false);
    }
  });
});
