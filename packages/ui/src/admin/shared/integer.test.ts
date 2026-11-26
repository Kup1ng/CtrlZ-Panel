import {describe, expect, it} from "vitest";

import {parseInteger} from "./integer.ts";

describe("parseInteger", () => {
  it("reads digits of every numeral system", () => {
    expect(parseInteger("720")).toEqual({kind: "number", value: 720});
    expect(parseInteger("۷۲۰")).toEqual({kind: "number", value: 720});
    expect(parseInteger("٧٢٠")).toEqual({kind: "number", value: 720});
  });

  it("reads grouping and invisible marks as layout", () => {
    expect(parseInteger("1,000")).toEqual({kind: "number", value: 1000});
    expect(parseInteger("۱٬۰۰۰")).toEqual({kind: "number", value: 1000});
    expect(parseInteger(" 5\u200c0 ")).toEqual({kind: "number", value: 50});
  });

  it("is empty for blank text and invalid for any decimal, minus or letter, never a different number", () => {
    expect(parseInteger("")).toEqual({kind: "empty"});
    expect(parseInteger("  \u200f ")).toEqual({kind: "empty"});
    for (const text of ["1.5", "۱٫۵", "1/5", "-5", "\u22125", "+5", "12abc", "abc", ",", "1e3", "0x10"]) {
      expect(parseInteger(text), text).toEqual({kind: "invalid"});
    }
  });

  it("keeps the first 15 digits of a number too long to be exact", () => {
    expect(parseInteger("9".repeat(30))).toEqual({kind: "number", value: 999999999999999});
  });
});
