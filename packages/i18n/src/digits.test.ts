import {describe, expect, it} from "vitest";

import {normalizeFaSearch, toAsciiDigits} from "./digits.ts";

describe("toAsciiDigits", () => {
  it("maps Persian digits", () => expect(toAsciiDigits("۰۱۲۳۴۵۶۷۸۹")).toBe("0123456789"));
  it("maps Arabic-Indic digits", () => expect(toAsciiDigits("٠١٢٣٤٥٦٧٨٩")).toBe("0123456789"));
  it("keeps ASCII and mixed input", () => expect(toAsciiDigits("12۳4٥ab")).toBe("12345ab"));
  it("keeps spaces, letters and separators", () => expect(toAsciiDigits("۱۲ ۳۴-x")).toBe("12 34-x"));
  it("handles the empty string", () => expect(toAsciiDigits("")).toBe(""));
  it("does not touch characters next to the digit ranges", () => {
    // U+06EF and U+06FA sit just outside the Persian digit range.
    expect(toAsciiDigits("\u06ef\u06fa\u065f\u066a")).toBe("\u06ef\u06fa\u065f\u066a");
  });
  it("keeps astral characters whole", () => expect(toAsciiDigits("😀۱")).toBe("😀1"));
});

describe("normalizeFaSearch", () => {
  it("folds Arabic yeh and kaf", () => expect(normalizeFaSearch("كتاب علي")).toBe("کتاب علی"));
  it("leaves Persian text as is", () => expect(normalizeFaSearch("کتاب علی")).toBe("کتاب علی"));
  it("leaves Latin text as is", () => expect(normalizeFaSearch("Netflix.com")).toBe("Netflix.com"));
  // A name drawn with Persian digits is found by typing Latin ones, and the other way round.
  it("folds Persian and Arabic-Indic digits to ASCII", () => expect(normalizeFaSearch("پروفایل ۷ و ٨")).toBe("پروفایل 7 و 8"));
  it("keeps ASCII digits", () => expect(normalizeFaSearch("Profile 7")).toBe("Profile 7"));
});
