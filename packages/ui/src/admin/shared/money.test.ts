import {describe, expect, it} from "vitest";

import {canonicalMoney, isMoney, normalizeMoney, sameMoney} from "./money.ts";

describe("normalizeMoney", () => {
  it("reads Persian digits and the Persian decimal mark", () => {
    expect(normalizeMoney("۱۲٫۵")).toBe("12.5");
    expect(normalizeMoney("۰٫۵")).toBe("0.5");
    expect(normalizeMoney("٠٫٥")).toBe("0.5");
  });
  it("treats the Persian thousands mark, spaces and invisible marks as layout", () => {
    expect(normalizeMoney("۱٬۲۵۰٫۵")).toBe("1250.5");
    expect(normalizeMoney(" 250 000\u200c")).toBe("250000");
  });
  it("leaves a Latin comma alone, so it stays invalid", () => {
    expect(isMoney(normalizeMoney("1,5"))).toBe(false);
  });
  it("is valid only in the shape of the API's money", () => {
    for (const ok of ["", "0", ".5", "12.5", "۱۲٫۵", "1234567890.1234"]) expect(isMoney(normalizeMoney(ok)), ok).toBe(true);
    for (const bad of ["-1", "1.", "1.23456", "12345678901", "abc", "1e3", "1٫2٫3"]) expect(isMoney(normalizeMoney(bad)), bad).toBe(false);
  });
});

describe("canonicalMoney", () => {
  it("is one spelling for one amount", () => {
    expect(sameMoney("250000.0000", "250000")).toBe(true);
    expect(sameMoney("0.5000", "۰٫۵")).toBe(true);
    expect(sameMoney("007", "7")).toBe(true);
    expect(sameMoney("0.0000", "0")).toBe(true);
    expect(canonicalMoney("12.3400")).toBe("12.34");
    expect(sameMoney(".5", "0.5000")).toBe(true);
  });
  it("never calls text that is not an amount the same as an amount", () => {
    expect(sameMoney("1.", "1")).toBe(false);
    expect(sameMoney("abc", "abc")).toBe(false);
  });
  it("keeps no cap and a zero cap apart, and different amounts apart", () => {
    expect(sameMoney("", "0")).toBe(false);
    expect(sameMoney("0.5", "0.6")).toBe(false);
  });
});
