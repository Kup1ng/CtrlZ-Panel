import {describe, expect, it} from "vitest";

import {COUNTRY_CODES, isCountryCode} from "./countries.ts";
import {createAppFormat} from "./format.ts";

const PERSIAN_DIGITS = /[۰-۹]/;
const LATIN_DIGITS = /[0-9]/;
// 2026-11-07 12:00 UTC is 15:30 in Tehran (UTC+3:30, no daylight saving).
const NOON_UTC = new Date("2026-11-07T12:00:00Z");

describe("createAppFormat fa", () => {
  const f = createAppFormat("fa");
  it("writes a Jalali date with Persian digits", () => {
    const s = f.date(NOON_UTC);
    expect(s).toMatch(PERSIAN_DIGITS);
    expect(s).not.toMatch(LATIN_DIGITS);
    // 16 Aban 1405.
    expect(s).toContain("۱۴۰۵");
    expect(s).toContain("آبان");
  });
  it("uses Tehran time", () => {
    expect(f.time(NOON_UTC)).toBe("۱۵:۳۰");
  });
  it("shows the date and the time together", () => {
    const s = f.dateTime(NOON_UTC);
    expect(s).toContain("۱۴۰۵");
    expect(s).toContain("۱۵:۳۰");
  });
  it("formats numbers with Persian digits and separators", () => {
    expect(f.number(1234567)).toBe("۱٬۲۳۴٬۵۶۷");
    expect(f.number(0.5, {style: "percent"})).toBe("۵۰٪");
    expect(f.percent(0.256)).toMatch(/^۲۶/);
  });
  it("writes relative time in Persian", () => {
    const s = f.relative(new Date(NOON_UTC.getTime() - 3 * 60_000), NOON_UTC);
    expect(s).toMatch(PERSIAN_DIGITS);
    expect(s).toContain("دقیقه");
  });
  it("names countries in Persian", () => expect(f.regionName("ir")).toBe("ایران"));
  it("lists names with the language's own conjunction", () => {
    const out = f.list(["a", "b", "c"]);
    expect(out).toContain("و");
    expect(out).not.toContain(" and ");
  });
});

describe("createAppFormat en", () => {
  const f = createAppFormat("en");
  it("writes a Gregorian date with Latin digits", () => {
    const s = f.date(NOON_UTC);
    expect(s).toBe("Nov 7, 2026");
  });
  it("uses Tehran time", () => expect(f.time(NOON_UTC)).toMatch(/^3:30\s?PM$/));
  it("formats numbers", () => {
    expect(f.number(1234567)).toBe("1,234,567");
    expect(f.percent(0.5)).toBe("50%");
  });
  it("names countries in English", () => expect(f.regionName("IR")).toBe("Iran"));
  it("lists names with the language's own conjunction", () => expect(f.list(["a", "b", "c"])).toBe("a, b, and c"));
});

describe("relative", () => {
  const f = createAppFormat("en");
  const now = NOON_UTC;
  const ago = (ms: number) => f.relative(new Date(now.getTime() - ms), now);
  const SEC = 1000;
  const MIN = 60 * SEC;
  const HOUR = 60 * MIN;
  const DAY = 24 * HOUR;
  it("calls the last few seconds now", () => expect(ago(4 * SEC)).toBe("now"));
  it("picks seconds, minutes, hours, days, months and years", () => {
    expect(ago(30 * SEC)).toBe("30 seconds ago");
    expect(ago(5 * MIN)).toBe("5 minutes ago");
    expect(ago(3 * HOUR)).toBe("3 hours ago");
    expect(ago(2 * DAY)).toBe("2 days ago");
    expect(ago(90 * DAY)).toBe("3 months ago");
    expect(ago(800 * DAY)).toBe("2 years ago");
  });
  it("looks forward too", () => expect(f.relative(new Date(now.getTime() + 2 * DAY), now)).toBe("in 2 days"));
  it("takes ISO strings and timestamps", () => {
    expect(f.relative("2026-11-07T11:00:00Z", now)).toBe("1 hour ago");
    expect(f.relative(now.getTime() - 5 * MIN, now)).toBe("5 minutes ago");
  });
});

describe("bad input", () => {
  it("never throws on an invalid date", () => {
    const f = createAppFormat("fa");
    expect(f.date("not a date")).toBe("\u2014");
    expect(f.dateTime(Number.NaN)).toBe("\u2014");
    expect(f.time(new Date("x"))).toBe("\u2014");
    expect(f.relative("x")).toBe("\u2014");
  });
});

describe("countries", () => {
  it("lists the 249 assigned codes once each", () => {
    expect(COUNTRY_CODES).toHaveLength(249);
    expect(new Set(COUNTRY_CODES).size).toBe(249);
  });
  it("has a real name for every code in both languages", () => {
    for (const locale of ["fa", "en"] as const) {
      const f = createAppFormat(locale);
      for (const code of COUNTRY_CODES) expect(f.regionName(code), `${locale} ${code}`).not.toBe(code);
    }
  });
  it("checks codes", () => {
    expect(isCountryCode("IR")).toBe(true);
    expect(isCountryCode("ir")).toBe(false);
    expect(isCountryCode("XX")).toBe(false);
  });
});
