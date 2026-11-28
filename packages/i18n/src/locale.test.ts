import {describe, expect, it} from "vitest";

import {defaultLocale, dirOf, isLocale, localeAutonym, locales, reactAriaLocale} from "./locale.ts";
import {routing} from "./routing.ts";

describe("locale", () => {
  it("is Persian first", () => {
    expect(defaultLocale).toBe("fa");
    expect([...locales]).toEqual(["fa", "en"]);
  });
  it("sets direction from the locale", () => {
    expect(dirOf("fa")).toBe("rtl");
    expect(dirOf("en")).toBe("ltr");
  });
  it("spells the calendar and the digits out", () => {
    expect(reactAriaLocale.fa).toContain("-u-ca-persian");
    expect(reactAriaLocale.fa).toContain("nu-arabext");
    expect(reactAriaLocale.en).toContain("-u-ca-gregory");
    expect(reactAriaLocale.en).toContain("nu-latn");
  });
  it("accepts only known locales", () => {
    expect(isLocale("fa")).toBe(true);
    expect(isLocale("en")).toBe(true);
    expect(isLocale("de")).toBe(false);
    expect(isLocale("FA")).toBe(false);
    expect(isLocale(undefined)).toBe(false);
  });
  it("writes each language in itself", () => {
    expect(localeAutonym.fa).toBe("فارسی");
    expect(localeAutonym.en).toBe("English");
  });
});

describe("routing", () => {
  it("lets the URL alone decide", () => {
    expect(routing.localePrefix).toBe("always");
    expect(routing.localeDetection).toBe(false);
    expect(routing.localeCookie).toBe(false);
    expect(routing.alternateLinks).toBe(false);
  });
});
