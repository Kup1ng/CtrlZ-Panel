import {describe, expect, it} from "vitest";

import {parseThemeMode, THEME_SET} from "./config.ts";
import {ALL_THEME_CLASSES, themeHtmlProps, themeNames} from "./html.ts";

describe("theme names (spec 5.2)", () => {
  it("keeps the stock class next to the set class, so .dark selectors still match", () => {
    expect(themeNames("dark")).toEqual({classes: ["dark", "flat-dark"], dataTheme: "dark"});
    expect(themeNames("light")).toEqual({classes: ["light", "flat-light"], dataTheme: "light"});
  });

  it("lists every class the controller may add, so a swap removes exactly those", () => {
    for (const mode of ["light", "dark"] as const) {
      for (const c of themeNames(mode).classes) expect(ALL_THEME_CLASSES).toContain(c);
    }
    expect(ALL_THEME_CLASSES).toHaveLength(4);
  });

  it("renders final classes for light and dark, and none for system until the script runs", () => {
    expect(themeHtmlProps("dark").className).toContain("dark");
    expect(themeHtmlProps("light")["data-theme"]).toBeDefined();
    expect(themeHtmlProps("system")).toEqual({className: "", "data-theme": undefined});
    expect(themeHtmlProps("system", "dark").className).toContain("dark");
  });

  it("ships Flat only (D17), and has no Glass class name left to select", () => {
    expect(THEME_SET).toBe("flat");
    expect(ALL_THEME_CLASSES.some((c) => c.startsWith("glass"))).toBe(false);
    expect(JSON.stringify([themeNames("light"), themeNames("dark")])).not.toMatch(/glass/);
  });

  it("reads an unknown cookie value as system", () => {
    expect(parseThemeMode("dark")).toBe("dark");
    expect(parseThemeMode("purple")).toBe("system");
    expect(parseThemeMode(undefined)).toBe("system");
  });
});
