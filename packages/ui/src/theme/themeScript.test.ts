import {renderToStaticMarkup} from "react-dom/server";
import {createElement} from "react";
import {describe, expect, it} from "vitest";

import {ThemeScript} from "./ThemeScript.tsx";
import {ALL_THEME_CLASSES} from "./html.ts";

// Gate round 10 (gate-r10-1). The script string is built from themeNames() at module load, so a rename of `classes` or a broken
// quotation turns it into a script that throws or does nothing for a visitor with no cookie, while the CSP stays satisfied. This runs
// the real string against a stand-in for <html> and for matchMedia. The browser case in apps/panel/e2e/theme-script.spec.ts runs it
// under the production CSP.

function scriptSource(nonce?: string) {
  const markup = renderToStaticMarkup(createElement(ThemeScript, {nonce}));
  const m = /^<script[^>]*>([\s\S]*)<\/script>$/.exec(markup);
  expect(m, "one script element").not.toBeNull();
  return {markup, body: m![1]!};
}

function run(opts: {dark: boolean; initial?: string[]}) {
  const classes = new Set<string>(opts.initial ?? ["font-dana"]);
  const attrs = new Map<string, string>();
  const root = {
    classList: {
      contains: (c: string) => classes.has(c),
      add(...names: string[]) {
        for (const n of names) classes.add(n);
      },
    },
    setAttribute: (k: string, v: string) => void attrs.set(k, v),
  };
  const matchMedia = (q: string) => ({matches: q.includes("dark") && opts.dark});
  new Function("document", "matchMedia", scriptSource().body)({documentElement: root}, matchMedia);
  return {classes: [...classes], dataTheme: attrs.get("data-theme")};
}

describe("ThemeScript body (spec 5.1)", () => {
  it("adds the dark classes and data-theme for a dark OS when the server rendered no theme class, and keeps the font class", () => {
    const r = run({dark: true});
    expect(r.classes).toEqual(["font-dana", "dark", "flat-dark"]);
    expect(r.dataTheme).toBe("dark");
  });

  it("adds the light classes for a light OS", () => {
    const r = run({dark: false});
    expect(r.classes).toEqual(["font-dana", "light", "flat-light"]);
    expect(r.dataTheme).toBe("light");
  });

  it("returns at once when the server rendered a light or dark class", () => {
    for (const initial of [["light", "flat-light"], ["dark", "flat-dark"]]) {
      const r = run({dark: initial[0] === "light", initial});
      expect(r.classes).toEqual(initial);
      expect(r.dataTheme).toBeUndefined();
    }
  });

  it("only ever adds classes the controller knows how to remove", () => {
    for (const dark of [true, false]) {
      for (const c of run({dark}).classes.filter((c) => c !== "font-dana")) expect(ALL_THEME_CLASSES).toContain(c);
    }
  });

  it("puts the nonce on the one script element and loads nothing", () => {
    const {markup} = scriptSource("abc123");
    expect(markup).toContain('nonce="abc123"');
    expect(markup).not.toMatch(/\ssrc=/);
  });
});
