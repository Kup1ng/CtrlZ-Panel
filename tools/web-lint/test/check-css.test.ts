import {describe, expect, it} from "vitest";

import {checkCss, ourCssFiles, stripComments} from "../check-css.mjs";
import {checkRoundedField, fieldRadiusSelectors, readUnused} from "../check-rounded-field.mjs";

// One passing and one failing sample per ban (spec 16.1).

const check = (css: string, path = "packages/ui/styles/shell.css") => checkCss([{path, text: css}]);

describe("check-css", () => {
  it("fails on a physical edge", () => {
    for (const css of [
      ".a { left: 0; }",
      ".a { margin-left: 4px; }",
      ".a { padding-right: 4px; }",
      ".a { border-left: 1px solid; }",
      ".a { text-align: left; }",
      ".a { float: right; }",
    ]) {
      expect(check(css), css).not.toEqual([]);
    }
  });
  it("passes the logical forms and look-alikes", () => {
    expect(check(".a { inset-inline-start: 0; margin-inline-end: 4px; text-align: start; border-inline-start: 1px solid; }")).toEqual([]);
    expect(check(".a { --left: 1px; }")).toEqual([]);
  });

  it("fails on a remote URL and passes a local one", () => {
    expect(check(".a { background: url(https://x.example/a.png); }")).not.toEqual([]);
    expect(check(".a { background: url(//x.example/a.png); }")).not.toEqual([]);
    expect(check("@import url(x.css);")).not.toEqual([]);
    // wp12-r1-13: an upper-case scheme and the string form of a protocol-relative import.
    expect(check(".a { background: url(HTTPS://x.example/a.png); }")).not.toEqual([]);
    expect(check('@import "//fonts.example.com/x.css";')).not.toEqual([]);
    expect(check("@import '//fonts.example.com/x.css';")).not.toEqual([]);
    expect(check('@import "./local.css";')).toEqual([]);
    expect(check(".a { background: url(/img/a.png); }")).toEqual([]);
  });

  it("fails on a hex colour and a gradient outside the token files, and allows them inside", () => {
    expect(check(".a { color: #04b5fb; }")).not.toEqual([]);
    expect(check(".a { background: linear-gradient(red, blue); }")).not.toEqual([]);
    expect(check(":root { --x: #04b5fb; background: linear-gradient(red, blue); }", "packages/ui/styles/tokens.css")).toEqual([]);
    expect(check(":root { --x: #fff; }", "packages/ui/styles/flat.css")).toEqual([]);
    expect(check(".a { color: var(--accent); }")).toEqual([]);
  });

  it("fails on text-shadow and drop-shadow", () => {
    expect(check(".a { text-shadow: 0 0 4px red; }")).not.toEqual([]);
    expect(check(".a { filter: drop-shadow(0 0 4px red); }")).not.toEqual([]);
    expect(check(".a { box-shadow: var(--shadow); }")).toEqual([]);
  });

  it("needs a prefers-reduced-motion rule in a file that moves, and lets transition: none be", () => {
    expect(check(".a { transition: opacity 150ms; }")).not.toEqual([]);
    expect(check("@keyframes spin { to { opacity: 1; } }")).not.toEqual([]);
    expect(check(".a { transition: opacity 150ms; } @media (prefers-reduced-motion: reduce) { .a { transition: none; } }")).toEqual([]);
    expect(check("* { transition: none !important; }")).toEqual([]);
  });

  it("ignores what is inside a comment and keeps the line numbers", () => {
    expect(check("/* left: 0; https://x.example */ .a { color: red; }")).toEqual([]);
    expect(stripComments("a\n/* x\ny */\nb").split("\n")).toHaveLength(4);
    expect(check("/* one\ntwo */\n.a { left: 0; }")[0]).toContain(":3:");
  });

  it("finds our own CSS and reports nothing in it today", () => {
    const files = ourCssFiles();
    expect(files.length).toBeGreaterThan(3);
  });
});

describe("check-rounded-field", () => {
  const css = `
.thing {
  @apply rounded-field border;

  &__inner {
    @apply rounded-s-field;
  }
}

.other {
  @apply rounded-lg;
}
`;
  it("lists the selectors that use the field radius, with nesting resolved", () => {
    expect(fieldRadiusSelectors(css).sort()).toEqual([".thing", ".thing__inner"].sort());
  });

  it("fails on a selector with no row and no reason, and passes once either exists", () => {
    const sheet = [{file: "a.css", css}];
    const rows = [{selector: ".thing"}];
    expect(checkRoundedField(sheet, rows, "")).toHaveLength(1);
    expect(checkRoundedField(sheet, [], "")).toHaveLength(2);
    expect(checkRoundedField(sheet, rows, ".thing__inner # inner part of a clipped group")).toEqual([]);
  });

  it("fails on a line with no reason", () => {
    expect(readUnused(".thing__inner").problems).toHaveLength(1);
    expect(readUnused(".thing__inner # because").problems).toEqual([]);
  });
});
