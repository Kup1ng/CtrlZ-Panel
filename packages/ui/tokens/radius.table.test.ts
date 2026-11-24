import {readFileSync} from "node:fs";
import {describe, expect, it} from "vitest";

import {render} from "../scripts/gen-radius.mjs";
import {rows} from "./radius.table.ts";

describe("radius table (T-474)", () => {
  it("has one row per selector", () => {
    const selectors = rows.map((r) => r.selector);
    expect(new Set(selectors).size).toBe(selectors.length);
  });

  it("matches the committed generated file", async () => {
    const committed = readFileSync(new URL("../styles/radius.generated.css", import.meta.url), "utf8");
    expect(await render()).toBe(committed);
  });

  it("never emits a pending row, and never uses !important or a physical sizing property", async () => {
    const css = await render();
    for (const r of rows) if (r.pendingOwner) expect(css).not.toContain(`${r.selector} {`);
    expect(css).not.toContain("!important");
  });

  it("only .control-50 and .control-75 set a height", () => {
    const setters = rows.filter((r) => r.kind === "control" && r.setsHeight).map((r) => r.selector);
    expect(setters.sort()).toEqual([".control-50", ".control-75"]);
  });

  it("keeps the D16 owner examples: 50 gives 20, 75 gives 30", async () => {
    const css = await render();
    expect(css).toContain("--control-h: var(--size-50)");
    expect(css).toContain("--control-h: var(--size-75)");
    // 0.4 * 50 = 20 and min(0.4 * 75, 30) = 30 are checked in a browser; here we only pin the inputs.
    expect(css).toContain("--radius-control-cap");
  });

  it("has no open exception candidate: Q5 is answered by D47", () => {
    for (const r of rows) expect(Object.keys(r), r.selector).not.toContain("exceptionCandidate");
  });

  it("exempts exactly the six switch rows, all as D47 pills", () => {
    const exempt = rows.filter((r) => r.kind === "control" && r.exception);
    expect(exempt.map((r) => r.selector)).toEqual([
      ".switch__control",
      ".switch--sm .switch__control",
      ".switch--lg .switch__control",
      ".switch__thumb",
      ".switch--sm .switch__thumb",
      ".switch--lg .switch__thumb",
    ]);
    for (const r of exempt) expect(r.kind === "control" && r.exception, r.selector).toEqual({decision: "D47", shape: "pill"});
  });

  it("emits a pill for an exempt row and the 0.4 formula for avatars and the checkbox", async () => {
    const css = await render();
    const block = (selector: string) => {
      const start = css.indexOf(`  ${selector} {`);
      expect(start, selector).toBeGreaterThan(-1);
      return css.slice(start, css.indexOf("}", start));
    };
    for (const r of rows) {
      if (r.kind !== "control" || !r.exception) continue;
      const b = block(r.selector);
      expect(b, r.selector).toContain("border-radius: calc(infinity * 1px)");
      expect(b, r.selector).not.toContain("--control-h");
      expect(b, r.selector).not.toContain("--radius-control-ratio");
    }
    for (const selector of [".avatar", ".avatar--sm", ".avatar--lg"]) {
      expect(block(selector), selector).toContain("--avatar-radius: min(calc(var(--control-h) * var(--radius-control-ratio))");
    }
    expect(block(".checkbox__control")).toContain("border-radius: min(calc(var(--control-h) * var(--radius-control-ratio))");
    // The CellSwitch row is not the track: it keeps the rule, and the track inside is a stock .switch__control.
    expect(block(".cell-switch .cell-switch__trigger")).toContain("var(--radius-control-ratio)");
  });
});
