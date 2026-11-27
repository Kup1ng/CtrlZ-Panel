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

  it("emits every row, and never uses !important", async () => {
    const css = await render();
    for (const r of rows) expect(css, r.selector).toContain(`  ${r.selector} {`);
    expect(css).not.toContain("!important");
  });

  // D71: the nine boxes that HeroUI draws at another radius were a proposal until 2026-11-25. They are rows now,
  // so a box is 20px at every one of them, and no row can wait for the owner again without a new field in the type.
  it("holds the nine boxes of D71 as live 20px box rows, and has no pendingOwner field", async () => {
    const css = await render();
    const d71 = [".item-card-group", ".widget", ".alert", ".toast", ".accordion--surface", ".select__popover", ".autocomplete__popover", ".combo-box__popover", ".sidebar--floating"];
    for (const selector of d71) {
      const row = rows.find((r) => r.selector === selector);
      expect(row?.kind, selector).toBe("box");
      expect(Object.keys(row ?? {}), selector).not.toContain("pendingOwner");
      const start = css.indexOf(`  ${selector} {`);
      expect(start, selector).toBeGreaterThan(-1);
      expect(css.slice(start, css.indexOf("}", start)), selector).toContain("border-radius: var(--radius-box)");
    }
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

  // wp8-r9-4: the parts of an input group round their free corners with --radius-field, so the shell hands them its own
  // radius, and keeps its border-radius. Without the first the autofill cover is clipped to the 8px --radius inside
  // a 15.6px shell; without the second the shell is square.
  it("the input group gives its inner parts the shell's radius and keeps its own", async () => {
    const css = await render();
    const group = css.slice(css.indexOf("  .input-group {"));
    const body = group.slice(0, group.indexOf("}"));
    const rule = "min(calc(var(--control-h) * var(--radius-control-ratio)), var(--radius-control-cap))";
    expect(body).toContain(`border-radius: ${rule};`);
    // HeroUI reads --field-radius for rounded-field and --radius-field for the autofill clip-path.
    expect(body).toContain(`--field-radius: ${rule};`);
    expect(body).toContain(`--radius-field: ${rule};`);
  });
});