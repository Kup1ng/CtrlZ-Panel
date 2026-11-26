import {existsSync, readFileSync, readdirSync} from "node:fs";
import {join} from "node:path";
import {isValidElement, type ReactElement} from "react";
import {describe, expect, it} from "vitest";

import {COUNTRY_CODES} from "../../i18n/src/countries.ts";
import {FLAGS} from "../src/flagTable.generated.ts";
import {drawNodes, flagDrawing, flagElement, loadFlags} from "../src/Flag.tsx";

const root = join(import.meta.dirname, "..");

describe("flag table", () => {
  it("has a flag for every ISO code the product knows, and no other", () => {
    expect(Object.keys(FLAGS).sort()).toEqual([...COUNTRY_CODES].sort());
  });

  it("draws with a few elements only, and carries no link, id, style or script", () => {
    const tags = new Set<string>();
    const attrs = new Set<string>();
    const walk = (nodes: readonly (readonly [string, Readonly<Record<string, string>>, readonly unknown[]])[]) => {
      for (const [tag, props, children] of nodes) {
        tags.add(tag);
        for (const [k, v] of Object.entries(props)) {
          attrs.add(k);
          expect(v, `${tag} ${k}`).not.toMatch(/https?:|url\(|javascript|<|>/i);
        }
        walk(children as never);
      }
    };
    for (const drawing of Object.values(FLAGS)) walk(drawing.children as never);
    expect([...tags].sort()).toEqual(["circle", "ellipse", "g", "path"]);
    expect(attrs.has("id")).toBe(false);
    expect(attrs.has("href")).toBe(false);
    expect(attrs.has("style")).toBe(false);
  });

  it("is 3 by 2 for every flag", () => {
    for (const [code, d] of Object.entries(FLAGS)) {
      // Some flags crop a larger drawing, so the origin is not always 0 0; the width and the height are what must be 3 by 2.
      const [, , w, h] = d.viewBox.split(" ").map(Number);
      expect(Math.abs(w! / h! - 1.5), code).toBeLessThan(0.02);
    }
  });

  it("keeps a copy of the licence beside the files and names the source in the note", () => {
    expect(readFileSync(join(root, "flags/LICENSE"), "utf8")).toMatch(/MIT License/);
    const note = join(root, "../../docs/licences/flags.md");
    expect(existsSync(note)).toBe(true);
    expect(readFileSync(note, "utf8")).toMatch(/Outcome: allowed/);
    expect(readdirSync(join(root, "flags")).filter((f) => f.endsWith(".svg"))).toHaveLength(COUNTRY_CODES.length);
  });
});

describe("Flag", () => {
  it("builds React elements from the table, with a key on each", () => {
    const nodes = drawNodes(FLAGS.DE!.children);
    expect(nodes.length).toBeGreaterThan(0);
    for (const n of nodes) {
      expect(isValidElement(n)).toBe(true);
      expect((n as ReactElement).key).not.toBeNull();
    }
  });

  it("finds a code in any case once the table is loaded, and nothing for what is not a code", async () => {
    await loadFlags();
    expect(flagDrawing("de")?.viewBox).toBe(FLAGS.DE!.viewBox);
    expect(flagDrawing("DE")).toBeDefined();
    for (const bad of ["", "D", "DEU", "XX", "1A", "__proto__", "constructor"]) expect(flagDrawing(bad), bad).toBeUndefined();
  });

  it("is hidden from readers beside a name and named when it stands alone", async () => {
    await loadFlags();
    const decorative = flagElement(flagDrawing("DE")) as ReactElement<Record<string, unknown>>;
    expect(decorative.props["aria-hidden"]).toBe(true);
    expect(decorative.props.role).toBeUndefined();
    const named = flagElement(flagDrawing("DE"), "Flag of Germany") as ReactElement<Record<string, unknown>>;
    expect(named.type).toBe("svg");
    // No drawing is an empty box of the same size, still hidden or named the same way.
    expect((flagElement(undefined) as ReactElement<Record<string, unknown>>).type).toBe("span");
    expect(named.props.role).toBe("img");
    expect(named.props["aria-label"]).toBe("Flag of Germany");
  });
});
