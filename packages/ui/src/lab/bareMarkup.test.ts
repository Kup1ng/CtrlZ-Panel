import {describe, expect, it} from "vitest";

import {rows} from "../../tokens/radius.table.ts";
import {bareMarkup} from "./bareMarkup.ts";

describe("bareMarkup", () => {
  it("reads a class", () => {
    expect(bareMarkup(".card")).toEqual([{classes: ["card"], attrs: {}, children: []}]);
  });

  it("nests a descendant chain, the last compound is the target", () => {
    const [root] = bareMarkup(".pagination--sm .pagination__link");
    expect(root?.classes).toEqual(["pagination--sm"]);
    expect(root?.children[0]?.classes).toEqual(["pagination__link"]);
  });

  it("reads attributes", () => {
    const [root] = bareMarkup(".sheet__content[data-detached] .sheet__dialog");
    expect(root?.attrs).toEqual({"data-detached": ""});
    expect(root?.children[0]?.classes).toEqual(["sheet__dialog"]);
  });

  it("puts a :has() argument inside the element", () => {
    const [root] = bareMarkup(".segment:has(.segment__item--lg)");
    expect(root?.classes).toEqual(["segment"]);
    expect(root?.children.map((c) => c.classes)).toEqual([["segment__item--lg"]]);
  });

  it("makes one root per alternative of a list", () => {
    expect(bareMarkup(".a, .b").map((n) => n.classes)).toEqual([["a"], ["b"]]);
  });

  it("refuses what it cannot draw", () => {
    expect(() => bareMarkup(".a > .b")).toThrow();
    expect(() => bareMarkup(".a:hover")).toThrow();
  });

  it("draws every selector of the radius table", () => {
    for (const row of rows) expect(() => bareMarkup(row.selector), row.selector).not.toThrow();
  });
});
