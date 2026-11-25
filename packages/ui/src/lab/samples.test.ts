import {describe, expect, it} from "vitest";

import {rows} from "../../tokens/radius.table.ts";
import {COMPONENT_SELECTORS, HAND_SELECTORS} from "./samples.ts";

const live = rows.filter((row) => !row.pendingOwner);
const selectors = new Set(live.map((row) => row.selector));

describe("token lab sample lists", () => {
  it("names only selectors that are live rows of the radius table", () => {
    // A selector the table renamed or dropped would turn its component sample into bare markup unnoticed.
    const stale = [...COMPONENT_SELECTORS, ...HAND_SELECTORS].filter((selector) => !selectors.has(selector));
    expect(stale).toEqual([]);
  });

  it("lists a selector once, and in one list", () => {
    const all = [...COMPONENT_SELECTORS, ...HAND_SELECTORS];
    expect(new Set(all).size).toBe(all.length);
  });

  it("keeps the split the spec states: 48 components, 40 bare markup, of 88 live rows", () => {
    expect(live.length).toBe(88);
    expect(COMPONENT_SELECTORS.length).toBe(48);
    expect(live.length - COMPONENT_SELECTORS.length).toBe(40);
  });
});
