import {describe, expect, it} from "vitest";

import {waitOf} from "./retryWait.ts";

describe("waitOf (S8-r2-4)", () => {
  it("counts seconds up to two minutes, minutes up to two hours and hours after that, rounding up", () => {
    expect(waitOf(1)).toEqual({unit: "seconds", count: 1});
    expect(waitOf(120)).toEqual({unit: "seconds", count: 120});
    expect(waitOf(121)).toEqual({unit: "minutes", count: 3});
    expect(waitOf(7200)).toEqual({unit: "minutes", count: 120});
    expect(waitOf(7201)).toEqual({unit: "hours", count: 3});
    expect(waitOf(71_234)).toEqual({unit: "hours", count: 20});
  });
});
