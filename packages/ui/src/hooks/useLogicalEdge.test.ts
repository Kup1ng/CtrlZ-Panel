import {describe, expect, it} from "vitest";

import {badgePlacement, edgeToward, physicalEdge} from "./useLogicalEdge.ts";

describe("physicalEdge", () => {
  it("maps start and end by direction", () => {
    expect(physicalEdge("start", "ltr")).toBe("left");
    expect(physicalEdge("end", "ltr")).toBe("right");
    expect(physicalEdge("start", "rtl")).toBe("right");
    expect(physicalEdge("end", "rtl")).toBe("left");
  });
});

describe("edgeToward", () => {
  // The sidebar sits at the inline start in both directions, so the content is toward the end.
  it("points a tooltip from the sidebar toward the content", () => {
    expect(edgeToward("content", "ltr")).toBe("right");
    expect(edgeToward("content", "rtl")).toBe("left");
  });

  it("points toward the sidebar the other way", () => {
    expect(edgeToward("sidebar", "ltr")).toBe("left");
    expect(edgeToward("sidebar", "rtl")).toBe("right");
  });
});

describe("badgePlacement", () => {
  it("puts a badge at the inline end of the top edge", () => {
    expect(badgePlacement("top", "end", "ltr")).toBe("top-right");
    expect(badgePlacement("top", "end", "rtl")).toBe("top-left");
    expect(badgePlacement("bottom", "start", "rtl")).toBe("bottom-right");
  });
});
