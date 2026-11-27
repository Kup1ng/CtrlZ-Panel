import {describe, expect, it} from "vitest";

import {drawnIndexes, needsMore, offsetsOf, windowRange, windowRangeOf} from "./virtualWindow.ts";

describe("windowRange", () => {
  it("holds the visible rows and the overscan, and never more", () => {
    const w = windowRange({scrollTop: 1000, viewport: 560, pitch: 56, count: 10_000, overscan: 6});
    // 1000 / 56 = 17.8 -> first 17; (1000 + 560) / 56 = 27.9 -> last 28.
    expect(w).toEqual({start: 11, end: 34});
    expect(w.end - w.start).toBeLessThan(100);
  });

  it("stays inside the list at both ends", () => {
    expect(windowRange({scrollTop: 0, viewport: 560, pitch: 56, count: 5})).toEqual({start: 0, end: 5});
    expect(windowRange({scrollTop: 99_999_999, viewport: 560, pitch: 56, count: 100, overscan: 6})).toEqual({start: 94, end: 100});
    expect(windowRange({scrollTop: -40, viewport: 100, pitch: 50, count: 20}).start).toBe(0);
  });

  it("is empty for an empty list or a pitch of zero", () => {
    expect(windowRange({scrollTop: 0, viewport: 500, pitch: 56, count: 0})).toEqual({start: 0, end: 0});
    expect(windowRange({scrollTop: 0, viewport: 500, pitch: 0, count: 10})).toEqual({start: 0, end: 0});
  });
});

describe("drawnIndexes", () => {
  it("adds the focused row when the window has moved past it", () => {
    expect(drawnIndexes({start: 10, end: 13}, 2, 100)).toEqual([2, 10, 11, 12]);
    expect(drawnIndexes({start: 10, end: 13}, 50, 100)).toEqual([10, 11, 12, 50]);
  });
  it("adds nothing for a focused row that is inside, absent or gone", () => {
    expect(drawnIndexes({start: 10, end: 13}, 11, 100)).toEqual([10, 11, 12]);
    expect(drawnIndexes({start: 10, end: 13}, null, 100)).toEqual([10, 11, 12]);
    expect(drawnIndexes({start: 10, end: 13}, 400, 100)).toEqual([10, 11, 12]);
  });
});

describe("needsMore", () => {
  it("asks for a page when the window nears the end of what is loaded", () => {
    expect(needsMore({start: 0, end: 70}, 100, true)).toBe(true);
    expect(needsMore({start: 0, end: 30}, 100, true)).toBe(false);
    expect(needsMore({start: 0, end: 100}, 100, false)).toBe(false);
  });
});

describe("offsetsOf and windowRangeOf (rows of different heights)", () => {
  it("places each row after the slot of the one before it and ends at the sum", () => {
    expect(offsetsOf(4, (i) => (i === 0 ? 52 : 92))).toEqual([0, 52, 144, 236, 328]);
    expect(offsetsOf(0, () => 10)).toEqual([0]);
  });

  it("gives the same window as one pitch when every slot is the same", () => {
    for (const [scrollTop, viewport, count] of [
      [1000, 560, 10_000],
      [0, 560, 5],
      [1568, 560, 100],
      [99_999_999, 560, 100],
    ] as const) {
      const offsets = offsetsOf(count, () => 56);
      const fixed = windowRange({scrollTop, viewport, pitch: 56, count, overscan: 0});
      const variable = windowRangeOf({scrollTop, viewport, offsets, overscan: 0});
      // Past the end a fixed window starts at the count; the variable one keeps the last row. Both end at the count.
      if (scrollTop > 56 * count) expect(variable.end).toBe(fixed.end);
      else expect(variable).toEqual(fixed);
    }
  });

  it("finds the rows under a viewport when a short header sits among tall rows", () => {
    // Header 52, then rows of 92: row 1 is 52 to 144, row 2 is 144 to 236.
    const offsets = offsetsOf(5, (i) => (i === 0 ? 52 : 92));
    expect(windowRangeOf({scrollTop: 60, viewport: 100, offsets, overscan: 0})).toEqual({start: 1, end: 3});
    expect(windowRangeOf({scrollTop: 0, viewport: 52, offsets, overscan: 0})).toEqual({start: 0, end: 1});
  });

  it("is empty for an empty list", () => {
    expect(windowRangeOf({scrollTop: 0, viewport: 500, offsets: [0]})).toEqual({start: 0, end: 0});
  });
});
