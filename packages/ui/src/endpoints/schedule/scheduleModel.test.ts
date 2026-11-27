import {describe, expect, it} from "vitest";

import {
  CELLS,
  CELLS_PER_DAY,
  cellsOf,
  clearDay,
  copyDay,
  dayOrder,
  defaultPair,
  emptyWeek,
  isFree,
  MAX_WINDOWS,
  paint,
  pairOf,
  removeRun,
  reshape,
  runAt,
  runsOf,
  sameDayRange,
  slotOf,
  tooManyWindows,
  windowsOf,
} from "./scheduleModel.ts";

const A = slotOf({profile_id: "a"});
const B = slotOf({profile_id: "b", profile2_id: "c"});

describe("schedule cells (T-252, T-253)", () => {
  it("round-trips windows on the 30-minute grid", () => {
    const windows = [
      {start: 540, end: 1020, profile_id: "a"},
      {start: 1440 + 60, end: 1440 + 120, profile_id: "b", profile2_id: "c"},
    ];
    const cells = cellsOf(windows);
    expect(windowsOf(cells)).toEqual(windows);
    expect(cells.filter((c) => c !== null)).toHaveLength(16 + 2);
  });

  it("merges two abutting windows that hold the same pair and keeps different pairs apart", () => {
    const cells = cellsOf([
      {start: 0, end: 60, profile_id: "a"},
      {start: 60, end: 120, profile_id: "a"},
      {start: 120, end: 180, profile_id: "b"},
    ]);
    expect(runsOf(cells)).toEqual([
      {from: 0, to: 4, slot: A},
      {from: 4, to: 6, slot: slotOf({profile_id: "b"})},
    ]);
  });

  it("a window may end at the end of the week", () => {
    const cells = cellsOf([{start: 10050, end: 10080, profile_id: "a"}]);
    expect(runAt(cells, CELLS - 1)).toEqual({from: CELLS - 1, to: CELLS, slot: A});
  });

  it("paints only free cells: a window never overwrites another (T-253 no overlap)", () => {
    const cells = paint(emptyWeek(), 10, 14, A)!;
    expect(paint(cells, 12, 16, B)).toBeNull();
    expect(paint(cells, 14, 16, B)).not.toBeNull();
    expect(isFree(cells, 0, 10)).toBe(true);
    expect(paint(cells, 5, 5, B)).toBeNull();
    expect(paint(cells, -1, 2, B)).toBeNull();
    expect(paint(cells, CELLS - 1, CELLS + 1, B)).toBeNull();
  });

  it("reshapes a run over its own cells but not over another window", () => {
    const cells = paint(paint(emptyWeek(), 10, 14, A)!, 20, 22, B)!;
    const run = runAt(cells, 11)!;
    expect(windowsOf(reshape(cells, run, 8, 16, A)!).map((w) => [w.start, w.end])).toEqual([[240, 480], [600, 660]]);
    expect(reshape(cells, run, 10, 21, A)).toBeNull();
    expect(removeRun(cells, run).filter((c) => c === A)).toHaveLength(0);
  });

  it("a pointer range stays in one day", () => {
    expect(sameDayRange(5, 9)).toEqual({from: 5, to: 10});
    expect(sameDayRange(9, 5)).toEqual({from: 5, to: 10});
    expect(sameDayRange(CELLS_PER_DAY - 1, CELLS_PER_DAY)).toBeNull();
  });

  it("copy day replaces the days it lands on and leaves the source and the others alone", () => {
    let cells = paint(emptyWeek(), 18, 34, A)!;
    cells = paint(cells, CELLS_PER_DAY * 2 + 4, CELLS_PER_DAY * 2 + 6, B)!;
    const next = copyDay(cells, 0, [1, 2]);
    expect(next.slice(0, CELLS_PER_DAY)).toEqual(cells.slice(0, CELLS_PER_DAY));
    expect(next.slice(CELLS_PER_DAY, CELLS_PER_DAY * 2)).toEqual(cells.slice(0, CELLS_PER_DAY));
    expect(next.slice(CELLS_PER_DAY * 2, CELLS_PER_DAY * 3)).toEqual(cells.slice(0, CELLS_PER_DAY));
    expect(next.slice(CELLS_PER_DAY * 3)).toEqual(cells.slice(CELLS_PER_DAY * 3));
    expect(copyDay(cells, 0, [0])).toEqual(cells);
  });

  it("clears one day", () => {
    const cells = paint(paint(emptyWeek(), 0, 3, A)!, CELLS_PER_DAY, CELLS_PER_DAY + 3, A)!;
    expect(runsOf(clearDay(cells, 0))).toEqual([{from: CELLS_PER_DAY, to: CELLS_PER_DAY + 3, slot: A}]);
  });

  it("counts the 64-window cap by runs", () => {
    let cells = emptyWeek();
    for (let i = 0; i < MAX_WINDOWS; i++) cells = paint(cells, i * 2, i * 2 + 1, A)!;
    expect(tooManyWindows(cells)).toBe(false);
    expect(tooManyWindows(paint(cells, 200, 201, A)!)).toBe(true);
  });

  it("orders the week from Saturday in Persian and from Sunday otherwise", () => {
    expect(dayOrder(6)).toEqual([6, 0, 1, 2, 3, 4, 5]);
    expect(dayOrder(0)).toEqual([0, 1, 2, 3, 4, 5, 6]);
  });

  it("starts a new window on a profile other than the Endpoint's own, when there is one", () => {
    expect(defaultPair(["a", "b"], {profile_id: "a"})).toEqual({profile_id: "b"});
    expect(defaultPair(["a"], {profile_id: "a"})).toEqual({profile_id: "a"});
    expect(pairOf(B)).toEqual({profile_id: "b", profile2_id: "c"});
  });
});
