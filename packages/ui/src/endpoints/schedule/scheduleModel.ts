// The weekly Schedule of an Endpoint (spec p3 3.8, 10; Plan T-252 to T-254), without React so a plain test holds the rules.
//
// The server's windows are `{start, end}` in minutes of a week that begins on Sunday 00:00 (shared/schedule), multiples of 30, at least 30
// long, never overlapping, at most 64. The screen works on the same week as 336 cells of 30 minutes, each empty or holding a PAIR of profiles.
// That one shape makes every operation of the screen total: painting a range, copying a day, clearing, and "no overlap" (a cell holds one
// pair, so two windows cannot share one). A window is a RUN: consecutive cells with the same pair. Two windows that abut with the same pair
// become one run on the way in, which serves the same stack, so the server's set and the screen's may differ only by that merge.

export const CELL_MINUTES = 30;
export const CELLS_PER_DAY = 48;
export const DAYS = 7;
export const CELLS = CELLS_PER_DAY * DAYS;
export const MAX_WINDOWS = 64;

/** `profile|profile2` (the second may be empty), or null for a cell with no window. */
export type Slot = string | null;
export type Pair = {profile_id: string; profile2_id?: string | undefined};
export type Window = {start: number; end: number; profile_id: string; profile2_id?: string};
export type Run = {from: number; to: number; slot: string};

export const slotOf = (pair: Pair): string => `${pair.profile_id}|${pair.profile2_id ?? ""}`;
export function pairOf(slot: string): Pair {
  const [profile_id = "", second = ""] = slot.split("|");
  return second ? {profile_id, profile2_id: second} : {profile_id};
}

export const emptyWeek = (): Slot[] => Array.from({length: CELLS}, () => null);

/** The cells of a set of windows. A window that is not on the grid (the server never sends one) is cut to the cells it covers whole. */
export function cellsOf(windows: readonly Pick<Window, "start" | "end" | "profile_id" | "profile2_id">[]): Slot[] {
  const cells = emptyWeek();
  for (const w of windows) {
    const first = Math.max(0, Math.ceil(w.start / CELL_MINUTES));
    const last = Math.min(CELLS, Math.floor(w.end / CELL_MINUTES));
    for (let i = first; i < last; i++) cells[i] = slotOf(w);
  }
  return cells;
}

/** The runs of a week, in order. */
export function runsOf(cells: readonly Slot[]): Run[] {
  const runs: Run[] = [];
  let i = 0;
  while (i < cells.length) {
    const slot = cells[i];
    if (slot === null || slot === undefined) {
      i++;
      continue;
    }
    let j = i + 1;
    while (j < cells.length && cells[j] === slot) j++;
    runs.push({from: i, to: j, slot});
    i = j;
  }
  return runs;
}

/** The windows to send: one for each run. */
export const windowsOf = (cells: readonly Slot[]): Window[] =>
  runsOf(cells).map((r) => ({start: r.from * CELL_MINUTES, end: r.to * CELL_MINUTES, ...pairOf(r.slot)}));

/** The run that holds a cell, or null. */
export function runAt(cells: readonly Slot[], index: number): Run | null {
  const slot = cells[index];
  if (slot === null || slot === undefined) return null;
  let from = index;
  let to = index + 1;
  while (from > 0 && cells[from - 1] === slot) from--;
  while (to < cells.length && cells[to] === slot) to++;
  return {from, to, slot};
}

export const dayOf = (cell: number): number => Math.floor(cell / CELLS_PER_DAY);
export const cellOfDay = (day: number, row: number): number => day * CELLS_PER_DAY + row;

/** The order the days are drawn in: Saturday first in Persian (the week of the people who read it), Sunday first otherwise. Days count from Sunday = 0. */
export const dayOrder = (weekStart: number): number[] => Array.from({length: DAYS}, (_, i) => (weekStart + i) % DAYS);

/** The cells `[a, b]` (any order) of ONE day: a range never crosses midnight when it is drawn with the pointer or the keys. */
export function sameDayRange(a: number, b: number): {from: number; to: number} | null {
  if (dayOf(a) !== dayOf(b)) return null;
  return {from: Math.min(a, b), to: Math.max(a, b) + 1};
}

/** Every cell of `[from, to)` is empty. */
export function isFree(cells: readonly Slot[], from: number, to: number): boolean {
  for (let i = from; i < to; i++) if (cells[i] !== null) return false;
  return true;
}

/** `slot` in `[from, to)`. Returns null when a cell there is not empty (a window never overwrites another). */
export function paint(cells: readonly Slot[], from: number, to: number, slot: string): Slot[] | null {
  if (from < 0 || to > cells.length || to <= from || !isFree(cells, from, to)) return null;
  const next = [...cells];
  for (let i = from; i < to; i++) next[i] = slot;
  return next;
}

/** The run `run` becomes `[from, to)` with `slot`. The new range may overlap only the run itself. Returns null when it would cover another window. */
export function reshape(cells: readonly Slot[], run: Run, from: number, to: number, slot: string): Slot[] | null {
  if (from < 0 || to > cells.length || to <= from) return null;
  const without = [...cells];
  for (let i = run.from; i < run.to; i++) without[i] = null;
  return paint(without, from, to, slot);
}

export function removeRun(cells: readonly Slot[], run: Run): Slot[] {
  const next = [...cells];
  for (let i = run.from; i < run.to; i++) next[i] = null;
  return next;
}

/** Gives every cell of a run another pair. */
export function repair(cells: readonly Slot[], run: Run, slot: string): Slot[] {
  const next = [...cells];
  for (let i = run.from; i < run.to; i++) next[i] = slot;
  return next;
}

/** The cells of one day, as they are now. */
export const dayCells = (cells: readonly Slot[], day: number): Slot[] => cells.slice(cellOfDay(day, 0), cellOfDay(day + 1, 0));

/**
 * Copy day: what `from` holds, cell by cell, replaces what each of `to` holds. A window that crosses midnight is copied as it is cut by the
 * day: its part in the day moves, the rest stays where it is. The days copied onto lose their cells first, so the copy is the day, whole.
 */
export function copyDay(cells: readonly Slot[], from: number, to: readonly number[]): Slot[] {
  const source = dayCells(cells, from);
  const next = [...cells];
  for (const day of to) {
    if (day === from) continue;
    for (let row = 0; row < CELLS_PER_DAY; row++) next[cellOfDay(day, row)] = source[row] ?? null;
  }
  return next;
}

export function clearDay(cells: readonly Slot[], day: number): Slot[] {
  const next = [...cells];
  for (let row = 0; row < CELLS_PER_DAY; row++) next[cellOfDay(day, row)] = null;
  return next;
}

export const sameWeek = (a: readonly Slot[], b: readonly Slot[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/** More windows than the server takes (64): a PUT would be 422 `exceeded` on `/windows`. */
export const tooManyWindows = (cells: readonly Slot[]): boolean => runsOf(cells).length > MAX_WINDOWS;

/** A minute of the week as `{day, minute}`; `end` of the week (10,080) is the end of day 6. */
export const minuteParts = (cell: number): {day: number; row: number} => ({day: dayOf(cell), row: cell % CELLS_PER_DAY});

/** The pair of the first window, which is what a new one starts from when the person has not chosen: the first profile that is not the Endpoint's own. */
export function defaultPair(profileIds: readonly string[], base: {profile_id: string}): Pair {
  const other = profileIds.find((id) => id !== base.profile_id);
  return {profile_id: other ?? base.profile_id};
}
