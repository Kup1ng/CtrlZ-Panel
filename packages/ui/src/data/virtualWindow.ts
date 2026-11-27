// The window of a long list of rows of one fixed pitch (spec p2 10.6, FE 8.10): which rows are in the page for a scroll position.
//
// Rows are placed by their index (`top = index * pitch`), so a row that is not in the window costs nothing, and the DOM of a list of
// 10,000 rules holds the visible rows and a few more on each side. A row that has the keyboard focus stays in the window wherever the
// scroll is, so Tab does not lose its place when the list scrolls under it.

export type WindowInput = {
  scrollTop: number;
  viewport: number;
  pitch: number;
  count: number;
  /** Rows kept on each side of the visible ones, so a Tab to the next row has a row to land on. */
  overscan?: number;
};

export type Window = {start: number; end: number};

/** The rows `[start, end)` that are in the window. Never more rows than the viewport holds plus the overscan on both sides. */
export function windowRange({scrollTop, viewport, pitch, count, overscan = 3}: WindowInput): Window {
  if (count <= 0 || pitch <= 0) return {start: 0, end: 0};
  const first = Math.floor(Math.max(0, scrollTop) / pitch);
  const last = Math.ceil((Math.max(0, scrollTop) + Math.max(0, viewport)) / pitch);
  // A scroll position past the end (a list that shrank under the scroll) is clamped, so `start` never passes `end`.
  return {start: Math.max(0, Math.min(first, count) - overscan), end: Math.min(count, last + overscan)};
}

/**
 * The top of every row of a list whose rows have different heights (a header takes less than a client), and the height of the whole list as the
 * last entry: `offsets[i]` is where row i starts, `offsets[count]` is where the list ends. `heightOf` is the slot of a row, its gap included.
 */
export function offsetsOf(count: number, heightOf: (index: number) => number): number[] {
  const offsets = new Array<number>(count + 1);
  offsets[0] = 0;
  for (let i = 0; i < count; i++) offsets[i + 1] = offsets[i]! + heightOf(i);
  return offsets;
}

/** The first index whose offset is more than `y` (the row under y is the one before it); `offsets.length - 1` when none is. */
function rowAfter(offsets: number[], y: number): number {
  let low = 0;
  let high = offsets.length - 1;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (offsets[mid]! > y) high = mid;
    else low = mid + 1;
  }
  return low;
}

/** `windowRange` for rows of different heights, placed by `offsetsOf`. The same rows come out as for one pitch when every height is the same. */
export function windowRangeOf({scrollTop, viewport, offsets, overscan = 3}: {scrollTop: number; viewport: number; offsets: number[]; overscan?: number}): Window {
  const count = offsets.length - 1;
  if (count <= 0) return {start: 0, end: 0};
  const top = Math.max(0, scrollTop);
  const first = Math.min(count, Math.max(0, rowAfter(offsets, top) - 1));
  // The row that holds the bottom edge is the last one drawn: a row that starts exactly at the edge is not.
  let last = rowAfter(offsets, top + Math.max(0, viewport) - 1);
  last = Math.min(count, Math.max(first, last));
  return {start: Math.max(0, first - overscan), end: Math.min(count, last + overscan)};
}

/** The indexes to draw: the window and, when it lies outside it, the row that holds the focus. Ascending. */
export function drawnIndexes(window: Window, focused: number | null, count: number): number[] {
  const out: number[] = [];
  for (let i = window.start; i < window.end; i++) out.push(i);
  if (focused !== null && focused >= 0 && focused < count && (focused < window.start || focused >= window.end)) {
    return focused < window.start ? [focused, ...out] : [...out, focused];
  }
  return out;
}

/** The list should ask for its next page: the window comes within `margin` rows of the end of what is loaded. */
export function needsMore(window: Window, loaded: number, hasNext: boolean, margin = 40): boolean {
  return hasNext && window.end >= loaded - margin;
}
