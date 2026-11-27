"use client";

import {useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode} from "react";

import {drawnIndexes, offsetsOf, windowRange, windowRangeOf, type Window} from "./virtualWindow.ts";

// A long list of rows of one height, drawn by window (FE 8.10, spec p2 10.6: the rules list of 10,000 rows). A `ListBox` in a `Virtualizer`
// is the right tool for a list of options, but its items are options and may not hold a switch, a check box and four buttons; a row of the
// Rules list does, so this places rows by their index itself and draws only the window. It is a plain `role="list"` of `role="listitem"`
// rows, each with its place in the whole list (`aria-posinset`, `aria-setsize`), so a screen reader hears "12 of 9,880". The size of the whole list
// is `setSize` (the loaded rows are only `count`): the caller gives the total it knows, or -1 while more pages may come and it does not know it, the
// value ARIA has for an unknown size.
//
// The scroll area is the list's own, with a height the caller gives, and it is focusable through the controls it holds. The row with the
// keyboard focus is always drawn, so Tab does not lose its place when the list scrolls under it. `onWindow` tells the screen which rows
// are drawn, to ask for the next page of the cursor.

/** `count` is the rows that are loaded (the window works on it); `setSize` is the size of the whole list for a screen reader, -1 when unknown. */
export type RowPlace = {style: CSSProperties; index: number; count: number; setSize: number};

export type VirtualRowsProps = {
  label: string;
  count: number;
  /** The size of the whole list when it is more than the loaded rows, or -1 when it is not known yet. Defaults to `count`. */
  setSize?: number;
  /** Distance from the top of one row to the top of the next, in px. The row itself is drawn a little shorter, which is the gap. */
  pitch: number;
  /**
   * The slot of one row, when rows are not all the height of `pitch` (a group header is smaller than a row). The caller keeps it stable
   * (`useCallback`): the places of all rows are worked out again when it changes. Without it every row has `pitch`.
   */
  pitchOf?: (index: number) => number;
  /** Classes for the scroll area: its height and its look. */
  className?: string;
  renderRow: (index: number, place: RowPlace) => ReactNode;
  onWindow?: (window: Window) => void;
  /** Rows kept on each side of the visible ones. */
  overscan?: number;
  /** Shown under the last row (a loading line while the next page comes). */
  footer?: ReactNode;
  /** Names the list that is shown (a search, a filter, a sort). When it changes the area goes back to the first row: another list has no use for the offset of the old one. */
  resetKey?: string;
  /**
   * The stable key of the row at an index. A list whose rows can move while pages arrive (grouped by what has been loaded so far) gives it,
   * and the row with the keyboard focus is then followed by its key and not by its place, so the focus stays on the same item. The row
   * element carries the same key in `data-key`.
   */
  keyOf?: (index: number) => string;
};

// Before the browser has measured the area (the server render, the first paint) the window assumes this many pixels.
const FIRST_VIEWPORT = 640;

export function VirtualRows({label, count, setSize = count, pitch, pitchOf, className, renderRow, onWindow, overscan = 3, footer, resetKey, keyOf}: VirtualRowsProps) {
  const area = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(FIRST_VIEWPORT);
  const [focusedAt, setFocusedAt] = useState<number | null>(null);
  const [focusedKey, setFocusedKey] = useState<string | null>(null);
  const frame = useRef<number | null>(null);

  useLayoutEffect(() => {
    const el = area.current;
    if (!el) return;
    setViewport(el.clientHeight || FIRST_VIEWPORT);
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => setViewport(el.clientHeight || FIRST_VIEWPORT));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // The same scroll area serves every list (so a row under the pointer or the keyboard keeps its place while a list loads), and so the
  // offset is put back by hand: without it a shorter list would show the clamped end of the offset of the last one.
  const lastReset = useRef(resetKey);
  useLayoutEffect(() => {
    if (lastReset.current === resetKey) return;
    lastReset.current = resetKey;
    if (area.current) area.current.scrollTop = 0;
    setScrollTop(0);
  }, [resetKey]);

  useEffect(
    () => () => {
      if (frame.current !== null) cancelAnimationFrame(frame.current);
    },
    [],
  );

  const onScroll = useCallback(() => {
    if (frame.current !== null) return;
    frame.current = requestAnimationFrame(() => {
      frame.current = null;
      setScrollTop(area.current?.scrollTop ?? 0);
    });
  }, []);

  const offsets = useMemo(() => (pitchOf ? offsetsOf(count, pitchOf) : null), [pitchOf, count]);
  const range = useMemo(
    () => (offsets ? windowRangeOf({scrollTop, viewport, offsets, overscan}) : windowRange({scrollTop, viewport, pitch, count, overscan})),
    [offsets, scrollTop, viewport, pitch, count, overscan],
  );
  const focused = useMemo(() => {
    if (!keyOf) return focusedAt;
    if (focusedKey === null) return null;
    for (let i = 0; i < count; i++) if (keyOf(i) === focusedKey) return i;
    return null;
  }, [keyOf, focusedKey, focusedAt, count]);
  const indexes = useMemo(() => drawnIndexes(range, focused, count), [range, focused, count]);

  const reported = useRef<Window | null>(null);
  useEffect(() => {
    if (reported.current?.start === range.start && reported.current.end === range.end) return;
    reported.current = range;
    onWindow?.(range);
  }, [range, onWindow]);

  return (
    <div ref={area} onScroll={onScroll} className={["virtual-rows overflow-y-auto overscroll-contain", className ?? ""].filter(Boolean).join(" ")}>
      <div
        role="list"
        aria-label={label}
        className="@container relative"
        style={{height: offsets ? offsets[count] : count * pitch}}
        onFocusCapture={(event) => {
          const row = (event.target as HTMLElement).closest<HTMLElement>("[data-index]");
          const index = row ? Number(row.dataset.index) : NaN;
          setFocusedAt(Number.isNaN(index) ? null : index);
          setFocusedKey(row?.dataset.key ?? null);
        }}
        onBlurCapture={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
            setFocusedAt(null);
            setFocusedKey(null);
          }
        }}
      >
        {indexes.map((index) => renderRow(index, {index, count, setSize, style: {position: "absolute", insetInline: 0, top: offsets ? offsets[index]! : index * pitch}}))}
      </div>
      {footer}
    </div>
  );
}
