"use client";

import {useCallback, useEffect, useMemo, useRef, useState} from "react";

import {useDirectionalKeys} from "../../hooks/useDirectionalKeys.ts";
import {CELLS_PER_DAY, cellOfDay, dayOf, isFree, runAt, sameDayRange, type Run, type Slot} from "./scheduleModel.ts";

// The week of a Schedule (spec p3 10, T-252, T-488): days are columns and half hours are rows, like a calendar, so the same grid reads at 375
// pixels (seven columns of about 40) and at 1280. In Persian the first day is at the right and time runs down; nothing in the code says
// "left" or "right": the columns are in reading order and the browser mirrors them.
//
// Three ways to make a window, one result (`onCreate(from, to)`, a range of cells in ONE day):
//   mouse and pen   press on a free cell, drag down or up, release. A press and a release on the same cell leaves the start set, and the next
//                   press on a cell of that day ends the range (so a 30-minute window is two clicks on one cell).
//   touch           tap the start, then tap the end. A drag would scroll the page, so touch never drags.
//   keyboard        arrows move (Left and Right follow what is drawn, so they swap in Persian), Enter or Space sets the start and then the end,
//                   Escape drops the start, Delete removes the window under the cell.
// A press on a cell that holds a window selects that window, whatever the way. The grid is one tab stop (roving tabindex), as a grid is.

export type GridLabels = {
  grid: string;
  /** Short day names by day number (Sunday = 0), the names read by a screen reader, and the time of a row. */
  dayShort: (day: number) => string;
  dayLong: (day: number) => string;
  time: (row: number) => string;
  hour: (row: number) => string;
  /** The name of a window's pair of profiles. */
  nameOf: (slot: string) => string;
  cell: (args: {day: string; time: string; name: string | null; selected: boolean; anchor: boolean}) => string;
  announceStart: (args: {day: string; time: string}) => string;
  announceCancelled: string;
  blocked: string;
};

export type ScheduleGridProps = {
  cells: readonly Slot[];
  order: readonly number[];
  labels: GridLabels;
  selected: Run | null;
  /** 0, 1 or 2: how a window is tinted. Words carry the profile; the tint only tells two neighbours apart. */
  toneOf: (slot: string) => number;
  onSelect: (run: Run | null) => void;
  onCreate: (from: number, to: number) => void;
  onRemove: (run: Run) => void;
  isDisabled?: boolean;
};

const TONES = ["bg-accent/15", "bg-success/15", "bg-warning/15"] as const;

export function ScheduleGrid({cells, order, labels, selected, toneOf, onSelect, onCreate, onRemove, isDisabled = false}: ScheduleGridProps) {
  const [anchor, setAnchor] = useState<number | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [focusCell, setFocusCell] = useState(() => cellOfDay(order[0] ?? 0, 18));
  const [note, setNote] = useState("");
  const dragging = useRef(false);
  const pointerType = useRef<string>("mouse");
  const root = useRef<HTMLDivElement>(null);
  const keys = useDirectionalKeys();

  const preview = useMemo(() => {
    if (anchor === null) return null;
    return sameDayRange(anchor, hover ?? anchor);
  }, [anchor, hover]);

  // The week changed under an open start (a copy, a clear, a reload): the start is dropped, since the cell may now hold a window.
  const [seen, setSeen] = useState(cells);
  if (seen !== cells) {
    setSeen(cells);
    if (anchor !== null && cells[anchor] !== null) {
      setAnchor(null);
      setHover(null);
    }
  }

  const finish = useCallback(
    (to: number) => {
      if (anchor === null) return;
      const range = sameDayRange(anchor, to);
      setAnchor(null);
      setHover(null);
      if (!range) return;
      if (!isFree(cells, range.from, range.to)) {
        setNote(labels.blocked);
        return;
      }
      setNote("");
      onCreate(range.from, range.to);
    },
    [anchor, cells, labels.blocked, onCreate],
  );

  const press = useCallback(
    (cell: number) => {
      setFocusCell(cell);
      const run = runAt(cells, cell);
      if (run) {
        setAnchor(null);
        setHover(null);
        onSelect(run);
        return;
      }
      if (anchor !== null && dayOf(anchor) === dayOf(cell)) return finish(cell);
      onSelect(null);
      setAnchor(cell);
      setHover(cell);
      setNote(labels.announceStart({day: labels.dayLong(dayOf(cell)), time: labels.time(cell % CELLS_PER_DAY)}));
    },
    [anchor, cells, finish, labels, onSelect],
  );

  const cellFromPoint = (x: number, y: number): number | null => {
    const el = document.elementFromPoint(x, y)?.closest<HTMLElement>("[data-cell]");
    const n = el ? Number(el.dataset.cell) : NaN;
    return Number.isNaN(n) ? null : n;
  };

  const move = (cell: number, event: {key: string}): number | null => {
    const key = event.key;
    const day = dayOf(cell);
    const row = cell % CELLS_PER_DAY;
    const column = order.indexOf(day);
    // The columns are in reading order, so "next" is the next day whichever side of the screen that is.
    const visual = keys.isNext(event) ? 1 : keys.isPrev(event) ? -1 : 0;
    switch (key) {
      case "ArrowUp":
        return row > 0 ? cell - 1 : null;
      case "ArrowDown":
        return row < CELLS_PER_DAY - 1 ? cell + 1 : null;
      case "PageUp":
        return cellOfDay(day, Math.max(0, row - 8));
      case "PageDown":
        return cellOfDay(day, Math.min(CELLS_PER_DAY - 1, row + 8));
      case "Home":
        return cellOfDay(day, 0);
      case "End":
        return cellOfDay(day, CELLS_PER_DAY - 1);
      default: {
        if (visual === 0) return null;
        const next = order[column + visual];
        return next === undefined ? null : cellOfDay(next, row);
      }
    }
  };

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>, cell: number) {
    if (isDisabled) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      press(cell);
      return;
    }
    if (event.key === "Escape" && anchor !== null) {
      event.preventDefault();
      event.stopPropagation();
      setAnchor(null);
      setHover(null);
      setNote(labels.announceCancelled);
      return;
    }
    if ((event.key === "Delete" || event.key === "Backspace") && cells[cell] !== null) {
      event.preventDefault();
      const run = runAt(cells, cell);
      if (run) onRemove(run);
      return;
    }
    const next = move(cell, event);
    if (next === null) {
      if (event.key === "ArrowUp" || event.key === "ArrowDown" || keys.isNext(event) || keys.isPrev(event)) event.preventDefault();
      return;
    }
    event.preventDefault();
    setFocusCell(next);
    if (anchor !== null && dayOf(next) === dayOf(anchor)) setHover(next);
    root.current?.querySelector<HTMLElement>(`[data-cell="${next}"]`)?.focus();
  }

  // The pointer moves over the whole grid while a drag is on, whatever the cell under it was when it began.
  useEffect(() => {
    const onMove = (event: PointerEvent) => {
      if (!dragging.current) return;
      const cell = cellFromPoint(event.clientX, event.clientY);
      if (cell !== null && anchor !== null && dayOf(cell) === dayOf(anchor)) setHover(cell);
    };
    const onUp = (event: PointerEvent) => {
      if (!dragging.current) return;
      dragging.current = false;
      const cell = cellFromPoint(event.clientX, event.clientY);
      if (cell !== null && anchor !== null && cell !== anchor && dayOf(cell) === dayOf(anchor)) finish(cell);
      else if (cell !== null && anchor !== null && cell !== anchor) setHover(anchor);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
  }, [anchor, finish]);

  return (
    <div className="schedule-grid-wrap">
      <p role="status" className="sr-only">
        {note}
      </p>
      <div
        ref={root}
        role="grid"
        aria-label={labels.grid}
        aria-rowcount={CELLS_PER_DAY + 1}
        aria-colcount={order.length + 1}
        aria-disabled={isDisabled || undefined}
        className="schedule-grid grid select-none"
        style={{gridTemplateColumns: "3rem repeat(7, minmax(0, 1fr))"}}
      >
        <div role="row" className="contents">
          <div role="columnheader" className="bg-surface sticky top-0 z-10 h-9" aria-label={labels.grid} />
          {order.map((day) => (
            <div key={day} role="columnheader" className="bg-surface text-foreground sticky top-0 z-10 flex h-9 items-center justify-center truncate px-0.5 text-xs font-medium">
              <span className="sm:hidden">{labels.dayShort(day)}</span>
              <span className="hidden sm:inline">{labels.dayLong(day)}</span>
            </div>
          ))}
        </div>
        {Array.from({length: CELLS_PER_DAY}, (_, row) => (
          <div key={row} role="row" className="contents">
            <div role="rowheader" className="text-muted flex h-6 items-start justify-end pe-1.5 text-[0.6875rem] leading-none tabular-nums" aria-label={labels.time(row)}>
              {row % 2 === 0 ? <span className={row === 0 ? "" : "-translate-y-1/2"}>{labels.hour(row)}</span> : null}
            </div>
            {order.map((day) => {
              const cell = cellOfDay(day, row);
              const slot = cells[cell] ?? null;
              const run = slot === null ? null : runAt(cells, cell);
              const inRun = run !== null && selected !== null && run.from === selected.from && run.to === selected.to;
              const first = run !== null && (cell === run.from || row === 0);
              const lastOfRun = run !== null && (cell === run.to - 1 || row === CELLS_PER_DAY - 1);
              const inPreview = preview !== null && cell >= preview.from && cell < preview.to;
              const isAnchor = anchor === cell;
              const name = slot === null ? null : labels.nameOf(slot);
              const tabbable = cell === focusCell;
              return (
                <div
                  key={day}
                  role="gridcell"
                  data-cell={cell}
                  data-selected={inRun || undefined}
                  data-preview={inPreview || undefined}
                  tabIndex={isDisabled ? -1 : tabbable ? 0 : -1}
                  aria-label={labels.cell({day: labels.dayLong(day), time: labels.time(row), name, selected: inRun, anchor: isAnchor})}
                  aria-selected={inRun || undefined}
                  className={[
                    "schedule-cell relative h-6 min-w-0 cursor-[var(--cursor-interactive)] border-separator outline-none",
                    row % 2 === 0 ? "border-t" : "border-t border-t-transparent",
                    "border-s",
                    slot !== null ? TONES[toneOf(slot) % TONES.length] : "",
                    first ? "rounded-t-(--radius)" : "",
                    lastOfRun ? "rounded-b-(--radius)" : "",
                    inRun ? "outline-2 -outline-offset-2 outline-accent" : "focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus",
                    inPreview ? "bg-accent/30" : "",
                    isAnchor ? "outline-2 -outline-offset-2 outline-dashed outline-accent" : "",
                  ]
                    .filter(Boolean)
                    .join(" ")}
                  onFocus={() => setFocusCell(cell)}
                  onKeyDown={(event) => onKeyDown(event, cell)}
                  onPointerDown={(event) => {
                    pointerType.current = event.pointerType;
                    if (isDisabled || event.pointerType === "touch" || event.button !== 0) return;
                    event.preventDefault();
                    const hasRun = cells[cell] !== null;
                    const startsDrag = !hasRun && (anchor === null || dayOf(anchor) !== dayOf(cell));
                    press(cell);
                    if (startsDrag) dragging.current = true;
                    (event.currentTarget as HTMLElement).focus({preventScroll: true});
                  }}
                  onClick={() => {
                    // Touch has no pointerdown branch above: a tap is a click.
                    if (isDisabled || pointerType.current !== "touch") return;
                    press(cell);
                  }}
                >
                  {slot !== null && first ? (
                    <span aria-hidden="true" className="text-foreground pointer-events-none absolute inset-x-0.5 top-0.5 truncate text-[0.6875rem] leading-4">
                      {name}
                    </span>
                  ) : null}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}
