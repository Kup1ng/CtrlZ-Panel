"use client";

import {Checkbox, Skeleton} from "@heroui/react";
import type {CSSProperties, KeyboardEventHandler, ReactNode} from "react";

import {ROW_FOCUS, RowMain} from "./RowMain.tsx";

// Spec 8.10, the low rows of the Rules list (WF "ردیف کم‌ارتفاع"): a leading mark, the domain, tags
// (the action label, the A and AAAA capsules), and a switch at the end. Height 50 with the
// `control-50` corner (20px).
//
// On hover or keyboard focus (`:focus-visible`, not `:focus-within`: a mouse click leaves focus on the
// row's button, and the swap must end when the pointer leaves, wp7-r1-2), `hoverActions` (Copy, Move, Edit,
// Delete) take the place of the tags; both sit in the same grid cell, so the row never changes size.
// The hidden actions are transparent and ignore the pointer, not `visibility: hidden`, so they stay in the
// accessibility tree: a screen reader's browse mode finds them without moving focus (wp7-r1-3). Touch has no
// hover: on a coarse pointer a selected row shows its actions, so a tap on the row (which selects it, WF)
// is the way to them. A row with no `selection` has no touch path of its own; its screen provides the
// header bar of WF. With `selection`
// the row shows a checkbox first (the selection mode that a click on a row opens in WF). The row's own
// action (`href` or `onPress`) is stretched over it; the switch, the checkbox and the hover actions
// are separate controls above it.

const ACTIONS = [
  "pointer-events-none relative z-10 col-start-1 row-start-1 flex items-center gap-1 opacity-0",
  // Below sm the hidden actions take no width from the name of the row (WF: rows are two lines on a phone) but stay in the accessibility tree: the
  // wrapper is 0 wide with its buttons overflowing it. A selected row, or one asking a question, gives them their width, and the name gives way.
  "max-sm:w-0 max-sm:justify-end max-sm:overflow-visible max-sm:group-data-selected:w-auto max-sm:group-data-pinned:w-auto",
  "group-hover:pointer-events-auto group-hover:opacity-100",
  "group-has-[:focus-visible]:pointer-events-auto group-has-[:focus-visible]:opacity-100",
  "group-data-pinned:pointer-events-auto group-data-pinned:opacity-100",
  "pointer-coarse:group-data-selected:pointer-events-auto pointer-coarse:group-data-selected:opacity-100",
  "max-sm:group-data-selected:pointer-events-auto max-sm:group-data-selected:opacity-100",
].join(" ");

export type DenseRowProps = {
  leading?: ReactNode;
  /** Usually a domain in `<Tech>`. */
  title: ReactNode;
  tags?: ReactNode;
  hoverActions?: ReactNode;
  /** A `Switch`, at the end (design taste). */
  trailing?: ReactNode;
  selection?: {isSelected: boolean; onChange: (selected: boolean) => void; label: string};
  href?: string;
  onPress?: () => void;
  className?: string;
  /**
   * The small view of a list (spec p2 9.6, T-196): 10 steps high with the `row-counter` corner (the radius table's 10-step row) instead of 50 with `control-50`. The row
   * holds one line, so a caller that has a second line leaves it out.
   */
  compact?: boolean;
  /**
   * The hover actions stay in place of the tags without the pointer or the focus: a row whose actions ask a question (the delete confirmed
   * in place) must not lose it when the pointer leaves.
   */
  actionsPinned?: boolean;
  /** A key pressed while the focus is inside the row (it bubbles from the row's own controls). */
  onKeyDown?: KeyboardEventHandler<HTMLDivElement>;
  /** Position inside a windowed list: the style that places the row and its place in the whole list for a screen reader. */
  place?: {style: CSSProperties; index: number; count: number; setSize?: number};
};

export function DenseRow({leading, title, tags, hoverActions, trailing, selection, href, onPress, className, compact = false, actionsPinned = false, onKeyDown, place}: DenseRowProps) {
  const interactive = Boolean(href || onPress);
  return (
    // The row has no key of its own: `onKeyDown` only hears the keys that bubble from the controls it holds (Escape of an in-row question).
    // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions
    <div
      role="listitem"
      data-selected={selection?.isSelected || undefined}
      data-pinned={actionsPinned || undefined}
      data-index={place?.index}
      aria-posinset={place ? place.index + 1 : undefined}
      aria-setsize={place ? (place.setSize ?? place.count) : undefined}
      style={place?.style}
      onKeyDown={onKeyDown}
      className={[
        compact ? "row-counter h-10" : "control-50",
        "group relative flex w-full items-center gap-3 px-3",
        selection?.isSelected ? "bg-accent/10" : "bg-surface",
        interactive ? "cursor-[var(--cursor-interactive)]" : "",
        interactive ? (selection?.isSelected ? "hover:bg-accent/15" : "hover:bg-default") : "",
        ROW_FOCUS,
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {selection ? (
        <Checkbox aria-label={selection.label} isSelected={selection.isSelected} onChange={selection.onChange} className="relative z-10 shrink-0">
          <Checkbox.Content>
            <Checkbox.Control>
              <Checkbox.Indicator />
            </Checkbox.Control>
          </Checkbox.Content>
        </Checkbox>
      ) : null}
      {leading ? <span className="text-muted grid size-6 shrink-0 place-items-center text-lg">{leading}</span> : null}
      <RowMain href={href} onPress={onPress} className="min-w-0 flex-1 truncate text-sm">
        {title}
      </RowMain>
      {tags || hoverActions ? (
        <div className="grid shrink-0 items-center justify-items-end">
          {tags ? (
            <div
              className={[
                "col-start-1 row-start-1 flex items-center gap-2",
                hoverActions
                  ? "group-hover:invisible group-has-[:focus-visible]:invisible group-data-pinned:invisible pointer-coarse:group-data-selected:invisible max-sm:group-data-selected:invisible"
                  : "",
              ]
                .filter(Boolean)
                .join(" ")}
            >
              {tags}
            </div>
          ) : null}
          {hoverActions ? (
            <div className={ACTIONS}>
              {hoverActions}
            </div>
          ) : null}
        </div>
      ) : null}
      {trailing ? <div className="relative z-10 flex shrink-0 items-center">{trailing}</div> : null}
    </div>
  );
}

/** Loading shape of a `DenseRow`. */
export function DenseRowSkeleton({className}: {className?: string}) {
  return <Skeleton className={["control-50 w-full", className ?? ""].filter(Boolean).join(" ")} />;
}
