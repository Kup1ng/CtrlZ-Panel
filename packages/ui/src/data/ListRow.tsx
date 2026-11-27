"use client";

import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Skeleton} from "@heroui/react";
import type {ReactNode} from "react";

import {ROW_FOCUS, RowMain} from "./RowMain.tsx";

// Spec 8.10 (T-487). The full-width row of a list: Profiles, and later the other lists that WF draws
// with a leading icon, a name, a sub-line, a group of counters and a chevron.
//
// At least 75 high, in the design scale, with the `control-75` corner (30px, the cap: spec 6, D16). When the LIST is wide enough for one
// line (a container of 42rem and more) the row is one line, and it is a minimum and not a fixed height: a list a little over that width
// (a 1024px window) holds the Endpoint line, a button and two chips with little to spare, and a fixed 75 let a wrapped line spill out of
// the row (S1-r3-4). Narrower, the row is two lines (T-115): icon, name and chevron first, the counters under them, and it grows to fit
// instead of squeezing. The test is the width of the list and not of the window, since the sidebar takes 280px of a 768px window
// and a one-line row had no room left for its name (P2 screens, S1).
//
// One main action for the whole row (`href` or `onPress`, as a stretched link, see RowMain);
// `counters` and `trailing` are their own controls and keep working. `isHighlighted` is the "just
// created" row at the top of the list. A row with no action is information only and does not react
// to the pointer.

export type ListRowProps = {
  /** A control before the icon (the box of a selection mode). It is inside the listitem, so a list of rows owns nothing but listitems. */
  leading?: ReactNode;
  /** An `Icon`, a `ServiceLogo`, or anything about 20px. Decorative: the name carries the meaning. */
  icon?: ReactNode;
  title: ReactNode;
  /** One line under the title, for example the Endpoint link. Truncates. */
  subtitle?: ReactNode;
  /** `RowCounters`, or any compact group. Goes under the title below md. */
  counters?: ReactNode;
  /** A control at the end (a switch, a menu button). Not covered by the row's action. */
  trailing?: ReactNode;
  href?: string;
  onPress?: () => void;
  isHighlighted?: boolean;
  className?: string;
  /**
   * Keep the two-line layout until the list is wider (a container of 56rem, not 42rem). A row whose end holds a lot (chips, counters and three
   * buttons: an Endpoint) has no room for its name on one line in a 768px window, where the sidebar takes a third of the width.
   */
  roomy?: boolean;
  /**
   * For a row whose name and sub-line the person must be able to read on a phone (an Endpoint: its profile link is in the sub-line) and
   * whose end holds buttons. Below the width where the row is one line, the sub-line wraps instead of being cut, and `trailing` takes its
   * own line under the counters, so the buttons do not take the width the name needs.
   */
  stacked?: boolean;
};

export function ListRow({leading, icon, title, subtitle, counters, trailing, href, onPress, isHighlighted = false, className, roomy = false, stacked = false}: ListRowProps) {
  const interactive = Boolean(href || onPress);
  return (
    <div
      role="listitem"
      data-highlighted={isHighlighted || undefined}
      className={[
        "control-75 relative flex h-auto min-h-control-75 w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2",
        roomy ? "@4xl:flex-nowrap" : "@2xl:flex-nowrap",
        isHighlighted ? "bg-accent/10" : "bg-surface",
        interactive ? "cursor-[var(--cursor-interactive)]" : "",
        interactive ? (isHighlighted ? "hover:bg-accent/15" : "hover:bg-default") : "",
        ROW_FOCUS,
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {leading ? <div className="relative z-10 flex shrink-0 items-center">{leading}</div> : null}
      {icon ? (
        <span
          aria-hidden="true"
          className="tile-11 bg-default text-foreground grid size-11 shrink-0 place-items-center text-xl"
        >
          {icon}
        </span>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <RowMain href={href} onPress={onPress} className="truncate text-sm font-medium">
          {title}
        </RowMain>
        {subtitle ? <span className={["text-muted text-xs", stacked ? (roomy ? "@4xl:truncate" : "@2xl:truncate") : "truncate"].join(" ")}>{subtitle}</span> : null}
      </div>
      {counters ? (
        <div
          className={["relative z-10 order-last basis-full ps-14", roomy ? "@4xl:order-none @4xl:basis-auto @4xl:ps-0" : "@2xl:order-none @2xl:basis-auto @2xl:ps-0"].join(" ")}
        >
          {counters}
        </div>
      ) : null}
      {trailing ? (
        <div
          className={[
            "relative z-10 flex shrink-0 items-center",
            stacked ? (roomy ? "order-last basis-full ps-14 @4xl:order-none @4xl:basis-auto @4xl:ps-0" : "order-last basis-full ps-14 @2xl:order-none @2xl:basis-auto @2xl:ps-0") : "",
          ]
            .filter(Boolean)
            .join(" ")}
        >
          {trailing}
        </div>
      ) : null}
      {interactive ? <Icon name="chevron" flip className="text-muted size-4 shrink-0" /> : null}
    </div>
  );
}

/** The list around `ListRow`s, with the gap WF shows between full-width rows. */
export function RowList({children, className, "aria-label": label}: {children: ReactNode; className?: string; "aria-label"?: string}) {
  return (
    <div role="list" aria-label={label} className={["@container flex flex-col gap-2", className ?? ""].filter(Boolean).join(" ")}>
      {children}
    </div>
  );
}

/** Loading shape of a `ListRow`. */
export function ListRowSkeleton({className}: {className?: string}) {
  return <Skeleton className={["control-75 w-full", className ?? ""].filter(Boolean).join(" ")} />;
}
