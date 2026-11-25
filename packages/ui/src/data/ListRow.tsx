"use client";

import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Skeleton} from "@heroui/react";
import type {ReactNode} from "react";

import {ROW_FOCUS, RowMain} from "./RowMain.tsx";

// Spec 8.10 (T-487). The full-width row of a list: Profiles, and later the other lists that WF draws
// with a leading icon, a name, a sub-line, a group of counters and a chevron.
//
// Height 75 at md and up, in the design scale, with the `control-75` corner (30px, the cap: spec 6,
// D16). Below md the row is two lines (T-115): icon, name and chevron first, the counters under
// them, and it grows to fit instead of squeezing.
//
// One main action for the whole row (`href` or `onPress`, as a stretched link, see RowMain);
// `counters` and `trailing` are their own controls and keep working. `isHighlighted` is the "just
// created" row at the top of the list. A row with no action is information only and does not react
// to the pointer.

export type ListRowProps = {
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
};

export function ListRow({icon, title, subtitle, counters, trailing, href, onPress, isHighlighted = false, className}: ListRowProps) {
  const interactive = Boolean(href || onPress);
  return (
    <div
      role="listitem"
      data-highlighted={isHighlighted || undefined}
      className={[
        "control-75 relative flex h-auto min-h-control-75 w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 md:h-control-75 md:flex-nowrap md:py-0",
        isHighlighted ? "bg-accent/10" : "bg-surface",
        interactive ? "cursor-[var(--cursor-interactive)]" : "",
        interactive ? (isHighlighted ? "hover:bg-accent/15" : "hover:bg-default") : "",
        ROW_FOCUS,
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
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
        {subtitle ? <span className="text-muted truncate text-xs">{subtitle}</span> : null}
      </div>
      {counters ? (
        <div className="relative z-10 order-last basis-full ps-14 md:order-none md:basis-auto md:ps-0">{counters}</div>
      ) : null}
      {trailing ? <div className="relative z-10 flex shrink-0 items-center">{trailing}</div> : null}
      {interactive ? <Icon name="chevron" flip className="text-muted size-4 shrink-0" /> : null}
    </div>
  );
}

/** The list around `ListRow`s, with the gap WF shows between full-width rows. */
export function RowList({children, className, "aria-label": label}: {children: ReactNode; className?: string; "aria-label"?: string}) {
  return (
    <div role="list" aria-label={label} className={["flex flex-col gap-2", className ?? ""].filter(Boolean).join(" ")}>
      {children}
    </div>
  );
}

/** Loading shape of a `ListRow`. */
export function ListRowSkeleton({className}: {className?: string}) {
  return <Skeleton className={["control-75 w-full", className ?? ""].filter(Boolean).join(" ")} />;
}
