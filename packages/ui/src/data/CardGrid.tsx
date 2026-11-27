"use client";

import {Card} from "@heroui/react";
import type {ReactNode} from "react";

// WF "Filters" and "Services": a grid of cards with a big icon at the start, the switch at the end, the name, a status line, and a
// footer for the info button or the three-state control. WF draws four columns on a wide screen; here the grid takes as many columns
// of at least 14rem as the width holds (one at 375, two at 768, four on a wide screen), so no breakpoint list can leave a card squeezed.
//
// A card is ONE list item. Its switch and buttons are their own controls, and the card itself is not a button, so no control sits inside
// another (a card that opens the explanation is the info button in its footer, not the whole card).
//
// Status is text: the `status` line says "Blocked" or "Allowed", and `data-state` is for tests and for the style of a switched-off card,
// which has its icon dimmed but never its text: dimming the whole card put the muted status line under 4.5:1 in the light theme (axe, 17.5).

// How wide a card must be at least. "compact" is for a card that holds a name, a status and a switch (the Filters grid: two across at 375,
// where a card of 14rem would stand alone and the page would be a column of mostly empty boxes). "wide" is for a card that holds the
// three-state control, which needs about 19rem. The `min(100%, ...)` keeps one card from ever being wider than the page.
const COLUMNS = {
  compact: "grid-cols-[repeat(auto-fill,minmax(min(100%,10rem),1fr))]",
  default: "grid-cols-[repeat(auto-fill,minmax(14rem,1fr))]",
  wide: "grid-cols-[repeat(auto-fill,minmax(min(100%,21rem),1fr))]",
} as const;

export function CardGrid({children, label, className, columns = "default"}: {children: ReactNode; label: string; className?: string; columns?: keyof typeof COLUMNS}) {
  return (
    <div role="list" aria-label={label} className={["card-grid grid gap-3", COLUMNS[columns], className ?? ""].filter(Boolean).join(" ")}>
      {children}
    </div>
  );
}

export type ItemTileProps = {
  /** The big icon at the start. Decorative: the title carries the meaning. */
  icon?: ReactNode;
  /** The switch, at the end. A control of its own, with its own accessible name. */
  toggle?: ReactNode;
  title: ReactNode;
  /** One line under the title: "Blocked", "Allowed", with the mode. Words, never colour alone. */
  status?: ReactNode;
  /** Free content under the status. */
  children?: ReactNode;
  /** The bottom row: the info button, a remove button, the three-state control. */
  footer?: ReactNode;
  /** The row is switched off or locked: it is dimmed and `data-state` says so. */
  state?: "on" | "off" | "disabled";
  className?: string;
};

export function ItemTile({icon, toggle, title, status, children, footer, state = "on", className}: ItemTileProps) {
  return (
    <Card
      role="listitem"
      data-state={state}
      className={["item-tile flex min-w-0 flex-col gap-3 p-4", className ?? ""].filter(Boolean).join(" ")}
    >
      <div className="flex items-start justify-between gap-3">
        {icon ? (
          <span aria-hidden="true" className={["tile-11 bg-default text-foreground grid size-11 shrink-0 place-items-center text-xl", state === "on" ? "" : "opacity-60"].join(" ")}>
            {icon}
          </span>
        ) : (
          <span />
        )}
        {toggle ? <div className="shrink-0">{toggle}</div> : null}
      </div>
      <div className="flex min-w-0 flex-col gap-0.5">
        <h3 className="truncate text-sm font-medium">{title}</h3>
        {status ? <p className="text-muted truncate text-xs">{status}</p> : null}
      </div>
      {children}
      {footer ? <div className="mt-auto flex flex-wrap items-center justify-between gap-2">{footer}</div> : null}
    </Card>
  );
}
