"use client";

import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";

// The group of counters at the end of a Profiles row (WF: four counters with a vertical separator).
// Each is a number over its label; with `href` it is a link of its own (the wireframe sends a click
// on a counter to that tab), above the row's stretched action. Digits follow the language (spec 4.4).

export type RowCounter = {id: string; label: string; value: number; href?: string};

const CELL = "flex min-w-14 flex-col items-center px-2 text-xs leading-tight md:px-3";
const LINK =
  "hover:bg-default focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus";

export function RowCounters({items, className}: {items: RowCounter[]; className?: string}) {
  const format = useAppFormat();
  return (
    <ul className={["flex items-center", className ?? ""].filter(Boolean).join(" ")}>
      {items.map((item, i) => {
        const cell = (
          <>
            <span className="text-sm font-medium tabular-nums">{format.number(item.value)}</span>
            <span className="text-muted">{item.label}</span>
          </>
        );
        return (
          <li key={item.id} className="flex items-center">
            {i > 0 ? <span aria-hidden="true" className="bg-separator mx-0.5 h-6 w-px" /> : null}
            {item.href ? (
              <Link href={item.href} className={`${CELL} ${LINK} row-counter py-1`}>
                {cell}
              </Link>
            ) : (
              <span className={CELL}>{cell}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
