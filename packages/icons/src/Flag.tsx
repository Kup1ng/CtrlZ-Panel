"use client";

import {createElement, useEffect, useSyncExternalStore, type ReactElement, type ReactNode} from "react";

import type {FlagDrawing, FlagNode} from "./flagTable.generated.ts";

// A country flag as inline SVG, from the table that scripts/flags.mjs writes (249 flags, 173 KB). The table is loaded on the first
// flag a page draws, as its own chunk, and kept: a page with no flag never fetches it, and no request ever leaves the origin for one.
// Until it arrives, and for a code with no flag (a label-only location, `XX`), the box is drawn empty at the same size, so nothing
// moves when the flags come in.
//
// A flag next to its country's name is decoration, so it is hidden from readers. Pass `label` when the flag stands alone.

type Table = Readonly<Record<string, FlagDrawing>>;

let table: Table | null = null;
let loading: Promise<Table> | null = null;
const listeners = new Set<() => void>();

/** Loads the table once. Tests call it to have the flags before they render. */
export function loadFlags(): Promise<Table> {
  loading ??= import("./flagTable.generated.ts").then((m) => {
    table = m.FLAGS;
    for (const listener of listeners) listener();
    return m.FLAGS;
  });
  return loading;
}

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => void listeners.delete(listener);
};
const snapshot = () => table;
const serverSnapshot = () => null;

const CODE = /^[A-Za-z]{2}$/;

/** The drawing of a code, or `undefined` for one that is not an ISO code or has no flag. Needs `loadFlags()` to have finished. */
export function flagDrawing(code: string): FlagDrawing | undefined {
  return table !== null && CODE.test(code) ? table[code.toUpperCase()] : undefined;
}

export function drawNodes(nodes: readonly FlagNode[], prefix = "n"): ReactNode[] {
  return nodes.map(([tag, props, children], i) => createElement(tag, {key: `${prefix}${i}`, ...props}, ...drawNodes(children, `${prefix}${i}.`)));
}

export type FlagProps = {
  /** ISO 3166-1 alpha-2, in any case. */
  code: string;
  /** Names the flag for a reader when nothing beside it does. */
  label?: string;
  className?: string;
};

const BOX = "flag inline-block h-4 w-6 shrink-0 border border-border bg-default align-middle";

/** The element of a flag, or an empty box of the same size when there is no drawing. A pure function, so it is tested without a DOM. */
export function flagElement(drawing: FlagDrawing | undefined, label?: string, className?: string): ReactElement {
  const classes = className ? `${BOX} ${className}` : BOX;
  const a11y = label ? ({role: "img", "aria-label": label} as const) : ({"aria-hidden": true} as const);
  if (!drawing) return <span className={classes} {...a11y} />;
  return (
    <svg viewBox={drawing.viewBox} className={classes} focusable="false" preserveAspectRatio="xMidYMid slice" {...a11y}>
      {drawNodes(drawing.children)}
    </svg>
  );
}

export function Flag({code, label, className}: FlagProps): ReactElement {
  // The table is a store outside React: the first flag of a page starts the load, and every flag redraws when it arrives.
  const loaded = useSyncExternalStore(subscribe, snapshot, serverSnapshot);
  useEffect(() => {
    void loadFlags();
  }, []);
  return flagElement(loaded ? flagDrawing(code) : undefined, label, className);
}
