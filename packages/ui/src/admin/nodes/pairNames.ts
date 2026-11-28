"use client";

import {useAppFormat} from "@ctrlz/i18n/format.ts";

// "node-1 and node-2" in the page's language. A node's name is typed by an admin and is usually Latin, so each name is wrapped in a
// first-strong isolate (U+2068 .. U+2069): inside a Persian sentence it keeps its own order and does not pull the words around it.

const FSI = "\u2068";
const PDI = "\u2069";

export function useNameList(): (names: readonly string[]) => string {
  const format = useAppFormat();
  return (names) => format.list(names.map((name) => `${FSI}${name}${PDI}`));
}
