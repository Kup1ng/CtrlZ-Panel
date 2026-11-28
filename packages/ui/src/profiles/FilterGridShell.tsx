"use client";

import {Skeleton} from "@heroui/react";
import type {CatalogFilter} from "@ctrlz/api-client/hooks/filters.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useLocale} from "next-intl";
import {useMemo, type ReactNode} from "react";

import {CardGrid} from "../data/CardGrid.tsx";
import {catalogName} from "./filtersModel.ts";

/** The catalogue entries in the order of the reader's language, which is the order they look for them in. */
export function useSortedFilters(filters: readonly CatalogFilter[]) {
  const locale = useLocale();
  const format = useAppFormat();
  return useMemo(
    () => filters.map((f) => ({filter: f, name: catalogName(f, locale)})).sort((a, b) => format.compare(a.name, b.name)),
    [filters, locale, format],
  );
}

/** What a Filters grid shows while its two reads are on the way: the shape of the cards (spec 8.7). */
export function FilterGridSkeleton({label}: {label: string}) {
  return (
    <div role="status" aria-label={label}>
      <CardGrid label={label}>
        {Array.from({length: 8}, (_, i) => (
          <Skeleton key={i} className="h-36 w-full" />
        ))}
      </CardGrid>
    </div>
  );
}

export function ScreenStack({screen, children}: {screen: string; children: ReactNode}) {
  return (
    <div data-screen={screen} className="flex flex-col gap-4">
      {children}
    </div>
  );
}
