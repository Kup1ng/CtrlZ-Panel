"use client";

import {Button, Skeleton, Spinner} from "@heroui/react";
import {DataGrid, type DataGridColumn} from "@heroui-pro/react";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {useTranslations} from "next-intl";
import type {InfiniteData, UseInfiniteQueryResult} from "@tanstack/react-query";
import type {ReactNode} from "react";
import {RefreshFailed} from "./RefreshFailed.tsx";
import {keepRetry} from "./restoreFocus.ts";

// The list of every admin page: a DataGrid that loads by `next_cursor` (spec 13.1, 13.2, 13.5). One component so the
// four states of a list are the same everywhere (spec 8.7): loading (a skeleton, announced as busy), failed (the section
// error with Retry and the request id), empty (the page's own words, and its one action) and loaded. A page that fails
// after some rows are on screen keeps them and says why under the grid.
//
// The grid is built only when there are rows. A DataGrid with a few hundred rows is fast; the page size is 50 and a long
// list is loaded by scrolling, never all at once (spec 8.10: the server-rendered grid is quadratic in the row count,
// and this one is only ever drawn in the browser after the first answer).

export type PagedGridProps<T extends object> = {
  /** The grid's accessible name. */
  label: string;
  columns: DataGridColumn<T>[];
  rows: readonly T[];
  getRowId: (row: T) => string;
  isPending: boolean;
  error: unknown;
  onRetry: () => void;
  /** The plain refetch, for the refresh-failed line above rows that are already shown (wp10-r16-3); it falls back to onRetry. */
  refetch?: () => unknown;
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  /** Returns the promise of the fetch, so the Load more of a failed later page can give the focus back once it has settled. */
  fetchNextPage: () => unknown;
  /** The failed call was a later page: rows stay and this says it. */
  isNextPageError?: boolean;
  empty: {icon?: GeneralIconName; title: ReactNode; description?: ReactNode; action?: ReactNode};
  /** Under this width the grid scrolls sideways inside its box instead of squeezing a phone number. */
  minWidth?: string;
};

export function PagedGrid<T extends object>({
  label,
  columns,
  rows,
  getRowId,
  isPending,
  error,
  onRetry,
  refetch,
  hasNextPage,
  isFetchingNextPage,
  fetchNextPage,
  isNextPageError = false,
  empty,
  minWidth = "min-w-[36rem]",
}: PagedGridProps<T>) {
  const c = useTranslations("common");
  const t = useTranslations("admin");

  if (isPending) {
    return (
      <div role="status" aria-busy="true" data-testid="grid-loading">
        <span className="sr-only">{c("loading")}</span>
        <div aria-hidden className="flex flex-col gap-2">
          {Array.from({length: 6}, (_, index) => (
            <Skeleton key={index} className="h-12 w-full rounded-(--radius-box)" />
          ))}
        </div>
      </div>
    );
  }
  if (error && rows.length === 0) return <SectionError error={error} onRetry={onRetry} />;
  if (rows.length === 0) {
    return (
      <div className="bg-surface rounded-(--radius-box) shadow-surface" data-testid="grid-empty">
        <SectionEmpty icon={empty.icon} title={empty.title} description={empty.description} action={empty.action} size="md" className="py-10" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {/* A refetch that failed while rows are held keeps them (TanStack keeps the data) and says so, as the sms and settings pages do (wp10-r16-3). A failed later page has its own block below. */}
      {error && !isNextPageError ? <RefreshFailed error={error} onRetry={refetch ?? onRetry} /> : null}
      <DataGrid
        aria-label={label}
        columns={columns}
        data={rows as T[]}
        getRowId={getRowId}
        contentClassName={minWidth}
        scrollContainerClassName="max-h-[calc(100dvh-14rem)] overflow-auto"
        stickyHeader
        isLoadingMore={isFetchingNextPage}
        loadMoreContent={<Spinner size="md" />}
        onLoadMore={hasNextPage && !isNextPageError ? () => void fetchNextPage() : undefined}
      />
      {isNextPageError ? (
        <div className="flex flex-col items-start gap-2" data-testid="grid-more-error">
          <SectionError error={error} className="w-full" />
          {/* Load more leaves with its error block when the page loads (wp10-r16-1), so it is a keepRetry like every Retry. */}
          <Button size="sm" variant="secondary" onPress={keepRetry(fetchNextPage)}>
            {t("grid.loadMore")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

/** The grid's state props from an infinite query whose pages hold `items`. A failed first page is an error with no rows; a failed later page keeps them. */
export function gridState<T, E>(query: UseInfiniteQueryResult<InfiniteData<{items: T[]}>, E>) {
  return {
    rows: query.data?.pages.flatMap((page) => page.items) ?? [],
    isPending: query.isPending,
    error: query.error,
    onRetry: keepRetry(() => query.refetch()),
    refetch: () => query.refetch(),
    hasNextPage: query.hasNextPage,
    isFetchingNextPage: query.isFetchingNextPage,
    fetchNextPage: () => query.fetchNextPage(),
    isNextPageError: query.isFetchNextPageError,
  };
}
