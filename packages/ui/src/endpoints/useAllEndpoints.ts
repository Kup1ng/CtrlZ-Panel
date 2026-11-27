"use client";

import {useEndpoints, type EndpointFilter} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useCallback, useEffect} from "react";

// The Endpoint list of a view, read to its last page. A tenant holds few Endpoints (the plan's `max_endpoints`), and the screens that
// group them, select among them or tick them in a dialog need all of them, so the next page is asked for as soon as one arrives.
// `loading` is true until the last page is in or a page failed. A failed page leaves the rows that came in, so `failed` says that the
// list may be partial (`incomplete`) or stale, and `retry` asks for what is missing: the next page if there is one, else a refetch.

export function useAllEndpoints(filter: EndpointFilter = {}, options: {enabled?: boolean} = {}) {
  const query = useEndpoints(filter, options);
  const {hasNextPage, isFetchingNextPage, isError, fetchNextPage, refetch, endpoints} = query;
  useEffect(() => {
    if (hasNextPage && !isFetchingNextPage && !isError) void fetchNextPage();
  }, [hasNextPage, isFetchingNextPage, isError, fetchNextPage]);
  const failed = isError && endpoints.length > 0;
  const retry = useCallback(() => void (hasNextPage ? fetchNextPage() : refetch()), [hasNextPage, fetchNextPage, refetch]);
  return {...query, loading: query.isPending || (hasNextPage === true && !isError), failed, incomplete: failed && hasNextPage === true, retry};
}
