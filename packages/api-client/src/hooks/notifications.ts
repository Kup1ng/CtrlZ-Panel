import {infiniteQueryOptions, useInfiniteQuery, useMutation, useQueryClient, type InfiniteData, type QueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {pollEvery} from "../activity.ts";
import {shouldRetry} from "../queryDefaults.ts";
import {useSession} from "./me.ts";

// Spec 8.5, 14.5. The bell's notifications. A list hook is an infinite query with
// `next_cursor` as the page parameter. The bell polls every 60 s while the tab is
// visible (TanStack pauses an interval in a hidden tab) and a person is at it (activity.ts), with no WebSocket.

export type Notification = components["schemas"]["Notification"];
export type NotificationPage = components["schemas"]["NotificationPage"];

export const POLL_MS = 60_000;
export const PAGE_SIZE = 50;

export const notificationKeys = {list: ["notifications", "list"] as const};

export const notificationsQueryOptions = () =>
  infiniteQueryOptions({
    queryKey: notificationKeys.list,
    queryFn: async ({pageParam, signal}) =>
      required(await api.GET("/notifications", {params: {query: {cursor: pageParam, limit: PAGE_SIZE}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    // Only while someone is at the page, so the poll does not keep an unattended session alive (activity.ts).
    refetchInterval: pollEvery(POLL_MS),
    retry: shouldRetry,
  });

type Pages = InfiniteData<NotificationPage, unknown>;

/**
 * The cache after one notification is read: it gets a `read_at`, and the badge
 * count, which belongs to the first page, drops by one if it was unread. A pure
 * function, so the rule is tested without a browser.
 */
export function markNotificationRead(data: Pages | undefined, id: string, now: Date): Pages | undefined {
  if (!data) return data;
  let changed = false;
  const pages = data.pages.map((page) => ({
    ...page,
    items: page.items.map((item) => {
      if (item.id !== id || item.read_at) return item;
      changed = true;
      return {...item, read_at: now.toISOString()};
    }),
  }));
  if (!changed) return data;
  const first = pages[0];
  if (first) first.unread_count = Math.max(0, first.unread_count - 1);
  return {...data, pages};
}

/**
 * `unread_count` of a page is counted over every row, not over the page, so the
 * badge is right on a long list (AUTH 14.2). Every page is refetched together, and
 * the first one is the newest.
 */
export function notificationUnread(data: Pages | undefined): number {
  return data?.pages[0]?.unread_count ?? 0;
}

export function flattenNotifications(data: Pages | undefined): Notification[] {
  return data?.pages.flatMap((p) => p.items) ?? [];
}

/** Feeds the bell and the banners. Runs only while the session is `ready`: a restricted or suspended session is refused these routes. */
export function useNotificationFeed() {
  const {status} = useSession();
  const query = useInfiniteQuery({...notificationsQueryOptions(), enabled: status === "ready"});
  return {
    items: flattenNotifications(query.data),
    unread: notificationUnread(query.data),
    isPending: query.isPending,
    hasNextPage: query.hasNextPage,
    fetchNextPage: query.fetchNextPage,
  };
}

/**
 * `POST /notifications/{id}/read`, with the change shown at once and put back if
 * the call fails. Options and not a hook, so the optimistic rule is tested without React.
 */
export const markNotificationReadOptions = (queryClient: QueryClient) => ({
  mutationFn: async (id: string) => {
    await api.POST("/notifications/{id}/read", {params: {path: {id}}});
  },
  onMutate: async (id: string) => {
    await queryClient.cancelQueries({queryKey: notificationKeys.list});
    const before = queryClient.getQueryData<Pages>(notificationKeys.list);
    queryClient.setQueryData<Pages>(notificationKeys.list, (data) => markNotificationRead(data, id, new Date()));
    return {before};
  },
  onError: (_error: unknown, _id: string, context: {before: Pages | undefined} | undefined) => {
    if (context?.before) queryClient.setQueryData(notificationKeys.list, context.before);
  },
  onSettled: () => queryClient.invalidateQueries({queryKey: notificationKeys.list}),
});

export function useMarkNotificationRead() {
  const queryClient = useQueryClient();
  return useMutation(markNotificationReadOptions(queryClient));
}
