import {useEffect} from "react";
import {infiniteQueryOptions, useInfiniteQuery, useMutation, useQueryClient, type InfiniteData, type QueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {pollEvery} from "../activity.ts";
import {hasCode} from "../errors.ts";
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
 * The cache after one notification is read, so the change shows at once. An ordinary notice gets a `read_at` and the
 * count of the first page drops by one if it was unread. An unread security notice (Question 19) is in `security_items`,
 * the same list on every page: it leaves that block on every page and `security_unread_count` drops by one. It is not put
 * into `items` here, because which page and place it takes is the server's to say; the refetch that follows a mark
 * brings it back there as a read notice. A pure function, so the rule is tested without a browser.
 */
export function markNotificationRead(data: Pages | undefined, id: string, now: Date): Pages | undefined {
  if (!data) return data;
  let changed = false;
  const pages = data.pages.map((page) => {
    const security = page.security_items.filter((item) => item.id !== id);
    const securityGone = security.length !== page.security_items.length;
    if (securityGone) changed = true;
    return {
      ...page,
      items: page.items.map((item) => {
        if (item.id !== id || item.read_at) return item;
        changed = true;
        return {...item, read_at: now.toISOString()};
      }),
      security_items: security,
      security_unread_count: securityGone ? Math.max(0, page.security_unread_count - 1) : page.security_unread_count,
    };
  });
  if (!changed) return data;
  // `unread_count` is the one figure of the first page. A notice that was in `security_items` did not count in it.
  const wasCounted = data.pages.some((page) => page.items.some((item) => item.id === id && !item.read_at));
  const first = pages[0];
  if (first && wasCounted) first.unread_count = Math.max(0, first.unread_count - 1);
  return {...data, pages};
}

/**
 * `unread_count` of a page is counted over every row, not over the page, so the badge is right on a long list (AUTH 14.2).
 * Every page is refetched together, and the first one is the newest. It leaves out the unread security notices that are
 * shown apart (`security_items`); `securityUnread` is those, and the badge is the sum of the two.
 */
export function notificationUnread(data: Pages | undefined): number {
  return data?.pages[0]?.unread_count ?? 0;
}

/** The unread security notices shown apart, newest first, at most 50 (the same on every page, so the first one is read). */
export function securityNotices(data: Pages | undefined): Notification[] {
  return data?.pages[0]?.security_items ?? [];
}

/** How many of them: what the badge adds to `notificationUnread`. Never counted from the rows of the list. */
export function securityUnread(data: Pages | undefined): number {
  return data?.pages[0]?.security_unread_count ?? 0;
}

/** The most pages the panel loads by itself to find unread notices. A person can ask for more with "Show older". */
export const AUTO_PAGES = 10;

/**
 * Whether unread notices are still on a page that is not loaded: `unread_count` is counted over every row (and holds the
 * unread security notices older than the newest 50), so while it is above the unread rows the pages hold, the next page has
 * some. This is how a security notice that a flood pushed past the first page is found without the person paging for it
 * (webi-r1-6). Bounded by `AUTO_PAGES`, so a count that never matches (rows that moved between two reads) ends. A pure function.
 */
export function needsMorePages(data: Pages | undefined, hasNextPage: boolean, maxPages = AUTO_PAGES): boolean {
  if (!data || !hasNextPage || data.pages.length >= maxPages) return false;
  const loaded = data.pages.reduce((sum, page) => sum + page.items.filter((item) => !item.read_at).length, 0);
  return (data.pages[0]?.unread_count ?? 0) > loaded;
}

/**
 * Whether the panel stopped at the cap with unread notices still on a page it did not load, so an unread security notice
 * could be among them (webi-r2-6). A pure function: the same count as `needsMorePages`, but only once the cap is reached,
 * which is the moment the person has to be told, because nothing will page for them any more.
 */
export function unreadPastCap(data: Pages | undefined, hasNextPage: boolean, maxPages = AUTO_PAGES): boolean {
  if (!data || data.pages.length < maxPages) return false;
  return needsMorePages(data, hasNextPage, Number.POSITIVE_INFINITY);
}

export function flattenNotifications(data: Pages | undefined): Notification[] {
  return data?.pages.flatMap((p) => p.items) ?? [];
}

/** Feeds the bell and the banners. Runs only while the session is `ready`: a restricted or suspended session is refused these routes. */
export function useNotificationFeed({autoPage = false}: {autoPage?: boolean} = {}) {
  const {status} = useSession();
  const query = useInfiniteQuery({...notificationsQueryOptions(), enabled: status === "ready"});
  const {data, hasNextPage, isFetching, isFetchNextPageError, fetchNextPage} = query;
  // Only one place asks for the pages (the banner stack, always mounted): fetchNextPage cancels a fetch that is running, so two
  // callers would cancel each other.
  // A page that failed is not asked for again by the effect, or a refusal would be retried in a loop; the next poll tries again.
  const more = autoPage && !isFetching && !isFetchNextPageError && needsMorePages(data, hasNextPage);
  useEffect(() => {
    if (more) void fetchNextPage();
  }, [more, fetchNextPage, data]);
  return {
    items: flattenNotifications(query.data),
    unread: notificationUnread(query.data),
    securityItems: securityNotices(query.data),
    securityUnread: securityUnread(query.data),
    moreUnread: unreadPastCap(data, hasNextPage),
    isPending: query.isPending,
    hasNextPage: query.hasNextPage,
    fetchNextPage: query.fetchNextPage,
    isFetchingNextPage: query.isFetchingNextPage,
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

/**
 * How many notices one press of Mark as read on a security group sends. `POST /notifications/{id}/read` is `user-write`, 60 a
 * minute per session, and the same budget carries every other write of the person (ending a session, for one). A group can hold
 * hundreds of notices when a thief made them on purpose, and one press must neither spend the whole minute nor leave the person
 * a wall of 429s: 40 leaves room for the rest of the page, and what remains is cleared by the next press (webi-r2-3, webi-r2-8).
 */
export const MARK_PER_PRESS = 40;

export type MarkManyResult = {done: number; left: number};

/**
 * Marks `ids` read one after another, at most `MARK_PER_PRESS`, and stops at the first refusal, which is thrown: a 429 would
 * repeat for every id that follows. A 409 `conflict` on one id is not a refusal of the run: the notice is locked to this session
 * (its verdict moved since the list was read), nothing the person presses will clear it, so it is skipped, left as it is in the
 * cache, and the list fetched at the end shows it as not markable (spec 8.5, webi-r3-2, webi-r3-4). It does not count as done, and
 * not as left either, because pressing again cannot clear it. Each success is applied to the cache at once, so a stop in the middle shows what is
 * really cleared, and the list is fetched once at the end and not once per answer. Options and not a hook, so the rule is
 * tested without React.
 */
export const markNotificationsReadOptions = (queryClient: QueryClient) => ({
  mutationFn: async (ids: string[]): Promise<MarkManyResult> => {
    await queryClient.cancelQueries({queryKey: notificationKeys.list});
    const batch = ids.slice(0, MARK_PER_PRESS);
    let done = 0;
    for (const id of batch) {
      try {
        await api.POST("/notifications/{id}/read", {params: {path: {id}}});
      } catch (error) {
        if (hasCode(error, "conflict")) continue;
        throw error;
      }
      queryClient.setQueryData<Pages>(notificationKeys.list, (data) => markNotificationRead(data, id, new Date()));
      done += 1;
    }
    return {done, left: ids.length - batch.length};
  },
  onSettled: () => queryClient.invalidateQueries({queryKey: notificationKeys.list}),
});

export function useMarkNotificationsRead() {
  const queryClient = useQueryClient();
  return useMutation(markNotificationsReadOptions(queryClient));
}
