import {infiniteQueryOptions, useInfiniteQuery, useMutation, useQueryClient, type InfiniteData, type QueryClient} from "@tanstack/react-query";
import {useEffect, useState} from "react";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {pollEvery} from "../activity.ts";
import {shouldRetry} from "../queryDefaults.ts";
import {useSession} from "./me.ts";
import {PAGE_SIZE, POLL_MS} from "./notifications.ts";

// Spec 8.5, 8.8, 14.5. Announcements written by an admin. Their text is plain,
// in whichever language the admin wrote, and is rendered as text only.

export type Announcement = components["schemas"]["Announcement"];
export type AnnouncementPage = components["schemas"]["AnnouncementPage"];

export const announcementKeys = {list: ["announcements", "list"] as const};

export const announcementsQueryOptions = () =>
  infiniteQueryOptions({
    queryKey: announcementKeys.list,
    queryFn: async ({pageParam, signal}) =>
      required(await api.GET("/announcements", {params: {query: {cursor: pageParam, limit: PAGE_SIZE}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    // Only while someone is at the page, so the poll does not keep an unattended session alive (activity.ts).
    refetchInterval: pollEvery(POLL_MS),
    retry: shouldRetry,
  });

type Pages = InfiniteData<AnnouncementPage, unknown>;

export function markAnnouncementRead(data: Pages | undefined, id: string): Pages | undefined {
  if (!data) return data;
  let changed = false;
  const pages = data.pages.map((page) => ({
    ...page,
    items: page.items.map((item) => {
      if (item.id !== id || item.read) return item;
      changed = true;
      return {...item, read: true};
    }),
  }));
  if (!changed) return data;
  const first = pages[0];
  if (first) first.unread_count = Math.max(0, first.unread_count - 1);
  return {...data, pages};
}

/** An announcement is shown from `starts_at` to `ends_at`, both inclusive; no end means no end. */
export function isAnnouncementLive(item: Pick<Announcement, "starts_at" | "ends_at">, now: Date): boolean {
  const t = now.getTime();
  if (Date.parse(item.starts_at) > t) return false;
  return item.ends_at === undefined || Date.parse(item.ends_at) >= t;
}

/**
 * The next moment at which `isAnnouncementLive` changes its answer for any of the items, in epoch ms,
 * or undefined when none will. A start is live from `starts_at`; an end is inclusive, so the item is
 * gone one millisecond after `ends_at`.
 */
export function nextAnnouncementChangeAt(items: ReadonlyArray<Pick<Announcement, "starts_at" | "ends_at">>, now: Date): number | undefined {
  const t = now.getTime();
  let next: number | undefined;
  const consider = (at: number) => {
    if (Number.isNaN(at) || at <= t) return;
    if (next === undefined || at < next) next = at;
  };
  for (const item of items) {
    consider(Date.parse(item.starts_at));
    if (item.ends_at !== undefined) consider(Date.parse(item.ends_at) + 1);
  }
  return next;
}

// setTimeout keeps its delay in a signed 32-bit integer and fires at once when it is larger.
const MAX_TIMER_MS = 2 ** 31 - 1;

/** Calls `onDue` once when the clock reaches `at`, whatever the distance; returns the cancel function. */
export function armAnnouncementChange(at: number, onDue: () => void): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const arm = () => {
    const left = at - Date.now();
    if (left <= 0) {
      onDue();
      return;
    }
    timer = setTimeout(arm, Math.min(left, MAX_TIMER_MS));
  };
  arm();
  return () => {
    if (timer !== undefined) clearTimeout(timer);
  };
}

/**
 * The `now` that the announcement window is judged against. The feed's poll returns the same data while
 * nothing changed, and TanStack keeps the old reference, so no render follows it, and an unattended tab
 * has its poll paused (activity.ts). Without a timer of its own a banner past its end, or before its
 * start, would stay as it is until something else re-rendered the page (wp4-r12-1). One timeout is
 * armed for the nearest start or end among the loaded rows and is armed again after it fires.
 */
export function useAnnouncementNow(items: ReadonlyArray<Pick<Announcement, "starts_at" | "ends_at">>): Date {
  // The state only forces a render; every render reads the clock itself, so rows that arrive late are
  // judged against the real time and not against the time of the last tick.
  const [tick, setTick] = useState(0);
  const now = new Date();
  const at = nextAnnouncementChangeAt(items, now);
  // `tick` is a dependency too: a timer that fired a hair early must be armed again.
  useEffect(() => {
    if (at === undefined) return undefined;
    return armAnnouncementChange(at, () => setTick((n) => n + 1));
  }, [at, tick]);
  return now;
}

export function useAnnouncementFeed() {
  const {status} = useSession();
  const query = useInfiniteQuery({...announcementsQueryOptions(), enabled: status === "ready"});
  return {
    items: query.data?.pages.flatMap((p) => p.items) ?? [],
    unread: query.data?.pages[0]?.unread_count ?? 0,
    isPending: query.isPending,
    hasNextPage: query.hasNextPage,
    fetchNextPage: query.fetchNextPage,
  };
}

export const markAnnouncementReadOptions = (queryClient: QueryClient) => ({
  mutationFn: async (id: string) => {
    await api.POST("/announcements/{id}/read", {params: {path: {id}}});
  },
  onMutate: async (id: string) => {
    await queryClient.cancelQueries({queryKey: announcementKeys.list});
    const before = queryClient.getQueryData<Pages>(announcementKeys.list);
    queryClient.setQueryData<Pages>(announcementKeys.list, (data) => markAnnouncementRead(data, id));
    return {before};
  },
  onError: (_error: unknown, _id: string, context: {before: Pages | undefined} | undefined) => {
    if (context?.before) queryClient.setQueryData(announcementKeys.list, context.before);
  },
  onSettled: () => queryClient.invalidateQueries({queryKey: announcementKeys.list}),
});

export function useMarkAnnouncementRead() {
  const queryClient = useQueryClient();
  return useMutation(markAnnouncementReadOptions(queryClient));
}
