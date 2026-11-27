"use client";

import {useAnnouncementFeed, useMarkAnnouncementRead, type Announcement} from "@ctrlz/api-client/hooks/announcements.ts";
import {useMarkNotificationRead, useNotificationFeed, type Notification} from "@ctrlz/api-client/hooks/notifications.ts";
import {useCallback, useMemo} from "react";

import {useMarkNoticeGroup} from "./useMarkNoticeGroup.ts";
import {PANEL_PROTECTED_PREFIXES} from "../proxy/prefixes.ts";
import {sanitizeNext} from "../proxy/safeNext.ts";

// What the bell reads: GET /notifications and GET /announcements, merged newest
// first and polled every 60 s while the tab is visible (spec 8.5). Both feeds are
// TanStack queries, so the banners read the same cache without a second request.

export type BellEntry = {
  /** Unique across both sources: `n:<id>` or `a:<id>`. */
  key: string;
  source: "notification" | "announcement";
  id: string;
  /** Notifications only: picks `shell.bell.kinds.<kind>`. */
  kind?: string;
  /** Notifications only: ICU params. Escaped by ICU, never HTML. */
  params?: Record<string, string | number | boolean>;
  /** Announcements only: plain text, in whichever language the admin wrote. */
  body?: string;
  severity?: "info" | "warning" | "critical";
  /** Only a path that starts with one `/` is followed (safeInternalPath). */
  link?: string;
  createdAt: string;
  /** A group only: the date of its oldest notice, so the person sees the date of every notice that one press clears, not only the newest (webi-r2-7). Equal to `createdAt` for one notice. */
  oldestAt: string;
  read: boolean;
  /** A notice of a change a thief could make to keep access (Question 19). Opening it never marks it read. */
  security: boolean;
  /** Whether the session that asked may mark it read. The API answers this per session; an announcement and an ordinary notice are always markable. A group is markable only when every notice in it is. */
  markable: boolean;
  /** How many notices the entry stands for. 1 except for a security group (one entry per kind, see groupSecurity). */
  count: number;
  /** The ids that "mark as read" clears: the notice itself, or every unread notice of a security group. */
  memberIds: string[];
};

export type BellData = {
  /** The list: ordinary notices and announcements, newest first. A read security notice is here like any read notice. */
  entries: BellEntry[];
  /** The unread security notices, one entry per kind with the newest one's text and a count, newest first, shown above the list and as banners (spec 8.5, 8.8). Never in `entries`. */
  security: BellEntry[];
  /** NotificationPage.unread_count plus security_unread_count plus AnnouncementPage.unread_count. Never counted from `entries`, which is one page. */
  unread: number;
  markRead: (entry: BellEntry) => void;
  /** Older notices are on a page that is not loaded yet. */
  hasMore: boolean;
  /** Unread notices remain beyond the pages the panel loaded by itself, so a security notice could still be among them (webi-r2-6). */
  moreUnread: boolean;
  loadingMore: boolean;
  loadMore: () => void;
};

/** Newest first. A date that does not parse sorts last, so one bad row cannot hide the rest. */
function byNewest(a: BellEntry, b: BellEntry): number {
  const ta = Date.parse(a.createdAt);
  const tb = Date.parse(b.createdAt);
  return (Number.isNaN(tb) ? -Infinity : tb) - (Number.isNaN(ta) ? -Infinity : ta);
}

type Feed = {
  items: Notification[];
  securityItems: Notification[];
};

const ofNotification = (n: Notification): BellEntry => ({
  key: `n:${n.id}`,
  source: "notification",
  id: n.id,
  kind: n.kind,
  params: n.params,
  severity: n.severity,
  link: n.link,
  createdAt: n.created_at,
  oldestAt: n.created_at,
  read: n.read_at !== undefined,
  security: n.security,
  markable: n.markable,
  count: 1,
  memberIds: [n.id],
});

/**
 * One entry per kind from the unread security notices: the newest one's text and date, how many there are, and the ids that
 * one press of Mark as read clears. A flood of one kind (a session can make a notice per call of a sensitive route) is one
 * line and cannot push another kind out of the block or out of the two banners (webi-r1-6, -7). The group is markable only
 * when every notice in it is, so a banner is never cleared while one notice that this session may not clear is behind it.
 */
export function groupSecurity(unread: BellEntry[]): BellEntry[] {
  const groups = new Map<string, BellEntry[]>();
  for (const entry of unread) {
    // A kind the page does not know is still a group of its own, and a missing kind is one more.
    const key = entry.kind ?? "";
    groups.set(key, [...(groups.get(key) ?? []), entry]);
  }
  return [...groups.values()]
    .map((members) => {
      const [newest] = [...members].sort(byNewest);
      // A date that does not parse is not the oldest: it would show as the first notice with no date to read.
      const dated = members.filter((m) => !Number.isNaN(Date.parse(m.createdAt)));
      const oldest = dated.length > 0 ? dated.reduce((a, b) => (Date.parse(b.createdAt) < Date.parse(a.createdAt) ? b : a)) : newest!;
      return {
        ...newest!,
        oldestAt: oldest.createdAt,
        count: members.length,
        memberIds: members.map((m) => m.id),
        markable: members.every((m) => m.markable),
      };
    })
    .sort(byNewest);
}

/**
 * The two lists of the bell from the three feeds. A pure function, so the rules are tested without a browser:
 * - the unread security notices are the security block, grouped by kind (groupSecurity): those of `security_items`, and the
 *   unread ones that the API leaves in `items` because they are older than the newest 50 (webi-r1-6). Only the pages the panel
 *   has loaded are read, at most `AUTO_PAGES` by itself, so a flood longer than that can still hide one: `moreUnread` says so (webi-r2-6);
 * - a notice that is in `security_items` is dropped from the list if a page of the list also holds it (the pages are
 *   read at slightly different moments), so one notice is never in both places and is never counted twice;
 * - every other notice, a read security notice included, is in the list.
 */
export function bellModel(feed: Feed, announcements: Announcement[]): {entries: BellEntry[]; security: BellEntry[]} {
  const unread = new Map<string, Notification>();
  for (const n of feed.securityItems) unread.set(n.id, n);
  for (const n of feed.items) if (n.security && n.read_at === undefined) unread.set(n.id, n);
  const security = groupSecurity([...unread.values()].map(ofNotification));
  const entries = [
    ...feed.items.filter((n) => !unread.has(n.id)).map(ofNotification),
    ...announcements.map(
      (a): BellEntry => ({
        key: `a:${a.id}`,
        source: "announcement",
        id: a.id,
        body: a.body,
        createdAt: a.starts_at,
        oldestAt: a.starts_at,
        read: a.read,
        security: false,
        markable: true,
        count: 1,
        memberIds: [a.id],
      }),
    ),
  ].sort(byNewest);
  return {entries, security};
}

export function useBellData(): BellData {
  const notifications = useNotificationFeed();
  const announcements = useAnnouncementFeed();
  const markNotification = useMarkNotificationRead();
  const markGroup = useMarkNoticeGroup();
  const markAnnouncement = useMarkAnnouncementRead();

  const model = useMemo(
    () => bellModel({items: notifications.items, securityItems: notifications.securityItems}, announcements.items),
    [notifications.items, notifications.securityItems, announcements.items],
  );

  const {mutate: readNotification} = markNotification;
  const {mutate: readAnnouncement} = markAnnouncement;
  const markRead = useCallback(
    (entry: BellEntry) => {
      // The API refuses a security notice the session may not clear (409), and nothing would change. The page does not ask.
      if (!entry.markable) return;
      // A security group is sent one id after another and in a bounded number (webi-r2-3, webi-r2-8); an ordinary notice is one call.
      if (entry.source === "notification") {
        if (entry.security) markGroup(entry.memberIds);
        else readNotification(entry.id);
      } else readAnnouncement(entry.id);
    },
    [readNotification, readAnnouncement, markGroup],
  );

  const {fetchNextPage} = notifications;
  const loadMore = useCallback(() => void fetchNextPage(), [fetchNextPage]);

  return {
    ...model,
    unread: notifications.unread + notifications.securityUnread + announcements.unread,
    markRead,
    hasMore: notifications.hasNextPage,
    moreUnread: notifications.moreUnread,
    loadingMore: notifications.isFetchingNextPage,
    loadMore,
  };
}

/**
 * `link` comes from the API and is free text in the database, so it is followed
 * only when the same rules that guard the login `next` value accept it (spec 8.5):
 * one leading slash, no `//` anywhere (also after a decode), no backslash, scheme
 * or control character, no `.` or `..` segment however it is written, and a known
 * panel prefix. A prefix and "starts with one slash" are not enough: the URL parser
 * turns `/..//host` into `//host`, a protocol-relative URL that leaves the origin
 * (wp4-r17-1). One validator for both places means they cannot drift apart.
 */
export function safeInternalPath(link: string | undefined | null): string | undefined {
  return sanitizeNext(link, PANEL_PROTECTED_PREFIXES);
}
