"use client";

import {useAnnouncementFeed, useMarkAnnouncementRead} from "@ctrlz/api-client/hooks/announcements.ts";
import {useMarkNotificationRead, useNotificationFeed} from "@ctrlz/api-client/hooks/notifications.ts";
import {useCallback, useMemo} from "react";

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
  read: boolean;
};

export type BellData = {
  entries: BellEntry[];
  /** NotificationPage.unread_count plus AnnouncementPage.unread_count. Never counted from `entries`, which is one page. */
  unread: number;
  markRead: (entry: BellEntry) => void;
};

/** Newest first. A date that does not parse sorts last, so one bad row cannot hide the rest. */
function byNewest(a: BellEntry, b: BellEntry): number {
  const ta = Date.parse(a.createdAt);
  const tb = Date.parse(b.createdAt);
  return (Number.isNaN(tb) ? -Infinity : tb) - (Number.isNaN(ta) ? -Infinity : ta);
}

export function useBellData(): BellData {
  const notifications = useNotificationFeed();
  const announcements = useAnnouncementFeed();
  const markNotification = useMarkNotificationRead();
  const markAnnouncement = useMarkAnnouncementRead();

  const entries = useMemo<BellEntry[]>(
    () =>
      [
        ...notifications.items.map(
          (n): BellEntry => ({
            key: `n:${n.id}`,
            source: "notification",
            id: n.id,
            kind: n.kind,
            params: n.params,
            severity: n.severity,
            link: n.link,
            createdAt: n.created_at,
            read: n.read_at !== undefined,
          }),
        ),
        ...announcements.items.map(
          (a): BellEntry => ({
            key: `a:${a.id}`,
            source: "announcement",
            id: a.id,
            body: a.body,
            createdAt: a.starts_at,
            read: a.read,
          }),
        ),
      ].sort(byNewest),
    [notifications.items, announcements.items],
  );

  const {mutate: readNotification} = markNotification;
  const {mutate: readAnnouncement} = markAnnouncement;
  const markRead = useCallback(
    (entry: BellEntry) => (entry.source === "notification" ? readNotification(entry.id) : readAnnouncement(entry.id)),
    [readNotification, readAnnouncement],
  );

  return {entries, unread: notifications.unread + announcements.unread, markRead};
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
