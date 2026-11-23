"use client";

// What the bell and the banners read. The real source is WP4's hooks
// (GET /notifications and GET /announcements, merged newest first, polled every
// 60 s while the tab is visible, spec 8.5). Until they exist this returns an
// empty list, so the bell shows its empty state and no badge.

export type BellEntry = {
  /** Unique across both sources: `n:<id>` or `a:<id>`. */
  key: string;
  source: "notification" | "announcement";
  id: string;
  /** Notifications only: picks `shell.bell.kinds.<kind>`. */
  kind?: string;
  /** Notifications only: ICU params. Escaped by ICU, never HTML. */
  params?: Record<string, string | number>;
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

const EMPTY: BellData = {entries: [], unread: 0, markRead: () => undefined};

export function useBellData(): BellData {
  return EMPTY;
}

/**
 * `link` comes from the API and is followed only when it is an app path: one
 * leading slash, not `//`, no backslash (spec 8.5). Anything else is ignored.
 */
export function safeInternalPath(link: string | undefined | null): string | undefined {
  if (!link) return undefined;
  if (!link.startsWith("/") || link.startsWith("//") || link.includes("\\")) return undefined;
  if (/[\u0000-\u001f\u007f]/.test(link)) return undefined;
  return link;
}
