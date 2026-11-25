import {afterEach, beforeEach, describe, expect, it, vi} from "vitest";

// The hooks use the app's one client, whose base URL is a path (`/api/v1`) that
// only a browser can resolve. Before the client module loads, give `Request` an
// origin and `fetch` a fake server. openapi-fetch reads both when it is created.
const server = vi.hoisted(() => {
  const BaseRequest = globalThis.Request;
  class AppRequest extends BaseRequest {
    constructor(input: RequestInfo | URL, init?: RequestInit) {
      super(typeof input === "string" && input.startsWith("/") ? `http://app.test${input}` : input, init);
    }
  }
  globalThis.Request = AppRequest as typeof Request;

  type Seen = {method: string; path: string; query: URLSearchParams; body: unknown; keepalive: boolean};
  const state = {
    seen: [] as Seen[],
    answer: (() => new Response(null, {status: 404})) as (s: Seen) => Response,
  };
  globalThis.fetch = (async (request: Request) => {
    const url = new URL(request.url);
    const text = request.body ? await request.clone().text() : "";
    const seen: Seen = {
      method: request.method,
      path: url.pathname.replace("/api/v1", ""),
      query: url.searchParams,
      body: text ? JSON.parse(text) : undefined,
      keepalive: request.keepalive,
    };
    state.seen.push(seen);
    return state.answer(seen);
  }) as typeof fetch;
  return state;
});

import {MutationObserver, QueryClient, QueryClientProvider, QueryObserver} from "@tanstack/react-query";
import {createElement, type ReactNode} from "react";
import {renderToString} from "react-dom/server";

import {ADMIN_SESSION_IDLE_MS, getIdleState, refetchWhenPresent, subscribeIdleState, watchActivity, type SharedPresence} from "../activity.ts";
import {ApiError, errorMessageKey} from "../errors.ts";
import {bindSession, clearLeaving} from "../session.ts";
import {
  announcementFixture,
  meFixture,
  notificationFixture,
  securityNoticeFixture,
  type Announcement,
  type Me,
  type Notification,
} from "../testing/fixtures.ts";
import {
  announcementKeys,
  announcementsQueryOptions,
  isAnnouncementLive,
  markAnnouncementRead,
  markAnnouncementReadOptions,
} from "./announcements.ts";
import {meKeys, meQueryOptions, useLogout, useSession, type Session} from "./me.ts";
import {
  flattenNotifications,
  markNotificationRead,
  MARK_PER_PRESS,
  markNotificationReadOptions,
  markNotificationsReadOptions,
  needsMorePages,
  notificationKeys,
  notificationsQueryOptions,
  notificationUnread,
  POLL_MS,
  securityNotices,
  securityUnread,
  unreadPastCap,
} from "./notifications.ts";
import {dismissedOnboardingState, dismissOnboarding, isOnboardingDismissed, updatePreferences, useOnboarding} from "./preferences.ts";
import {publicConfigQueryOptions} from "./config.ts";
import {logoutAllMutationOptions, sessionKeys, sessionsQueryOptions} from "./sessions.ts";
import {passkeyKeys, passkeyMutationOptions, passkeysQueryOptions} from "./passkeys.ts";
import {adminMeQueryOptions, deriveAdminSession, leaveEndedAdminSession, startAdminGuard, useAdminLogout} from "../admin/session.ts";
import {adminMeFixture} from "../testing/fixtures.ts";

const json = (status: number, body?: unknown, headers: Record<string, string> = {}) =>
  new Response(body === undefined ? null : JSON.stringify(body), {status, headers: {"content-type": "application/json", ...headers}});

beforeEach(() => {
  server.seen.length = 0;
  server.answer = () => new Response(null, {status: 404});
});

const newClient = () => new QueryClient({defaultOptions: {queries: {retry: false, retryOnMount: false}}});

/** First render of a hook against a prepared cache. SSR never fetches, so this reads what the cache holds. */
function renderHook<T>(client: QueryClient, hook: () => T): T {
  let out!: T;
  function Probe(): ReactNode {
    out = hook();
    return null;
  }
  renderToString(createElement(QueryClientProvider, {client}, createElement(Probe)));
  return out;
}

describe("useSession", () => {
  it("reads /me from the cache as a status", () => {
    const cases: [Me, Session["status"]][] = [
      [meFixture(), "ready"],
      [meFixture({user: {must_reset: true}}), "restricted"],
      [meFixture({tenant: {status: "suspended"}}), "suspended"],
      [meFixture({tenant: {status: "deleting"}}), "anonymous"],
    ];
    for (const [me, status] of cases) {
      const client = newClient();
      client.setQueryData(meKeys.all, me);
      const session = renderHook(client, useSession);
      expect(session.status).toBe(status);
    }
  });

  it("is loading with an empty cache", () => {
    expect(renderHook(newClient(), useSession)).toMatchObject({status: "loading", me: undefined});
  });

  it("is anonymous after a session_expired answer and error after a 503", async () => {
    const gone = newClient();
    server.answer = (s) => (s.path === "/me" ? json(401, {code: "session_expired"}) : json(401, {code: "session_expired"}));
    await gone.fetchQuery({...meQueryOptions(), retry: false}).catch(() => undefined);
    expect(renderHook(gone, useSession).status).toBe("anonymous");

    const down = newClient();
    server.answer = () => json(503, {code: "service_unavailable"});
    await down.fetchQuery({...meQueryOptions(), retry: false}).catch(() => undefined);
    expect(renderHook(down, useSession).status).toBe("error");
  });
});

describe("/me query", () => {
  it("asks again when the tab comes back, and soon enough for revocation to show", () => {
    const o = meQueryOptions();
    // A function, not true: only while a person is at the page (activity.ts, wp4-r3-7).
    expect(o.refetchOnWindowFocus).toBe(refetchWhenPresent);
    expect(refetchWhenPresent()).toBe(true);
    expect(o.staleTime).toBeLessThanOrEqual(30_000);
  });

  it("sends GET /me and keeps the answer in the cache under the me key", async () => {
    server.answer = () => json(200, meFixture());
    const client = newClient();
    await client.fetchQuery(meQueryOptions());
    expect(server.seen).toEqual([{keepalive: false, method: "GET", path: "/me", query: expect.any(URLSearchParams), body: undefined}]);
    expect(client.getQueryData(meKeys.all)).toEqual(meFixture());
  });

  it("applies the retry rule: a 503 is retried, a 401 is not", () => {
    const retry = meQueryOptions().retry as (n: number, e: unknown) => boolean;
    expect(retry(0, new ApiError(503, "service_unavailable"))).toBe(true);
    expect(retry(0, new ApiError(401, "session_expired"))).toBe(false);
  });
});

describe("notifications", () => {
  const read = (over: Partial<Notification> = {}) => notificationFixture({read_at: "2026-11-10T09:00:00Z", ...over});

  it("polls every 60 s and pages by next_cursor", async () => {
    expect((notificationsQueryOptions().refetchInterval as () => number | false)()).toBe(POLL_MS);
    expect(POLL_MS).toBe(60_000);
    server.answer = (s) =>
      s.query.get("cursor") === "c2"
        ? json(200, {items: [notificationFixture({id: "00000000-0000-4000-8000-0000000000bb"})], unread_count: 2, security_items: [], security_unread_count: 0})
        : json(200, {items: [notificationFixture({id: "00000000-0000-4000-8000-0000000000aa"})], next_cursor: "c2", unread_count: 2, security_items: [], security_unread_count: 0});
    const client = newClient();
    const o = notificationsQueryOptions();
    const first = await client.fetchInfiniteQuery({...o, pages: 2});
    expect(flattenNotifications(first).map((n) => n.id)).toEqual([
      "00000000-0000-4000-8000-0000000000aa",
      "00000000-0000-4000-8000-0000000000bb",
    ]);
    expect(server.seen.map((s) => s.query.get("cursor"))).toEqual([null, "c2"]);
    expect(server.seen[0]!.query.get("limit")).toBe("50");
  });

  it("counts unread from the first page's figure, which covers every row", () => {
    const data = {pages: [{items: [notificationFixture()], unread_count: 7, security_items: [], security_unread_count: 0}, {items: [], unread_count: 7, security_items: [], security_unread_count: 0}], pageParams: [undefined, "c"]};
    expect(notificationUnread(data)).toBe(7);
    expect(notificationUnread(undefined)).toBe(0);
  });

  it("marks one read and lowers the count once, never below zero, and never for one already read", () => {
    const a = notificationFixture();
    const b = read();
    const data = {pages: [{items: [a, b], unread_count: 1, security_items: [], security_unread_count: 0}], pageParams: [undefined]};
    const once = markNotificationRead(data, a.id, new Date("2026-11-11T00:00:00Z"))!;
    expect(once.pages[0]!.items[0]!.read_at).toBe("2026-11-11T00:00:00.000Z");
    expect(once.pages[0]!.unread_count).toBe(0);
    expect(markNotificationRead(once, a.id, new Date())).toBe(once);
    expect(markNotificationRead(data, b.id, new Date())).toBe(data);
    expect(markNotificationRead(data, "missing", new Date())).toBe(data);
    expect(markNotificationRead({pages: [{items: [a], unread_count: 0, security_items: [], security_unread_count: 0}], pageParams: [undefined]}, a.id, new Date())!.pages[0]!.unread_count).toBe(0);
    // The input is not changed.
    expect(data.pages[0]!.unread_count).toBe(1);
  });

  it("shows the read at once, calls POST /notifications/{id}/read, and refetches", async () => {
    const n = notificationFixture();
    const client = newClient();
    client.setQueryData(notificationKeys.list, {pages: [{items: [n], unread_count: 1, security_items: [], security_unread_count: 0}], pageParams: [undefined]});
    let during: number | undefined;
    server.answer = (s) => {
      if (s.method === "POST") {
        during = notificationUnread(client.getQueryData(notificationKeys.list));
        return new Response(null, {status: 204});
      }
      return json(200, {items: [{...n, read_at: "2026-11-11T00:00:00Z"}], unread_count: 0, security_items: [], security_unread_count: 0});
    };
    await new MutationObserver(client, markNotificationReadOptions(client)).mutate(n.id);
    expect(during).toBe(0);
    expect(server.seen[0]).toMatchObject({method: "POST", path: `/notifications/${n.id}/read`});
    expect(notificationUnread(client.getQueryData(notificationKeys.list))).toBe(0);
  });

  it("puts the unread state back when the call fails", async () => {
    const n = notificationFixture();
    const client = newClient();
    const before = {pages: [{items: [n], unread_count: 1, security_items: [], security_unread_count: 0}], pageParams: [undefined]};
    client.setQueryData(notificationKeys.list, before);
    server.answer = (s) => (s.method === "POST" ? json(500, {code: "internal"}) : json(200, {items: [n], unread_count: 1, security_items: [], security_unread_count: 0}));
    await new MutationObserver(client, markNotificationReadOptions(client)).mutate(n.id).catch(() => undefined);
    expect(notificationUnread(client.getQueryData(notificationKeys.list))).toBe(1);
    expect(flattenNotifications(client.getQueryData(notificationKeys.list))[0]!.read_at).toBeUndefined();
  });
});

describe("security notices (Question 19)", () => {
  const page = (over: Partial<{items: Notification[]; unread_count: number; security_items: Notification[]; security_unread_count: number}> = {}) => ({
    items: [],
    unread_count: 0,
    security_items: [],
    security_unread_count: 0,
    ...over,
  });

  it("reads the block and its count from the first page, and the count is not the ordinary one", () => {
    const sec = [securityNoticeFixture(), securityNoticeFixture({kind: "recovery_codes_regenerated"})];
    const data = {pages: [page({unread_count: 3, security_items: sec, security_unread_count: 2}), page({unread_count: 3, security_items: sec, security_unread_count: 2})], pageParams: [undefined, "c"]};
    expect(securityNotices(data).map((n) => n.id)).toEqual(sec.map((n) => n.id));
    expect(securityUnread(data)).toBe(2);
    expect(notificationUnread(data)).toBe(3);
    expect(securityNotices(undefined)).toEqual([]);
    expect(securityUnread(undefined)).toBe(0);
  });

  it("marking one takes it out of the block on every page and lowers only the security count, never the ordinary one", () => {
    const sec = securityNoticeFixture();
    const other = securityNoticeFixture();
    const plain = notificationFixture();
    const data = {
      pages: [page({items: [plain], unread_count: 1, security_items: [sec, other], security_unread_count: 2}), page({security_items: [sec, other], security_unread_count: 2})],
      pageParams: [undefined, "c"],
    };
    const next = markNotificationRead(data, sec.id, new Date("2026-11-13T00:00:00Z"))!;
    for (const p of next.pages) {
      expect(p.security_items.map((n) => n.id)).toEqual([other.id]);
      expect(p.security_unread_count).toBe(1);
    }
    expect(next.pages[0]!.unread_count).toBe(1);
    expect(next.pages[0]!.items[0]!.read_at).toBeUndefined();
    // The input is not changed.
    expect(data.pages[0]!.security_items).toHaveLength(2);
    // A second mark finds nothing to change.
    expect(markNotificationRead(next, sec.id, new Date())).toBe(next);
  });

  it("an unread security notice past the newest 50 sits in the list and is counted by the ordinary figure", () => {
    const past = securityNoticeFixture({markable: false});
    const data = {pages: [page({items: [past], unread_count: 1})], pageParams: [undefined]};
    const next = markNotificationRead(data, past.id, new Date("2026-11-13T00:00:00Z"))!;
    expect(next.pages[0]!.items[0]!.read_at).toBe("2026-11-13T00:00:00.000Z");
    expect(next.pages[0]!.unread_count).toBe(0);
  });

  // webi-r1-6: unread_count is over every row, so it says when an unread notice is on a page that is not loaded.
  it("asks for the next page while unread_count is above the unread rows loaded, and stops at the cap", () => {
    const past = securityNoticeFixture({markable: false});
    const unreadRows = Array.from({length: 3}, () => notificationFixture());
    const first = {pages: [page({items: unreadRows, unread_count: 4})], pageParams: [undefined]};
    expect(needsMorePages(first, true)).toBe(true);
    // The page that holds the fourth one arrives: nothing is missing any more.
    const second = {pages: [first.pages[0]!, page({items: [past]})], pageParams: [undefined, "c"]};
    expect(needsMorePages(second, true)).toBe(false);
    // A read row does not count as unread, and no next page means nothing to ask for.
    const read = {pages: [page({items: [notificationFixture({read_at: "2026-11-13T00:00:00Z"})], unread_count: 1})], pageParams: [undefined]};
    expect(needsMorePages(read, true)).toBe(true);
    expect(needsMorePages(read, false)).toBe(false);
    expect(needsMorePages(undefined, true)).toBe(false);
    // A count that never matches ends at the cap.
    expect(needsMorePages(first, true, 1)).toBe(false);
    // webi-r2-6: once the cap is reached with unread notices still unloaded, the panel says so; before the cap it just pages.
    expect(unreadPastCap(first, true, 1)).toBe(true);
    expect(unreadPastCap(first, true)).toBe(false);
    expect(unreadPastCap(first, false, 1)).toBe(false);
    expect(unreadPastCap(second, true, 1)).toBe(false);
    expect(unreadPastCap(undefined, true, 1)).toBe(false);
  });

  it("a 409 from the API puts the block back and marks the list stale, so it is asked again, with one POST and no retry", async () => {
    const sec = securityNoticeFixture({markable: false});
    const client = newClient();
    const before = {pages: [page({security_items: [sec], security_unread_count: 1})], pageParams: [undefined]};
    client.setQueryData(notificationKeys.list, before);
    server.answer = (s) => (s.method === "POST" ? json(409, {code: "conflict"}) : json(200, page({security_items: [sec], security_unread_count: 1})));
    await new MutationObserver(client, markNotificationReadOptions(client)).mutate(sec.id).catch(() => undefined);
    expect(securityUnread(client.getQueryData(notificationKeys.list))).toBe(1);
    expect(securityNotices(client.getQueryData(notificationKeys.list)).map((n) => n.id)).toEqual([sec.id]);
    expect(server.seen.filter((c) => c.method === "POST")).toHaveLength(1);
    // The list is invalidated by the settle, so an active observer refetches; here the cache is marked stale.
    expect(client.getQueryState(notificationKeys.list)?.isInvalidated).toBe(true);
  });

  // webi-r2-3, webi-r2-8: a group of hundreds must not be sent as hundreds of parallel calls against 60 writes a minute.
  it("marks a group one id after another, stops at the first refusal and asks for the list once at the end", async () => {
    const notes = Array.from({length: 4}, () => securityNoticeFixture({kind: "recovery_codes_regenerated"}));
    const client = newClient();
    client.setQueryData(notificationKeys.list, {pages: [page({security_items: notes, security_unread_count: 4})], pageParams: [undefined]});
    let posts = 0;
    server.answer = (s) => {
      if (s.method !== "POST") return json(200, page({security_items: notes, security_unread_count: 4}));
      posts += 1;
      return posts === 3 ? json(429, {code: "rate_limited"}, {"retry-after": "30"}) : new Response(null, {status: 204});
    };
    const error = await new MutationObserver(client, markNotificationsReadOptions(client)).mutate(notes.map((n) => n.id)).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    // The third call was refused and the fourth never sent; the two that passed are cleared in the cache.
    expect(server.seen.filter((c) => c.method === "POST")).toHaveLength(3);
    expect(securityNotices(client.getQueryData(notificationKeys.list)).map((n) => n.id)).toEqual([notes[2]!.id, notes[3]!.id]);
    expect(securityUnread(client.getQueryData(notificationKeys.list))).toBe(2);
    expect(client.getQueryState(notificationKeys.list)?.isInvalidated).toBe(true);
  });

  // webi-r3-2, webi-r3-4: a 409 is the verdict having moved for one notice, not a failure of the press and not a rate limit.
  it("skips a notice that answers 409, keeps it in the block, and says nothing is left for it", async () => {
    const notes = Array.from({length: 3}, () => securityNoticeFixture({kind: "recovery_codes_regenerated"}));
    const client = newClient();
    client.setQueryData(notificationKeys.list, {pages: [page({security_items: notes, security_unread_count: 3})], pageParams: [undefined]});
    server.answer = (s) => {
      if (s.method !== "POST") return json(200, page({security_items: notes, security_unread_count: 3}));
      return s.path === `/notifications/${notes[1]!.id}/read` ? json(409, {code: "conflict"}) : new Response(null, {status: 204});
    };
    const result = await new MutationObserver(client, markNotificationsReadOptions(client)).mutate(notes.map((n) => n.id));
    expect(result).toEqual({done: 2, left: 0});
    expect(server.seen.filter((c) => c.method === "POST")).toHaveLength(3);
    expect(securityNotices(client.getQueryData(notificationKeys.list)).map((n) => n.id)).toEqual([notes[1]!.id]);
    expect(securityUnread(client.getQueryData(notificationKeys.list))).toBe(1);
    expect(client.getQueryState(notificationKeys.list)?.isInvalidated).toBe(true);
  });

  it("a single notice that answers 409 resolves with nothing done, and any other failure is still thrown", async () => {
    const sec = securityNoticeFixture();
    const client = newClient();
    client.setQueryData(notificationKeys.list, {pages: [page({security_items: [sec], security_unread_count: 1})], pageParams: [undefined]});
    server.answer = (s) => (s.method === "POST" ? json(409, {code: "conflict"}) : json(200, page({security_items: [sec], security_unread_count: 1})));
    await expect(new MutationObserver(client, markNotificationsReadOptions(client)).mutate([sec.id])).resolves.toEqual({done: 0, left: 0});
    server.answer = (s) => (s.method === "POST" ? json(500, {code: "internal"}) : json(200, page()));
    await expect(new MutationObserver(client, markNotificationsReadOptions(client)).mutate([sec.id])).rejects.toBeInstanceOf(ApiError);
  });

  it("sends at most MARK_PER_PRESS marks in one press and says how many are left", async () => {
    const notes = Array.from({length: MARK_PER_PRESS + 5}, () => securityNoticeFixture());
    const client = newClient();
    client.setQueryData(notificationKeys.list, {pages: [page({security_items: notes.slice(0, 50), security_unread_count: notes.length})], pageParams: [undefined]});
    server.answer = (s) => (s.method === "POST" ? new Response(null, {status: 204}) : json(200, page()));
    const result = await new MutationObserver(client, markNotificationsReadOptions(client)).mutate(notes.map((n) => n.id));
    expect(result).toEqual({done: MARK_PER_PRESS, left: 5});
    expect(server.seen.filter((c) => c.method === "POST")).toHaveLength(MARK_PER_PRESS);
  });
});

describe("announcements", () => {
  const now = new Date("2026-11-10T12:00:00Z");

  it("is live from starts_at to ends_at inclusive, and with no end it does not end", () => {
    expect(isAnnouncementLive({starts_at: "2026-11-10T12:00:00Z"}, now)).toBe(true);
    expect(isAnnouncementLive({starts_at: "2026-11-10T12:00:01Z"}, now)).toBe(false);
    expect(isAnnouncementLive({starts_at: "2026-11-01T00:00:00Z", ends_at: "2026-11-10T12:00:00Z"}, now)).toBe(true);
    expect(isAnnouncementLive({starts_at: "2026-11-01T00:00:00Z", ends_at: "2026-11-10T11:59:59Z"}, now)).toBe(false);
    expect(isAnnouncementLive({starts_at: "2026-11-01T00:00:00Z"}, now)).toBe(true);
  });

  it("marks one read and lowers the count once", () => {
    const a = announcementFixture();
    const data = {pages: [{items: [a], unread_count: 1}], pageParams: [undefined]};
    const next = markAnnouncementRead(data, a.id)!;
    expect(next.pages[0]!.items[0]!.read).toBe(true);
    expect(next.pages[0]!.unread_count).toBe(0);
    expect(markAnnouncementRead(next, a.id)).toBe(next);
  });

  it("polls like the bell, and its mutation calls the read route and rolls back on failure", async () => {
    expect((announcementsQueryOptions().refetchInterval as () => number | false)()).toBe(POLL_MS);
    const a = announcementFixture();
    const client = newClient();
    client.setQueryData(announcementKeys.list, {pages: [{items: [a], unread_count: 1}], pageParams: [undefined]});
    server.answer = (s) => (s.method === "POST" ? json(500, {code: "internal"}) : json(200, {items: [a], unread_count: 1}));
    await new MutationObserver(client, markAnnouncementReadOptions(client)).mutate(a.id).catch(() => undefined);
    expect(server.seen[0]).toMatchObject({method: "POST", path: `/announcements/${a.id}/read`});
    const data = client.getQueryData<{pages: {items: Announcement[]; unread_count: number}[]}>(announcementKeys.list)!;
    expect(data.pages[0]!.items[0]!.read).toBe(false);
  });
});

describe("preferences and onboarding", () => {
  it("PATCHes only what is given and puts the answered Me into the /me cache", async () => {
    const updated = meFixture({user: {locale: "en"}});
    server.answer = () => json(200, updated);
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    await updatePreferences(client, {locale: "en"});
    expect(server.seen[0]).toMatchObject({method: "PATCH", path: "/account/preferences", body: {locale: "en"}});
    expect(client.getQueryData(meKeys.all)).toEqual(updated);
  });

  // wp4-r5-1: a /me that was asked before the PATCH answers with the old Me, and must not land over the new one.
  it("a /me that was already in flight does not overwrite the answer of the PATCH", async () => {
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture({user: {theme: "light"}}));
    let release!: () => void;
    const slow = new Promise<void>((resolve) => (release = resolve));
    server.answer = ((s: {method: string}) =>
      s.method === "GET"
        ? slow.then(() => json(200, meFixture({user: {theme: "light"}})))
        : json(200, meFixture({user: {theme: "dark"}}))) as never;
    const inFlight = client.fetchQuery({...meQueryOptions(), staleTime: 0}).catch(() => undefined);
    await vi.waitFor(() => expect(server.seen.some((s) => s.method === "GET" && s.path === "/me")).toBe(true));

    await updatePreferences(client, {theme: "dark"});
    release();
    await inFlight;
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(client.getQueryData<Me>(meKeys.all)?.user.theme).toBe("dark");
  });

  // wp4-r9-2: every write answers with a whole Me. A server that applies two writes in the order they arrive
  // answers the first with the OLD value of the second one's field, so if that answer comes back last it
  // would be the one left in the cache. The writes go one after the other, so there is no such answer.
  describe("preference writes that overlap (wp4-r9-2)", () => {
    // A server that applies each PATCH when it arrives and lets the test choose when each answer leaves.
    function slowServer() {
      const state = {theme: "light", dismissed: false};
      const gates: Array<() => void> = [];
      let sent = 0;
      server.answer = ((s: {body: unknown}) => {
        sent++;
        const body = s.body as {theme?: string; onboarding_state?: unknown};
        if (body.theme) state.theme = body.theme;
        if (body.onboarding_state) state.dismissed = true;
        const me = meFixture({user: {theme: state.theme as never, onboarding_state: state.dismissed ? {v: 1, dismissed_at: "2026-11-10T00:00:00Z"} : {}}});
        return new Promise<Response>((resolve) => gates.push(() => resolve(json(200, me))));
      }) as never;
      return {gates, sent: () => sent};
    }

    /** Releases the newest waiting answer first, until nothing is left: the order a slow link can produce. */
    async function answerNewestFirst(gates: Array<() => void>, done: Promise<unknown>) {
      let settled = false;
      void done.then(() => (settled = true));
      for (let i = 0; i < 50 && !settled; i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
        gates.pop()?.();
      }
    }

    it("two different fields, answers in the reverse order: the cache keeps both changes", async () => {
      const client = newClient();
      client.setQueryData(meKeys.all, meFixture());
      const {gates, sent} = slowServer();
      const theme = updatePreferences(client, {theme: "dark"});
      const dismissal = updatePreferences(client, {onboarding_state: {v: 1, dismissed_at: "2026-11-10T00:00:00Z"}});
      await vi.waitFor(() => expect(gates.length).toBeGreaterThan(0));
      // The second write is not sent until the first has been answered.
      expect(sent()).toBe(1);
      await answerNewestFirst(gates, Promise.all([theme, dismissal]));
      const me = client.getQueryData<Me>(meKeys.all)!;
      expect(me.user.theme).toBe("dark");
      expect(isOnboardingDismissed(me.user.onboarding_state)).toBe(true);
    });

    it("the same field twice ends on the last choice", async () => {
      const client = newClient();
      client.setQueryData(meKeys.all, meFixture());
      const {gates} = slowServer();
      const first = updatePreferences(client, {theme: "dark"});
      const second = updatePreferences(client, {theme: "light"});
      await answerNewestFirst(gates, Promise.all([first, second]));
      expect(client.getQueryData<Me>(meKeys.all)!.user.theme).toBe("light");
    });

    it("a write that fails does not hold up the next one, and rejects only its own caller", async () => {
      const client = newClient();
      client.setQueryData(meKeys.all, meFixture());
      let n = 0;
      server.answer = (() => (++n === 1 ? json(503, {code: "server_busy"}) : json(200, meFixture({user: {theme: "dark"}})))) as never;
      const failing = updatePreferences(client, {theme: "dark"});
      const next = updatePreferences(client, {theme: "dark"});
      await expect(failing).rejects.toBeInstanceOf(ApiError);
      await expect(next).resolves.toMatchObject({user: {theme: "dark"}});
      expect(client.getQueryData<Me>(meKeys.all)!.user.theme).toBe("dark");
    });

    // wp4-r10-3: a request that never settles must not hold back every later write of the tab.
    it("a write that never settles times out, and the next one still goes out", async () => {
      const client = newClient();
      client.setQueryData(meKeys.all, meFixture());
      let n = 0;
      server.answer = (() => (++n === 1 ? new Promise<Response>(() => undefined) : json(200, meFixture({user: {theme: "light"}})))) as never;
      const stuck = updatePreferences(client, {theme: "dark"}, {timeoutMs: 40});
      const next = updatePreferences(client, {theme: "light"}, {timeoutMs: 40});
      await expect(stuck).rejects.toBeInstanceOf(ApiError);
      await expect(next).resolves.toMatchObject({user: {theme: "light"}});
      expect(server.seen).toHaveLength(2);
      expect(client.getQueryData<Me>(meKeys.all)!.user.theme).toBe("light");
    });

    // wp4-r11-1: aborting the fetch does not recall a request the server already has, so the write that timed
    // out can be applied after the next one. The cache must not keep believing the later write won.
    it("a write that timed out is followed by a read of /me, which puts the stored value back in the cache", async () => {
      const client = newClient();
      client.setQueryData(meKeys.all, meFixture());
      let patches = 0;
      server.answer = ((s: {method: string; path: string}) => {
        if (s.path === "/me") return json(200, meFixture({user: {theme: "dark"}})); // the stalled dark write landed last
        return ++patches === 1 ? new Promise<Response>(() => undefined) : json(200, meFixture({user: {theme: "light"}}));
      }) as never;
      const observer = new QueryObserver(client, meQueryOptions());
      const stopObserving = observer.subscribe(() => undefined);
      await vi.waitFor(() => expect(client.getQueryState(meKeys.all)?.fetchStatus).toBe("idle"));
      const readsBefore = server.seen.filter((s) => s.method === "GET" && s.path === "/me").length;

      const stuck = updatePreferences(client, {theme: "dark"}, {timeoutMs: 20, reconcileMs: 60});
      const next = updatePreferences(client, {theme: "light"}, {timeoutMs: 20, reconcileMs: 60});
      await expect(stuck).rejects.toBeInstanceOf(ApiError);
      await next;
      expect(client.getQueryData<Me>(meKeys.all)!.user.theme).toBe("light");
      await vi.waitFor(() => expect(client.getQueryData<Me>(meKeys.all)!.user.theme).toBe("dark"), {timeout: 2_000});
      expect(server.seen.filter((s) => s.method === "GET" && s.path === "/me").length).toBe(readsBefore + 1);
      stopObserving();
    });

    it("a write that succeeds schedules no read of /me", async () => {
      const client = newClient();
      client.setQueryData(meKeys.all, meFixture());
      server.answer = (() => json(200, meFixture({user: {theme: "dark"}}))) as never;
      const stopObserving = new QueryObserver(client, meQueryOptions()).subscribe(() => undefined);
      await vi.waitFor(() => expect(client.getQueryState(meKeys.all)?.fetchStatus).toBe("idle"));
      const readsBefore = server.seen.filter((s) => s.method === "GET" && s.path === "/me").length;
      await updatePreferences(client, {theme: "dark"}, {timeoutMs: 20, reconcileMs: 40});
      await new Promise((r) => setTimeout(r, 120));
      expect(server.seen.filter((s) => s.method === "GET" && s.path === "/me").length).toBe(readsBefore);
      stopObserving();
    });

    it("the language write skips a slow earlier write, and merges only its own field into the cache", async () => {
      const client = newClient();
      client.setQueryData(meKeys.all, meFixture({user: {theme: "dark", locale: "fa"}}));
      let release!: () => void;
      const slow = new Promise<void>((resolve) => (release = resolve));
      server.answer = ((s: {body: {theme?: string; locale?: string}}) =>
        s.body.theme
          ? slow.then(() => json(200, meFixture({user: {theme: "light", locale: "fa"}})))
          : json(200, meFixture({user: {theme: "dark", locale: "en"}}))) as never;
      const theme = updatePreferences(client, {theme: "light"});
      await vi.waitFor(() => expect(server.seen).toHaveLength(1));
      // Sent at once, while the theme write is still waiting for its answer.
      await updatePreferences(client, {locale: "en"}, {immediate: true});
      expect(server.seen.map((s) => s.body)).toEqual([{theme: "light"}, {locale: "en"}]);
      // The locale answer carried the older theme; it must not have been put in the cache.
      expect(client.getQueryData<Me>(meKeys.all)!.user).toMatchObject({theme: "dark", locale: "en"});
      release();
      await theme;
      expect(client.getQueryData<Me>(meKeys.all)!.user.theme).toBe("light");
    });

    it("the onboarding body is built when its turn comes, from the newest cache, not when it was asked for", async () => {
      const client = newClient();
      client.setQueryData(meKeys.all, meFixture({user: {onboarding_state: {v: 1, tutorial_seen_at: "2026-11-01T00:00:00Z"}}}));
      let n = 0;
      server.answer = (() => {
        // The first write puts a new key in the stored state; the dismissal queued behind it must keep it.
        if (++n === 1) return json(200, meFixture({user: {onboarding_state: {v: 1, tutorial_seen_at: "2026-11-01T00:00:00Z", checklist_done: 2}}}));
        return json(200, meFixture());
      }) as never;
      const first = updatePreferences(client, {onboarding_state: {v: 1, tutorial_seen_at: "2026-11-01T00:00:00Z", checklist_done: 2}});
      const dismissal = dismissOnboarding(client, new Date("2026-11-10T00:00:00Z"));
      await Promise.all([first, dismissal]);
      expect(server.seen[1]?.body).toEqual({
        onboarding_state: {v: 1, tutorial_seen_at: "2026-11-01T00:00:00Z", checklist_done: 2, dismissed_at: "2026-11-10T00:00:00.000Z"},
      });
    });
  });

  it("dismisses by sending the whole onboarding_state, keeping what was there, with no null", () => {
    const state = dismissedOnboardingState({v: 1, tutorial_seen_at: "2026-11-01T00:00:00Z", custom: 3}, new Date("2026-11-10T00:00:00Z"));
    expect(state).toEqual({v: 1, tutorial_seen_at: "2026-11-01T00:00:00Z", custom: 3, dismissed_at: "2026-11-10T00:00:00.000Z"});
    expect(Object.values(state).every((v) => v !== null)).toBe(true);
    expect(dismissedOnboardingState(undefined, new Date(0))).toEqual({v: 1, dismissed_at: "1970-01-01T00:00:00.000Z"});
  });

  it("knows a dismissal when dismissed_at is a non-empty string", () => {
    expect(isOnboardingDismissed({v: 1, dismissed_at: "2026-11-10T00:00:00Z"})).toBe(true);
    for (const state of [undefined, {}, {dismissed_at: ""}, {dismissed_at: 5}, {dismissed_at: false}] as const) expect(isOnboardingDismissed(state as never)).toBe(false);
  });

  it("shows the card for a user with hints on who has not dismissed it", () => {
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    expect(renderHook(client, useOnboarding)).toMatchObject({hintsEnabled: true, dismissed: false});
  });

  it("hides it when dismissed, and when hints are off, without calling that a dismissal", () => {
    const dismissed = newClient();
    dismissed.setQueryData(meKeys.all, meFixture({user: {onboarding_state: {v: 1, dismissed_at: "2026-11-10T00:00:00Z"}}}));
    expect(renderHook(dismissed, useOnboarding)).toMatchObject({hintsEnabled: true, dismissed: true});

    const off = newClient();
    off.setQueryData(meKeys.all, meFixture({user: {onboarding_hints: {enabled: false}}}));
    expect(renderHook(off, useOnboarding)).toMatchObject({hintsEnabled: false, dismissed: false});
  });

  it("stays hidden until /me is known, so the card does not flash", () => {
    expect(renderHook(newClient(), useOnboarding)).toMatchObject({hintsEnabled: false, dismissed: true});
  });

  it("dismiss PATCHes the stored state plus dismissed_at", async () => {
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture({user: {onboarding_state: {v: 1, tutorial_seen_at: "2026-11-01T00:00:00Z"}}}));
    server.answer = (s) => json(200, meFixture({user: {onboarding_state: s.body as Record<string, string | number>}}));
    const {dismiss} = renderHook(client, useOnboarding);
    await dismiss();
    const body = server.seen[0]!.body as Record<string, unknown>;
    expect(server.seen[0]).toMatchObject({method: "PATCH", path: "/account/preferences"});
    expect(body).toHaveProperty("onboarding_state");
    expect(body.onboarding_state).toMatchObject({v: 1, tutorial_seen_at: "2026-11-01T00:00:00Z"});
    expect(typeof (body.onboarding_state as {dismissed_at: unknown}).dismissed_at).toBe("string");
    expect(Object.keys(body)).toEqual(["onboarding_state"]);
  });
});

describe("the other queries read the routes of the spec", () => {
  it.each([
    ["public config", publicConfigQueryOptions(), "/auth/config", {registration_mode: "open", sms_available: true, passkey_enabled: false}],
    ["sessions", sessionsQueryOptions(), "/account/sessions", {sessions: []}],
    ["passkeys", passkeysQueryOptions(), "/account/passkeys", {passkeys: []}],
  ] as const)("%s: GET %s", async (_name, options, path, body) => {
    server.answer = () => json(200, body);
    const client = newClient();
    await client.fetchQuery(options as never);
    expect(server.seen[0]).toMatchObject({method: "GET", path});
  });
});

describe("admin session", () => {
  it("is setup for a one-time password or a missing authenticator, ready otherwise, anonymous on session_expired", () => {
    const status = (data: ReturnType<typeof adminMeFixture> | undefined, error: unknown = null, isPending = false) =>
      deriveAdminSession({data, error, isPending}).status;
    expect(status(adminMeFixture())).toBe("ready");
    expect(status(adminMeFixture({must_change_password: true}))).toBe("setup");
    expect(status(adminMeFixture({totp_enrolled: false}))).toBe("setup");
    expect(status(undefined, new ApiError(401, "session_expired"))).toBe("anonymous");
    expect(status(undefined, new ApiError(503, "service_unavailable"))).toBe("error");
    expect(status(undefined, null, true)).toBe("loading");
    // A known answer survives a failed refetch.
    expect(status(adminMeFixture(), new TypeError("offline"))).toBe("ready");
  });

  it("reads /me of the admin API and has no refresh behind it", async () => {
    server.answer = () => json(401, {code: "session_expired"});
    const client = newClient();
    await client.fetchQuery(adminMeQueryOptions()).catch(() => undefined);
    expect(server.seen.map((s) => s.path)).toEqual(["/me"]);
  });
});

// The session sequences of spec 14.4, through the hooks and the real client against the fake server.
describe("leaving the session", () => {
  let assigned: string[];

  beforeEach(() => {
    assigned = [];
    clearLeaving();
    vi.stubGlobal("window", {location: {assign: (url: string) => assigned.push(url), pathname: "/fa/preferences/account"}});
    vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
  });

  afterEach(() => {
    clearLeaving();
    vi.unstubAllGlobals();
  });

  const calls = () => server.seen.map((s) => `${s.method} ${s.path}`);

  it("useLogout: POST /auth/logout, clear the cache, load the login page", async () => {
    server.answer = () => new Response(null, {status: 204});
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    await renderHook(client, () => useLogout("fa"))();
    expect(calls()).toEqual(["POST /auth/logout"]);
    expect(client.getQueryCache().getAll()).toHaveLength(0);
    expect(assigned).toEqual(["/fa/login"]);
  });

  it("useLogout with a dead session: refresh once, end the session it brings back, then leave", async () => {
    // The 30-day refresh cookie can outlive the session cookie, and the 401 of a dead session clears nothing.
    let sessionLive = false;
    server.answer = (s) => {
      if (s.path === "/auth/refresh") {
        sessionLive = true;
        return new Response(null, {status: 204});
      }
      return sessionLive ? new Response(null, {status: 204}) : json(401, {code: "session_expired"});
    };
    await renderHook(newClient(), () => useLogout("en"))();
    expect(calls()).toEqual(["POST /auth/logout", "POST /auth/refresh", "POST /auth/logout"]);
    expect(assigned).toEqual(["/en/login"]);
  });

  it("useLogout with nothing left to refresh: the refresh says 401 and the user leaves", async () => {
    server.answer = () => json(401, {code: "session_expired"});
    await renderHook(newClient(), () => useLogout("fa"))();
    expect(calls()).toEqual(["POST /auth/logout", "POST /auth/refresh"]);
    expect(assigned).toEqual(["/fa/login"]);
  });

  it("useLogout: any other failure is thrown, the page stays and the cache is kept", async () => {
    server.answer = () => json(503, {code: "service_unavailable"});
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    await expect(renderHook(client, () => useLogout("fa"))()).rejects.toMatchObject({status: 503, code: "service_unavailable"});
    expect(assigned).toEqual([]);
    expect(client.getQueryData(meKeys.all)).toBeDefined();
  });

  it("useAdminLogout: admin has no refresh, so a dead session leaves at once", async () => {
    server.answer = () => json(401, {code: "session_expired"});
    await renderHook(newClient(), () => useAdminLogout("fa"))();
    expect(calls()).toEqual(["POST /auth/logout"]);
    expect(assigned).toEqual(["/fa/login"]);
  });

  // wp4-r8-4. The cover hides the page, but the session behind it would stay alive: a Continue press or an F5
  // would get it back with its limit renewed. For admin (no Remember me, no refresh, R44) the client ends it.
  describe("the admin idle cover ends the session (wp4-r8-4)", () => {
    function coverIt(answer: () => Response | Promise<Response>, shared?: SharedPresence) {
      vi.useFakeTimers({toFake: ["Date", "setTimeout", "clearTimeout"]});
      vi.stubGlobal("window", {
        location: {assign: (url: string) => assigned.push(url), pathname: "/en/users", search: ""},
        document: {documentElement: {style: {visibility: ""}}},
        addEventListener: () => undefined,
      });
      server.answer = answer as never;
      const client = newClient();
      client.setQueryData(["admin", "users"], [{phone: "0912"}]);
      const stopGuard = startAdminGuard(client, {locale: "en", currentNext: () => "/users"});
      let guardRunning = true;
      const stopGuardOnce = () => {
        if (!guardRunning) return;
        guardRunning = false;
        stopGuard();
      };
      const stopWatch = watchActivity(
        client,
        {addEventListener: () => undefined, removeEventListener: () => undefined},
        {coverMs: ADMIN_SESSION_IDLE_MS, shared},
      );
      // As React does (wp4-r11-4): the cover unmounts the gate, and the effect cleanup stops the guard and
      // releases its surface. The recheck minutes later must end the session without any mounted page.
      const unsubscribe = subscribeIdleState(() => {
        if (getIdleState().covered) queueMicrotask(stopGuardOnce);
      });
      return {
        client,
        stop() {
          unsubscribe();
          stopWatch();
          stopGuardOnce();
          vi.useRealTimers();
        },
      };
    }

    it("sends exactly one POST /auth/logout with keepalive, and leaves for /login?ended=1: no Continue to press", async () => {
      const {client, stop} = coverIt(() => new Response(null, {status: 204}));
      await vi.advanceTimersByTimeAsync(ADMIN_SESSION_IDLE_MS + 1_000);
      expect(getIdleState().covered).toBe(true);
      expect(client.getQueryCache().getAll()).toHaveLength(0);
      expect(calls()).toEqual(["POST /auth/logout"]);
      expect(server.seen[0]?.keepalive).toBe(true);
      expect(assigned).toEqual(["/en/login?next=%2Fusers&ended=1"]);
      stop();
    });

    // wp4-r9-3: the session cookie is shared by every admin tab. This tab is in the background and has had no
    // input, but the admin has been working in another one, and the server has kept the session alive for it.
    it("does not end the session while another admin tab has had input within the limit", async () => {
      const store = {value: undefined as number | undefined, read: () => store.value, write: (ms: number) => void (store.value = ms)};
      const {client, stop} = coverIt(() => new Response(null, {status: 204}), store);
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      store.value = Date.now(); // the other tab
      await vi.advanceTimersByTimeAsync(5 * 60_000 + 1_000);
      expect(getIdleState()).toMatchObject({covered: true, ending: false});
      expect(client.getQueryCache().getAll()).toHaveLength(0);
      expect(calls()).toEqual([]);
      expect(assigned).toEqual([]);
      stop();
    });

    // wp4-r10-1: the other tab is closed and can no longer end the session. This tab, covered and told the
    // session is live, looks at the shared time again when its limit runs out and ends the session itself.
    it("ends it by itself, once, when the other tab goes away and its limit runs out (a Continue press later revives nothing)", async () => {
      const store = {value: undefined as number | undefined, read: () => store.value, write: (ms: number) => void (store.value = ms)};
      const {client, stop} = coverIt(() => new Response(null, {status: 204}), store);
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      store.value = Date.now(); // the other tab's last input; it is then closed
      await vi.advanceTimersByTimeAsync(5 * 60_000 + 1_000); // this tab covers: live, nothing sent
      expect(calls()).toEqual([]);
      expect(assigned).toEqual([]);
      await vi.advanceTimersByTimeAsync(9 * 60_000); // still inside the other tab's limit
      expect(calls()).toEqual([]);
      await vi.advanceTimersByTimeAsync(60_000 + 1_000); // 15 minutes after that input
      expect(calls()).toEqual(["POST /auth/logout"]);
      expect(server.seen[0]?.keepalive).toBe(true);
      expect(assigned).toEqual(["/en/login?next=%2Fusers&ended=1"]);
      expect(getIdleState()).toMatchObject({covered: true, ending: true});
      expect(client.getQueryCache().getAll()).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(60 * 60_000);
      expect(calls()).toEqual(["POST /auth/logout"]);
      expect(assigned).toHaveLength(1);
      stop();
    });

    it("ends it exactly once when no tab has had input for the limit", async () => {
      const store = {value: undefined as number | undefined, read: () => store.value, write: (ms: number) => void (store.value = ms)};
      const {stop} = coverIt(() => new Response(null, {status: 204}), store);
      await vi.advanceTimersByTimeAsync(ADMIN_SESSION_IDLE_MS + 1_000);
      await vi.advanceTimersByTimeAsync(60 * 60_000);
      expect(calls()).toEqual(["POST /auth/logout"]);
      expect(assigned).toEqual(["/en/login?next=%2Fusers&ended=1"]);
      stop();
    });

    it("leaves although the logout cannot be sent (offline)", async () => {
      const {stop} = coverIt(() => Promise.reject(new TypeError("fetch failed")));
      await vi.advanceTimersByTimeAsync(ADMIN_SESSION_IDLE_MS + 1_000);
      expect(assigned).toEqual(["/en/login?next=%2Fusers&ended=1"]);
      stop();
    });

    it("does nothing before the limit", async () => {
      const {stop} = coverIt(() => new Response(null, {status: 204}));
      await vi.advanceTimersByTimeAsync(ADMIN_SESSION_IDLE_MS - 1_000);
      expect(calls()).toEqual([]);
      expect(assigned).toEqual([]);
      stop();
    });
  });

  it("an admin session that ended by itself leaves for /login?ended=1 with next, and tells no other tab", async () => {
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    let message: unknown = "none";
    const other = new BroadcastChannel("ctrlz-session");
    other.onmessage = (e: MessageEvent) => (message = e.data);
    leaveEndedAdminSession({queryClient: client, locale: "en"}, "/users");
    await new Promise((r) => setTimeout(r, 30));
    other.close();
    expect(assigned).toEqual(["/en/login?next=%2Fusers&ended=1"]);
    expect(message).toBe("none");
  });

  // gate-r33-11: a link from another site arrives with no admin cookie (it is Strict), the page is served, and its first /me is a 401. A page that
  // never had a session cannot say that it ended.
  it("the guard's first 401 of a page that had no session leaves with next and no ended marker, and a 401 after a success keeps it", async () => {
    const client = newClient();
    const stop = startAdminGuard(client, {locale: "en", currentNext: () => "/users"});
    const refuse = () => Promise.reject(new ApiError(401, "session_expired"));
    await client.fetchQuery({queryKey: ["admin", "me"], queryFn: refuse}).catch(() => undefined);
    await new Promise((r) => setTimeout(r, 30));
    stop();
    expect(assigned).toEqual(["/en/login?next=%2Fusers"]);

    clearLeaving();
    assigned.length = 0;
    const live = newClient();
    const stopLive = startAdminGuard(live, {locale: "en", currentNext: () => "/users"});
    await live.fetchQuery({queryKey: ["admin", "me"], queryFn: () => Promise.resolve({username: "root"})});
    await live.fetchQuery({queryKey: ["admin", "users"], queryFn: refuse}).catch(() => undefined);
    await new Promise((r) => setTimeout(r, 30));
    stopLive();
    expect(assigned).toEqual(["/en/login?next=%2Fusers&ended=1"]);
  });

  it("Log out all: logoutLocal alone, and the host's re-render cannot start a /me that redirects again", async () => {
    server.answer = (s) => (s.path === "/auth/logout-all" ? new Response(null, {status: 204}) : json(401, {code: "session_expired"}));
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    const unbind = bindSession({onEnded: () => assigned.push("second leave")});
    await new MutationObserver(client, logoutAllMutationOptions(client, "fa")).mutate();
    expect(assigned).toEqual(["/fa/login"]);

    // What the host component does after the mutation changes state: its useQuery observes /me in the cleared cache.
    const observer = new QueryObserver(client, meQueryOptions());
    const stop = observer.subscribe(() => undefined);
    await new Promise((r) => setTimeout(r, 30));
    stop();
    unbind();
    expect(calls()).toEqual(["POST /auth/logout-all"]);
    expect(assigned).toEqual(["/fa/login"]);
  });

  it("Log out all meets a dead session cookie: refresh, ask again, then leave (the Remember me cookie must not outlive it)", async () => {
    let logoutAll = 0;
    server.answer = (s) => {
      if (s.path === "/auth/refresh") return new Response(null, {status: 204});
      if (s.path === "/auth/logout-all") return ++logoutAll === 1 ? json(401, {code: "session_expired"}) : new Response(null, {status: 204});
      return json(404, {code: "not_found"});
    };
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    await new MutationObserver(client, logoutAllMutationOptions(client, "fa")).mutate();
    expect(calls()).toEqual(["POST /auth/logout-all", "POST /auth/refresh", "POST /auth/logout-all"]);
    expect(assigned).toEqual(["/fa/login"]);
  });

  it("Log out all with a login that is over for good does not claim success and does not say the session ended", async () => {
    server.answer = () => json(401, {code: "session_expired"});
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    const error = await new MutationObserver(client, logoutAllMutationOptions(client, "fa")).mutate().catch((e: unknown) => e);
    expect(calls()).toEqual(["POST /auth/logout-all", "POST /auth/refresh"]);
    expect(errorMessageKey(error)).toBe("logout_all_incomplete");
    expect(assigned).toEqual([]);
    expect(client.getQueryData(meKeys.all)).toBeDefined();
  });

  it("Log out all that the server refuses clears nothing", async () => {
    server.answer = () => json(503, {code: "service_unavailable"});
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    await new MutationObserver(client, logoutAllMutationOptions(client, "fa")).mutate().catch(() => undefined);
    expect(assigned).toEqual([]);
    expect(client.getQueryData(meKeys.all)).toBeDefined();
  });
});

describe("passkey mutations", () => {
  async function run<T>(pick: (o: ReturnType<typeof passkeyMutationOptions>) => unknown, variables: T) {
    const client = newClient();
    for (const key of [passkeyKeys.list, meKeys.all, sessionKeys.list, ["notifications", "list"]]) client.setQueryData(key, {}, {updatedAt: Date.now()});
    await new MutationObserver(client, pick(passkeyMutationOptions(client)) as never).mutate(variables as never);
    const state = (key: readonly string[]) => client.getQueryState(key)!.isInvalidated;
    return {client, invalidated: {passkeys: state(passkeyKeys.list), me: state(meKeys.all), sessions: state(sessionKeys.list), other: state(["notifications", "list"])}};
  }

  const everything = {passkeys: true, me: true, sessions: true, other: false};

  it.each([
    ["rename", (o: ReturnType<typeof passkeyMutationOptions>) => o.rename, {id: "p1", name: "Laptop"}, "PATCH", "/account/passkeys/p1", {id: "p1", name: "Laptop"}],
    ["delete", (o: ReturnType<typeof passkeyMutationOptions>) => o.remove, "p1", "DELETE", "/account/passkeys/p1", undefined],
    ["review", (o: ReturnType<typeof passkeyMutationOptions>) => o.review, undefined, "POST", "/account/passkeys/review", undefined],
    ["enforce", (o: ReturnType<typeof passkeyMutationOptions>) => o.enforce, true, "PUT", "/account/passkey-enforcement", {ended_sessions: 0}],
  ] as const)("%s calls its route and drops the passkey, /me and session caches, and only those", async (_name, pick, variables, method, path, answer) => {
    server.answer = () => (answer === undefined ? new Response(null, {status: 204}) : json(200, answer));
    const {invalidated} = await run(pick, variables);
    expect(server.seen[0]).toMatchObject({method, path});
    expect(invalidated).toEqual(everything);
  });

  it("a failed call drops nothing", async () => {
    server.answer = () => json(403, {code: "reauth_required"});
    const client = newClient();
    client.setQueryData(passkeyKeys.list, []);
    await new MutationObserver(client, passkeyMutationOptions(client).remove).mutate("p1").catch(() => undefined);
    expect(client.getQueryState(passkeyKeys.list)!.isInvalidated).toBe(false);
  });
});

describe("dismissing the onboarding card fails visibly", () => {
  it("rejects with the API's error and leaves the card's state alone", async () => {
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    server.answer = () => json(503, {code: "service_unavailable"});
    await expect(dismissOnboarding(client)).rejects.toMatchObject({status: 503, code: "service_unavailable"});
    expect(isOnboardingDismissed(client.getQueryData<Me>(meKeys.all)!.user.onboarding_state)).toBe(false);
  });

  it("the hook's dismiss rejects too, for the card to catch", async () => {
    const client = newClient();
    client.setQueryData(meKeys.all, meFixture());
    server.answer = () => json(500, {code: "internal"});
    const {dismiss} = renderHook(client, useOnboarding);
    await expect(dismiss()).rejects.toMatchObject({status: 500});
  });
});
