import {
  announcementFixture,
  errorBody,
  meFixture,
  notificationFixture,
  publicConfigFixture,
  type Announcement,
  type Me,
  type Notification,
} from "./fixtures.ts";

// Mock mode of spec 17.1: `context.route("**/api/v1/**", handler)` answers from
// typed fixtures, so UI work never waits for the backend. This file imports no
// Playwright type: a `BrowserContext` fits `MockContext` structurally, and the
// api-client package keeps its dependency list.
//
// The default state is a ready, signed-in Persian user with an empty bell. It is
// stateful where a test reloads and expects the server to remember (a read
// notification, a dismissed onboarding card). `expire()` makes the session end
// the way the API does: every route but `/auth/*` answers 401 `session_expired`
// until `POST /auth/refresh` succeeds, which is what the refresh rule of
// AUTH 3.4 is tested against.

export type MockRoute = {
  request(): {
    url(): string;
    method(): string;
    postData(): string | null;
    headers(): Record<string, string>;
    /** The page that made the request. */
    frame(): {url(): string};
  };
  fulfill(response: {status: number; headers?: Record<string, string>; contentType?: string; body?: string}): Promise<void>;
};

export type MockContext = {
  route(url: string | RegExp, handler: (route: MockRoute) => Promise<void> | void): Promise<unknown>;
};

export type MockCall = {
  method: string;
  /** The path after `/api/v1`, with no query. */
  path: string;
  query: URLSearchParams;
  body: unknown;
  headers: Record<string, string>;
  /** The URL of the page that made the call. */
  pageUrl: string;
};

export type MockReply = {status?: number; body?: unknown; headers?: Record<string, string>};
export type MockHandler = (call: MockCall, state: MockState) => MockReply | Promise<MockReply>;
/** `"GET /me"`, `"POST /notifications/{id}/read"`. */
export type MockKey = `${"GET" | "POST" | "PUT" | "PATCH" | "DELETE"} /${string}`;

export type MockState = {
  me: Me;
  notifications: Notification[];
  announcements: Announcement[];
  /** `true` after `expire()`, until a refresh succeeds. */
  expired: boolean;
  /** What `POST /auth/refresh` answers while expired: 204, or 401 for a session that is truly over. */
  refreshStatus: 204 | 401 | 503;
  /**
   * `/me` reports the language of the page that asks, so a test of an `/en/...` page
   * is not sent to the user's saved language (spec 4.2). A test of that redirect turns it off.
   */
  followPageLocale: boolean;
};

export type ApiMock = {
  state: MockState;
  /** Every request the page made, in order. */
  calls: MockCall[];
  /** Requests no handler matched. A test that expects none asserts this is empty. */
  unhandled: MockCall[];
  count(key: MockKey): number;
  /** The next calls of `key` use `handler`. */
  on(key: MockKey, handler: MockHandler | MockReply): void;
  /** The session ends: see the header comment. */
  expire(refreshStatus?: MockState["refreshStatus"]): void;
};

const NO_CONTENT: MockReply = {status: 204};

export function matches(key: string, call: MockCall): boolean {
  const [method, template] = key.split(" ") as [string, string];
  if (method !== call.method) return false;
  const pattern = new RegExp(`^${template.replace(/[.*+?^$()|[\]\\]/g, "\\$&").replace(/\{[^}]+\}/g, "[^/]+")}$`);
  return pattern.test(call.path);
}

export function defaultHandlers(): Record<MockKey, MockHandler> {
  return {
    "GET /me": (c, s) => {
      const page = /^\/(fa|en)(\/|$)/.exec(new URL(c.pageUrl).pathname)?.[1] as Me["user"]["locale"] | undefined;
      return {body: s.followPageLocale && page ? {...s.me, user: {...s.me.user, locale: page}} : s.me};
    },
    "GET /auth/config": () => ({body: publicConfigFixture()}),
    // The shell asks for these two on every page: the sidebar's counters and the first-run checklist read them (T-113, T-119). A tenant
    // that has made nothing has none, which is what this answers; a spec of the P2 and P3 screens installs `screenHandlers` over them.
    "GET /profiles": () => ({body: {items: []}}),
    "GET /endpoints": () => ({body: {items: [], by_type: {}, by_status: {pending: 0, active: 0}}}),
    // The server's split (Question 19): the unread security notices, the newest 50, are `security_items` and are not in `items` or
    // `unread_count`; a read one, or one past the newest 50, is in the list. `markable` is whatever the fixture says it is for this session.
    // Paged like the server: newest first, `limit` rows a page (the panel asks for 50), the cursor is the offset of the next row, and
    // `unread_count` is counted over every row of the list, not over the page.
    "GET /notifications": (c, s) => {
      const apart = s.notifications
        .filter((n) => n.security && !n.read_at)
        .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
        .slice(0, 50);
      const apartIds = new Set(apart.map((n) => n.id));
      const rows = s.notifications
        .filter((n) => !apartIds.has(n.id))
        .map((n) => (n.read_at ? {...n, markable: true} : n))
        .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
      const limit = Math.min(Number(c.query.get("limit")) || 50, 100);
      const from = Number(c.query.get("cursor")) || 0;
      const items = rows.slice(from, from + limit);
      return {
        body: {
          items,
          ...(from + limit < rows.length ? {next_cursor: String(from + limit)} : {}),
          unread_count: rows.filter((n) => !n.read_at).length,
          security_items: apart,
          security_unread_count: apart.length,
        },
      };
    },
    "GET /announcements": (_c, s) => ({
      body: {items: s.announcements, unread_count: s.announcements.filter((a) => !a.read).length},
    }),
    "POST /notifications/{id}/read": (c, s) => {
      const id = c.path.split("/")[2];
      // A security notice that is unread is marked only by a session made after it; from another it is 409 and nothing changes.
      const target = s.notifications.find((n) => n.id === id);
      if (target?.security && !target.read_at && !target.markable) return {status: 409, body: errorBody("conflict")};
      s.notifications = s.notifications.map((n) => (n.id === id && !n.read_at ? {...n, read_at: new Date().toISOString()} : n));
      return NO_CONTENT;
    },
    "POST /announcements/{id}/read": (c, s) => {
      const id = c.path.split("/")[2];
      s.announcements = s.announcements.map((a) => (a.id === id ? {...a, read: true} : a));
      return NO_CONTENT;
    },
    "PATCH /account/preferences": (c, s) => {
      const patch = c.body as {locale?: Me["user"]["locale"]; theme?: Me["user"]["theme"]; onboarding_hints?: {enabled: boolean}; onboarding_state?: Me["user"]["onboarding_state"]};
      s.me = {
        ...s.me,
        user: {
          ...s.me.user,
          ...(patch.locale ? {locale: patch.locale} : {}),
          ...(patch.theme ? {theme: patch.theme} : {}),
          ...(patch.onboarding_hints ? {onboarding_hints: patch.onboarding_hints} : {}),
          ...(patch.onboarding_state ? {onboarding_state: patch.onboarding_state} : {}),
        },
      };
      return {body: s.me};
    },
    "POST /auth/logout": () => NO_CONTENT,
    "POST /auth/logout-all": () => NO_CONTENT,
  };
}

export async function installApiMock(
  context: MockContext,
  options: {
    me?: Me;
    notifications?: Notification[];
    announcements?: Announcement[];
    handlers?: Partial<Record<MockKey, MockHandler | MockReply>>;
  } = {},
): Promise<ApiMock> {
  const state: MockState = {
    me: options.me ?? meFixture(),
    notifications: options.notifications ?? [],
    announcements: options.announcements ?? [],
    expired: false,
    refreshStatus: 204,
    followPageLocale: true,
  };
  const table = new Map<string, MockHandler | MockReply>(Object.entries(defaultHandlers()));
  for (const [key, value] of Object.entries(options.handlers ?? {})) if (value) table.set(key, value);
  const calls: MockCall[] = [];
  const unhandled: MockCall[] = [];

  await context.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const raw = request.postData();
    let body: unknown;
    try {
      body = raw ? JSON.parse(raw) : undefined;
    } catch {
      body = raw;
    }
    const call: MockCall = {
      method: request.method(),
      path: url.pathname.replace(/^\/api\/v1/, ""),
      query: url.searchParams,
      body,
      headers: request.headers(),
      pageUrl: request.frame().url(),
    };
    calls.push(call);

    let reply: MockReply;
    if (call.method === "POST" && call.path === "/auth/refresh" && state.expired) {
      if (state.refreshStatus === 204) state.expired = false;
      reply =
        state.refreshStatus === 204
          ? NO_CONTENT
          : {status: state.refreshStatus, body: errorBody(state.refreshStatus === 401 ? "session_expired" : "service_unavailable")};
    } else if (state.expired && !call.path.startsWith("/auth/")) {
      reply = {status: 401, body: errorBody("session_expired")};
    } else {
      // The most specific key wins: an exact path before a templated one.
      const keys = [...table.keys()].filter((k) => matches(k, call));
      const hit = keys.find((k) => !k.includes("{")) ?? keys[0];
      const found = hit ? table.get(hit) : undefined;
      if (!found) {
        unhandled.push(call);
        reply = {status: 404, body: errorBody("not_found")};
      } else {
        reply = typeof found === "function" ? await found(call, state) : found;
      }
    }

    const status = reply.status ?? 200;
    await route.fulfill({
      status,
      headers: {"cache-control": "no-store", ...reply.headers},
      ...(reply.body === undefined || status === 204
        ? {}
        : {contentType: "application/json", body: JSON.stringify(reply.body)}),
    });
  });

  return {
    state,
    calls,
    unhandled,
    count: (key) => calls.filter((c) => matches(key, c)).length,
    on: (key, handler) => void table.set(key, handler),
    expire: (refreshStatus = 204) => {
      state.expired = true;
      state.refreshStatus = refreshStatus;
    },
  };
}

export {announcementFixture, meFixture, notificationFixture};
