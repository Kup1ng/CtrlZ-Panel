import {QueryClient, QueryClientProvider, QueryObserver} from "@tanstack/react-query";
import {createElement} from "react";
import {renderToString} from "react-dom/server";
import {afterEach, describe, expect, it, vi} from "vitest";

// renderToString runs no effect, so the effects of the hook are collected and run by hand.
const effects = vi.hoisted(() => [] as Array<() => unknown>);
vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useEffect: (effect: () => unknown) => void effects.push(effect),
}));

import {useLoginSessionReset} from "./hooks/me.ts";
import {completeSignIn, SESSION_CHANNEL, takeLocaleSync} from "./session.ts";
import {onSessionEnd} from "./sessionEnd.ts";

afterEach(() => {
  effects.length = 0;
  vi.unstubAllGlobals();
});

// Renders a login page's reset over a client, runs its effects by hand, and returns the client.
function mountReset(opts?: {signedIn?: boolean}, client = new QueryClient()) {
  function Page() {
    useLoginSessionReset(opts);
    return null;
  }
  renderToString(createElement(QueryClientProvider, {client}, createElement(Page)));
  for (const effect of effects) effect();
  return client;
}

function fakeSessionStorage() {
  const data = new Map<string, string>();
  vi.stubGlobal("sessionStorage", {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
  });
}

// gate-r1-19: the pages of the auth layout hold one-time values (the reset ticket of Forgot Password, a typed password) in
// memory, so a page restored from the back/forward cache is hidden and loaded again, as every gated page is.
describe("a login-layout page restored from the back/forward cache (gate-r1-19)", () => {
  function restorable() {
    const listeners = new Map<string, (e: unknown) => void>();
    const reload = vi.fn();
    const props: Record<string, string> = {};
    const style = {props, setProperty: (name: string, value: string, priority?: string) => void (props[name] = priority ? `${value} !${priority}` : value)};
    vi.stubGlobal("window", {
      location: {assign: vi.fn(), reload},
      document: {documentElement: {style}},
      addEventListener: (type: string, l: (e: unknown) => void) => void listeners.set(type, l),
    });
    vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
    return {listeners, reload, style};
  }

  it.each([[{}], [{signedIn: true}]])("is hidden and reloaded when restored, with %j", async (opts) => {
    // The listener is installed once per window object, so each case gets a fresh module state.
    vi.resetModules();
    const fresh = await import("./hooks/me.ts");
    const {listeners, reload, style} = restorable();
    function Page() {
      fresh.useLoginSessionReset(opts);
      return null;
    }
    renderToString(createElement(QueryClientProvider, {client: new QueryClient()}, createElement(Page)));
    for (const effect of effects) effect();
    listeners.get("pageshow")?.({persisted: false});
    expect(reload).not.toHaveBeenCalled();
    listeners.get("pageshow")?.({persisted: true});
    expect(reload).toHaveBeenCalledTimes(1);
    expect(style.props).toEqual({display: "none !important", visibility: "hidden !important"});
  });
});

// wp4-r7-2: a session that ended with no logoutLocal (the cookie expired, the proxy sent the visitor to
// the login page) left the flag set, so the next sign-in never applied the saved language.
describe("the sign-in side of the session (wp4-r7-2)", () => {
  it("a login page clears the flag on mount, so the next sign-in applies the saved language once", () => {
    fakeSessionStorage();
    expect(takeLocaleSync()).toBe(true); // the previous signed-in session set it
    expect(takeLocaleSync()).toBe(false);
    mountReset();
    expect(takeLocaleSync()).toBe(true);
    expect(takeLocaleSync()).toBe(false);
  });

  it("completeSignIn clears the flag and tells the other tabs, in one call", async () => {
    fakeSessionStorage();
    takeLocaleSync();
    const heard = new Promise((resolve) => {
      const channel = new BroadcastChannel(SESSION_CHANNEL);
      channel.onmessage = (e: MessageEvent) => {
        channel.close();
        resolve(e.data);
      };
    });
    completeSignIn();
    expect(await heard).toBe("login");
    expect(takeLocaleSync()).toBe(true);
  });

  // wp4-r14-1: a soft redirect to the login page keeps the tab's QueryClient, so the previous account's
  // rows were still there when the next person signed in.
  describe("the previous account's cache (wp4-r14-1)", () => {
    const seed = () => {
      const client = new QueryClient();
      for (const key of [["me"], ["notifications", "list"], ["announcements", "list"], ["account", "sessions"], ["account", "passkeys"]]) {
        client.setQueryData(key, {of: "account A"});
      }
      return client;
    };

    it("a login page empties it on mount", () => {
      fakeSessionStorage();
      const client = mountReset(undefined, seed());
      expect(client.getQueryCache().getAll()).toEqual([]);
    });

    it("keeps a query the page itself observes", () => {
      fakeSessionStorage();
      const client = seed();
      // A real observer makes the query active, as the login page's own config query is.
      const observer = new QueryObserver(client, {queryKey: ["auth", "config"], queryFn: () => ({public: true}), staleTime: Infinity});
      const unsubscribe = observer.subscribe(() => {});
      mountReset(undefined, client);
      expect(client.getQueryCache().getAll().map((q) => q.queryKey)).toEqual([["auth", "config"]]);
      unsubscribe();
    });

    it("does not touch /me on a page a signed-in user lands on (change password, suspended)", () => {
      fakeSessionStorage();
      const client = mountReset({signedIn: true}, seed());
      expect(client.getQueryData(["me"])).toEqual({of: "account A"});
      expect(client.getQueryData(["notifications", "list"])).toBeDefined();
    });

    it("is what the effect does, not what render does", () => {
      fakeSessionStorage();
      const client = seed();
      function Page() {
        useLoginSessionReset();
        return null;
      }
      renderToString(createElement(QueryClientProvider, {client}, createElement(Page)));
      expect(client.getQueryCache().getAll()).toHaveLength(5);
    });
  });
});

// S1-r2-4: a store outside the query cache (the job the Profiles screen follows) belongs to one session. The soft navigation to /login after
// the cookies expired is a session end that no page load wipes, so it runs what the stores registered, like the cache clear next to it.
describe("a session that ends without a page load (S1-r2-4)", () => {
  it("the login layout's reset runs the session-end handlers, and a signed-in page of that layout does not", () => {
    fakeSessionStorage();
    const ended = vi.fn();
    const off = onSessionEnd(ended);
    mountReset({signedIn: true});
    expect(ended).not.toHaveBeenCalled();
    mountReset();
    expect(ended).toHaveBeenCalledTimes(1);
    off();
    mountReset();
    expect(ended).toHaveBeenCalledTimes(1);
  });
});
