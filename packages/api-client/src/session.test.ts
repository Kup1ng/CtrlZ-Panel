import {QueryClient, QueryObserver} from "@tanstack/react-query";
import {afterEach, describe, expect, it, vi} from "vitest";

import {copyOneTimeSecret, wipeCopiedSecret} from "./clipboard.ts";
import {ApiError, errorMessageKey, hasCode} from "./errors.ts";
import {meKeys, startSessionBinding} from "./hooks/me.ts";
import {
  bindSession,
  broadcastLogin,
  clearLeaving,
  completeSignIn,
  deriveSession,
  guardRestoredPage,
  handleSessionEnded,
  isOnLoginPath,
  isSessionEnding,
  loginUrl,
  logoutAndLeave,
  logoutLocal,
  parseSessionMessage,
  reloadForNewIdentity,
  resetLocaleSync,
  SESSION_CHANNEL,
  takeLocaleSync,
  watchIdentity,
} from "./session.ts";
import {adminMeFixture, meFixture} from "./testing/fixtures.ts";
import {onSessionEnd} from "./sessionEnd.ts";
import {adminMeKeys, startAdminGuard, type AdminMe} from "./admin/session.ts";

afterEach(() => {
  clearLeaving();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/** The next message a second tab would see. */
function listen(): Promise<unknown> {
  const channel = new BroadcastChannel(SESSION_CHANNEL);
  return new Promise((resolve) => {
    channel.onmessage = (e: MessageEvent) => {
      channel.close();
      resolve(e.data);
    };
  });
}

describe("deriveSession", () => {
  const ready = meFixture();

  it("is loading until /me answers", () => {
    expect(deriveSession({data: undefined, error: null, isPending: true})).toEqual({status: "loading", me: undefined});
  });

  it("is ready for an active tenant and a user with a password to keep", () => {
    expect(deriveSession({data: ready, error: null, isPending: false})).toEqual({status: "ready", me: ready});
  });

  it("is restricted while the user must reset, and suspended for a suspended tenant", () => {
    const restricted = meFixture({user: {must_reset: true}});
    expect(deriveSession({data: restricted, error: null, isPending: false}).status).toBe("restricted");
    const suspended = meFixture({tenant: {status: "suspended"}});
    expect(deriveSession({data: suspended, error: null, isPending: false}).status).toBe("suspended");
    // Suspended comes first: such a tenant can reach nothing else.
    const both = meFixture({user: {must_reset: true}, tenant: {status: "suspended"}});
    expect(deriveSession({data: both, error: null, isPending: false}).status).toBe("suspended");
  });

  it("treats a tenant being deleted as signed out", () => {
    expect(deriveSession({data: meFixture({tenant: {status: "deleting"}}), error: null, isPending: false}).status).toBe("anonymous");
  });

  it("is anonymous on session_expired, which is final because the client already tried a refresh", () => {
    const error = new ApiError(401, "session_expired");
    expect(deriveSession({data: undefined, error, isPending: false})).toEqual({status: "anonymous", me: undefined});
    // Even over an earlier answer: the session is what ended.
    expect(deriveSession({data: ready, error, isPending: false}).status).toBe("anonymous");
  });

  it("keeps a known Me when a refetch fails for any other reason", () => {
    for (const error of [new ApiError(503, "service_unavailable"), new TypeError("offline"), new ApiError(500, "internal")]) {
      expect(deriveSession({data: ready, error, isPending: false}).status).toBe("ready");
    }
  });

  it("is error, not anonymous, for a first /me that failed without ending the session", () => {
    for (const error of [new ApiError(503, "service_unavailable"), new TypeError("offline"), new ApiError(403, "csrf_rejected")]) {
      expect(deriveSession({data: undefined, error, isPending: false}).status).toBe("error");
    }
  });
});

describe("loginUrl", () => {
  it("builds the login path with an encoded next", () => {
    expect(loginUrl("fa")).toBe("/fa/login");
    expect(loginUrl("en", {next: "/preferences/account?tab=2"})).toBe("/en/login?next=%2Fpreferences%2Faccount%3Ftab%3D2");
  });

  it("adds the ended marker for the login page's notice, with or without next", () => {
    expect(loginUrl("fa", {ended: true})).toBe("/fa/login?ended=1");
    expect(loginUrl("en", {next: "/users", ended: true})).toBe("/en/login?next=%2Fusers&ended=1");
    expect(loginUrl("en", {ended: false})).toBe("/en/login");
  });

  it("falls back to fa for a locale that is not two letters, so it cannot be steered off-site", () => {
    expect(loginUrl("//evil.example")).toBe("/fa/login");
    expect(loginUrl("")).toBe("/fa/login");
  });
});

describe("channel messages", () => {
  it("accepts only the two words", () => {
    expect(parseSessionMessage("logout")).toBe("logout");
    expect(parseSessionMessage("login")).toBe("login");
    for (const bad of ["LOGOUT", {type: "logout"}, null, undefined, 1, "logout "]) expect(parseSessionMessage(bad)).toBeUndefined();
  });

  it("broadcastLogin posts login on ctrlz-session", async () => {
    const heard = listen();
    broadcastLogin();
    expect(await heard).toBe("login");
  });
});

describe("logoutLocal (spec 14.4)", () => {
  function setup() {
    const assign = vi.fn();
    vi.stubGlobal("window", {location: {assign}});
    const store = new Map<string, string>([["ctrlz.localeSynced", "1"]]);
    vi.stubGlobal("sessionStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });
    const queryClient = new QueryClient();
    queryClient.setQueryData(["me"], meFixture());
    return {assign, store, queryClient};
  }

  it("clears the cache, tells the other tabs, then loads the login page", async () => {
    const {assign, queryClient, store} = setup();
    const heard = listen();
    logoutLocal({queryClient, locale: "fa"}, {broadcast: true});
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(store.has("ctrlz.localeSynced")).toBe(false);
    expect(assign).toHaveBeenCalledExactlyOnceWith("/fa/login");
    expect(await heard).toBe("logout");
  });

  // S1-r2-4: a store outside the cache (the job the Profiles screen follows) ends with the session, on this path as on the others.
  it("runs the session-end handlers next to the cache clear", () => {
    const {queryClient} = setup();
    const ended = vi.fn();
    const off = onSessionEnd(ended);
    logoutLocal({queryClient, locale: "fa"});
    off();
    expect(ended).toHaveBeenCalledTimes(1);
  });

  // wp4-r16-2: a forgotten option must fail closed. A call that only saw an error is not proof that
  // the session ended, and a "logout" message takes every live tab down.
  it("does not broadcast unless it is told to: no option, an empty option and broadcast: undefined", async () => {
    for (const options of [undefined, {}, {broadcast: undefined}, {next: "/x"}]) {
      const {queryClient} = setup();
      let message: unknown = "none";
      const channel = new BroadcastChannel(SESSION_CHANNEL);
      channel.onmessage = (e: MessageEvent) => (message = e.data);
      logoutLocal({queryClient, locale: "fa"}, options);
      await new Promise((r) => setTimeout(r, 30));
      channel.close();
      expect(message, JSON.stringify(options)).toBe("none");
      clearLeaving();
    }
  });

  // gate-r5-8: the secret that Copy put in the system clipboard does not outlive the session.
  it("overwrites a copied one-time secret in the clipboard, and leaves a clipboard that it did not fill alone", async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal("navigator", {clipboard: {writeText}});
    const {queryClient} = setup();
    logoutLocal({queryClient, locale: "fa"});
    expect(writeText).not.toHaveBeenCalled();
    clearLeaving();
    await copyOneTimeSecret("SECRET");
    logoutLocal({queryClient, locale: "fa"});
    expect(writeText).toHaveBeenLastCalledWith("");
    expect(writeText).toHaveBeenCalledTimes(2);
  });

  // gate-r13-10. The page that was open keeps whatever it painted until the next document commits; every way the session ends hides it first.
  describe("the page that is left is taken out of the rendering before the navigation starts (gate-r13-10)", () => {
    function leavable() {
      const order: string[] = [];
      const props: Record<string, string> = {};
      const style = {
        setProperty: (name: string, value: string, priority?: string) => {
          props[name] = priority ? `${value} !${priority}` : value;
          order.push("hide");
        },
      };
      const assign = vi.fn(() => void order.push("assign"));
      const reload = vi.fn(() => void order.push("reload"));
      vi.stubGlobal("window", {
        location: {assign, reload},
        document: {documentElement: {style}},
        addEventListener: () => undefined,
      });
      vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
      return {order, props};
    }

    it("logoutLocal hides <html> before it assigns the login URL", () => {
      const {order, props} = leavable();
      logoutLocal({queryClient: new QueryClient(), locale: "fa"});
      expect(props).toEqual({display: "none !important", visibility: "hidden !important"});
      expect(order.indexOf("hide")).toBeGreaterThanOrEqual(0);
      expect(order.indexOf("hide")).toBeLessThan(order.indexOf("assign"));
    });

    it("reloadForNewIdentity hides <html> before it reloads", () => {
      const {order, props} = leavable();
      reloadForNewIdentity({queryClient: new QueryClient()});
      expect(props.display).toBe("none !important");
      expect(order.indexOf("hide")).toBeLessThan(order.indexOf("reload"));
    });

    it("a session that a refused refresh ends hides <html> as well", () => {
      const {props} = leavable();
      const unbind = bindSession({onEnded: () => undefined});
      handleSessionEnded();
      expect(props.display).toBe("none !important");
      unbind();
    });
  });

  it("does the same when the tab reloads for another identity", async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal("navigator", {clipboard: {writeText}});
    const {queryClient} = setup();
    vi.stubGlobal("window", {location: {assign: vi.fn(), reload: vi.fn()}});
    await copyOneTimeSecret("SECRET");
    reloadForNewIdentity({queryClient});
    expect(writeText).toHaveBeenLastCalledWith("");
  });

  // gate-r7-10. The tab that has the focus is the one that can write: a logout, or a sign-in as another person, there empties a clipboard
  // that another tab filled, once that tab has said so on the channel of clipboard.ts.
  it("a logout, or a sign-in, in a tab that copied nothing overwrites what another tab copied", async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal("navigator", {clipboard: {writeText}});
    await wipeCopiedSecret(); // opens this tab's channel; nothing is known yet, so nothing is written
    expect(writeText).not.toHaveBeenCalled();
    const sibling = new BroadcastChannel("ctrlz-clip");
    sibling.postMessage("held");
    await new Promise((r) => setTimeout(r, 30));
    const {queryClient} = setup();
    logoutLocal({queryClient, locale: "fa"});
    expect(writeText).toHaveBeenLastCalledWith("");
    clearLeaving();
    sibling.postMessage("held");
    await new Promise((r) => setTimeout(r, 30));
    completeSignIn();
    expect(writeText).toHaveBeenCalledTimes(2);
    sibling.close();
  });

  it("does not broadcast when it is itself the answer to a broadcast", async () => {
    const {assign, queryClient} = setup();
    let message: unknown = "none";
    const channel = new BroadcastChannel(SESSION_CHANNEL);
    channel.onmessage = (e: MessageEvent) => (message = e.data);
    logoutLocal({queryClient, locale: "en"}, {broadcast: false, next: "/profiles"});
    await new Promise((r) => setTimeout(r, 30));
    channel.close();
    expect(message).toBe("none");
    expect(assign).toHaveBeenCalledWith("/en/login?next=%2Fprofiles");
  });

  it("cancels what is in flight before it clears, so a /me on its way does not land in the new cache", async () => {
    const {queryClient} = setup();
    let aborted = false;
    const inFlight = queryClient
      .fetchQuery({
        queryKey: ["slow"],
        queryFn: ({signal}) =>
          new Promise((_resolve, reject) =>
            signal.addEventListener("abort", () => {
              aborted = true;
              reject(new Error("aborted"));
            }),
          ),
      })
      .catch(() => undefined);
    logoutLocal({queryClient, locale: "fa"});
    await inFlight;
    expect(aborted).toBe(true);
  });

  it("marks the tab as leaving, and a refused refresh then does not start a second navigation", () => {
    const {assign, queryClient} = setup();
    const onEnded = vi.fn();
    const unbind = bindSession({onEnded});
    expect(isSessionEnding()).toBe(false);
    logoutLocal({queryClient, locale: "fa"});
    expect(isSessionEnding()).toBe(true);
    handleSessionEnded();
    expect(onEnded).not.toHaveBeenCalled();
    expect(assign).toHaveBeenCalledTimes(1);
    unbind();
  });

  it("carries next and the ended marker to the login page when asked", () => {
    const {assign, queryClient} = setup();
    logoutLocal({queryClient, locale: "en"}, {broadcast: false, ended: true, next: "/users"});
    expect(assign).toHaveBeenCalledWith("/en/login?next=%2Fusers&ended=1");
  });

  it("keeps the tab leaving however long the login page takes", () => {
    // A timer would drop the flag on a slow link, and a focus or a re-render would then ask /me
    // into the empty cache and replace the plain redirect by one with next (wp4-r2-3).
    vi.useFakeTimers();
    vi.stubGlobal("window", {location: {assign: vi.fn()}, addEventListener: () => undefined});
    vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
    const queryClient = new QueryClient();
    logoutLocal({queryClient, locale: "fa"});
    vi.advanceTimersByTime(10 * 60_000);
    expect(isSessionEnding()).toBe(true);
    // A late refused refresh still starts nothing new.
    const onEnded = vi.fn();
    const unbind = bindSession({onEnded});
    handleSessionEnded();
    expect(onEnded).not.toHaveBeenCalled();
    unbind();
  });

  // wp4-r4-2: Safari restores a page from the back/forward cache with the previous account's DOM,
  // and nothing re-renders it. The page must not come back to life: it is hidden and loaded again.
  describe("a page restored from the back/forward cache after logout", () => {
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

    it("is hidden and reloaded, and the leaving flag still blocks a late session end", () => {
      const {listeners, reload, style} = restorable();
      logoutLocal({queryClient: new QueryClient(), locale: "fa"});
      listeners.get("pageshow")?.({persisted: true});
      expect(reload).toHaveBeenCalledTimes(1);
      expect(style.props).toEqual({display: "none !important", visibility: "hidden !important"});
      expect(isSessionEnding()).toBe(true);
      const onEnded = vi.fn();
      const unbind = bindSession({onEnded});
      handleSessionEnded();
      expect(onEnded).not.toHaveBeenCalled();
      unbind();
    });

    it("does nothing for a normal load", () => {
      const {listeners, reload, style} = restorable();
      guardRestoredPage();
      listeners.get("pageshow")?.({persisted: false});
      expect(reload).not.toHaveBeenCalled();
      expect(style.props).toEqual({});
      expect(isSessionEnding()).toBe(false);
    });

    // wp4-r5-7: a gated page that never left (it went into the cache by an ordinary navigation, and its
    // session ended in another tab) is restored with the old account's DOM too. The presence gate cannot
    // be trusted to ask again: it reads the last input of a document frozen hours ago.
    it("a gated panel page that never left is hidden and reloaded when restored", () => {
      const {listeners, reload, style} = restorable();
      const stop = startSessionBinding(new QueryClient(), {locale: "fa", currentNext: () => undefined}, null);
      expect(isSessionEnding()).toBe(false);
      listeners.get("pageshow")?.({persisted: false});
      expect(reload).not.toHaveBeenCalled();
      expect(isSessionEnding(), "an ordinary pageshow does not end the page").toBe(false);
      listeners.get("pageshow")?.({persisted: true});
      expect(reload).toHaveBeenCalledTimes(1);
      expect(style.props).toEqual({display: "none !important", visibility: "hidden !important"});
      // gate-r11-4: the restored page is ending before it reloads, which is what makes a leave guard (recovery codes on screen) step aside
      // instead of answering the reload with a prompt that a person can cancel.
      expect(isSessionEnding()).toBe(true);
      stop();
    });

    it("a gated admin page that never left is hidden and reloaded when restored", () => {
      const {listeners, reload, style} = restorable();
      const stop = startAdminGuard(new QueryClient(), {locale: "fa", currentNext: () => undefined});
      listeners.get("pageshow")?.({persisted: true});
      expect(reload).toHaveBeenCalledTimes(1);
      expect(style.props).toEqual({display: "none !important", visibility: "hidden !important"});
      stop();
    });

    it("installs one listener per window, however many gated pages mount and leave", () => {
      const {listeners, reload} = restorable();
      const add = vi.spyOn(window, "addEventListener");
      const stopA = startSessionBinding(new QueryClient(), {locale: "fa", currentNext: () => undefined}, null);
      const stopB = startAdminGuard(new QueryClient(), {locale: "fa", currentNext: () => undefined});
      logoutLocal({queryClient: new QueryClient(), locale: "fa"});
      expect(add).toHaveBeenCalledTimes(1);
      listeners.get("pageshow")?.({persisted: true});
      expect(reload).toHaveBeenCalledTimes(1);
      stopA();
      stopB();
    });

    it("also covers a tab that was sent away by another account signing in", () => {
      const {listeners, reload} = restorable();
      reloadForNewIdentity({queryClient: new QueryClient()});
      expect(reload).toHaveBeenCalledTimes(1);
      listeners.get("pageshow")?.({persisted: true});
      expect(reload).toHaveBeenCalledTimes(2);
    });
  });

  it("holds nothing in storage but the language flag, and removes it", () => {
    const {queryClient, store} = setup();
    store.set("other", "x");
    logoutLocal({queryClient, locale: "fa"});
    expect([...store.keys()]).toEqual(["other"]);
  });
});

describe("the saved language is applied once", () => {
  it("is true the first time in a tab session, and again after a logout", () => {
    const store = new Map<string, string>();
    vi.stubGlobal("sessionStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });
    expect(takeLocaleSync()).toBe(true);
    expect(takeLocaleSync()).toBe(false);
    resetLocaleSync();
    expect(takeLocaleSync()).toBe(true);
  });

  it("is false when storage is blocked, so a page cannot loop on it", () => {
    vi.stubGlobal("sessionStorage", {
      getItem: () => {
        throw new DOMException("blocked", "SecurityError");
      },
    });
    expect(takeLocaleSync()).toBe(false);
  });
});

describe("handleSessionEnded", () => {
  it("runs the bound handler once however many requests were waiting, and tells the other tabs", async () => {
    vi.useFakeTimers({toFake: ["setTimeout"]});
    const onEnded = vi.fn();
    const unbind = bindSession({onEnded});
    const heard = listen();
    handleSessionEnded();
    handleSessionEnded();
    handleSessionEnded();
    expect(onEnded).toHaveBeenCalledTimes(1);
    expect(await heard).toBe("logout");
    unbind();
  });

  // gate-r17-4: a refresh that is refused after the router has committed the login page, while the binding of the page that was left is
  // still bound, must not hide the login page or set the leaving flag, which has no reset.
  it("leaves a login page visible and not leaving, and still ends a session on the next gated page (gate-r17-4)", () => {
    const props: Record<string, string> = {};
    const style = {setProperty: (name: string, value: string, priority?: string) => void (props[name] = priority ? `${value} !${priority}` : value)};
    const location = {pathname: "/fa/login", assign: vi.fn()};
    vi.stubGlobal("window", {location, document: {documentElement: {style}}, addEventListener: () => undefined});
    vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
    const onEnded = vi.fn();
    const unbind = bindSession({onEnded});
    for (const path of ["/fa/login", "/en/login/"]) {
      location.pathname = path;
      handleSessionEnded();
      expect(props, path).toEqual({});
      expect(isSessionEnding(), path).toBe(false);
    }
    expect(onEnded).not.toHaveBeenCalled();
    // Nothing is stuck: the same document, now on a gated page, ends normally.
    location.pathname = "/fa/profiles";
    handleSessionEnded();
    expect(onEnded).toHaveBeenCalledTimes(1);
    expect(isSessionEnding()).toBe(true);
    expect(props).toEqual({display: "none !important", visibility: "hidden !important"});
    unbind();
  });

  it("does nothing without a binding, so a login page is not thrown around", () => {
    vi.useFakeTimers({toFake: ["setTimeout"]});
    const onEnded = vi.fn();
    const unbind = bindSession({onEnded});
    unbind();
    handleSessionEnded();
    expect(onEnded).not.toHaveBeenCalled();
  });
});

describe("isOnLoginPath", () => {
  it("is true on the login page of either language and nowhere else", () => {
    const at = (pathname: string) => {
      vi.stubGlobal("window", {location: {pathname}});
      return isOnLoginPath();
    };
    expect(at("/fa/login")).toBe(true);
    expect(at("/en/login")).toBe(true);
    expect(at("/en/login/")).toBe(true);
    expect(at("/fa/profiles")).toBe(false);
    expect(at("/fa/loginx")).toBe(false);
    // Below the login page there is no page: the catch-all renders the signed-in shell's 404 there (gate-r20-6).
    expect(at("/fa/login/x")).toBe(false);
    expect(at("/en/login/x/y")).toBe(false);
    expect(at("/fa/login//")).toBe(false);
    expect(at("/fa/login/.")).toBe(false);
    expect(at("/fa/preferences/login")).toBe(false);
    expect(at("/login")).toBe(false);
  });
});

describe("logoutAndLeave: the logout that has a dead session cookie in front of it", () => {
  const expiredError = () => new ApiError(401, "session_expired");

  function setup() {
    const assign = vi.fn();
    vi.stubGlobal("window", {location: {assign}});
    vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
    return {assign, queryClient: new QueryClient()};
  }

  it("logs out and leaves", async () => {
    const {assign, queryClient} = setup();
    const logout = vi.fn(async () => undefined);
    const refresh = vi.fn(async () => undefined);
    await logoutAndLeave({queryClient, locale: "fa"}, {logout, refresh});
    expect(logout).toHaveBeenCalledTimes(1);
    expect(refresh).not.toHaveBeenCalled();
    expect(assign).toHaveBeenCalledWith("/fa/login");
  });

  it("refreshes after a dead session, then ends what the refresh brought back, then leaves", async () => {
    const {assign, queryClient} = setup();
    const order: string[] = [];
    let first = true;
    const logout = vi.fn(async () => {
      order.push("logout");
      if (first) {
        first = false;
        throw expiredError();
      }
    });
    const refresh = vi.fn(async () => void order.push("refresh"));
    await logoutAndLeave({queryClient, locale: "fa"}, {logout, refresh});
    // The refresh cookie of Remember me would otherwise give the next visitor this account back.
    expect(order).toEqual(["logout", "refresh", "logout"]);
    expect(assign).toHaveBeenCalledTimes(1);
  });

  it("leaves when the refresh itself says the login is over: the server has cleared both cookies", async () => {
    const {assign, queryClient} = setup();
    const logout = vi.fn(async () => Promise.reject(expiredError()));
    const refresh = vi.fn(async () => Promise.reject(expiredError()));
    await logoutAndLeave({queryClient, locale: "fa"}, {logout, refresh});
    expect(logout).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith("/fa/login");
  });

  it("a call that ends more than this browser fails, clearing nothing, when the refresh is refused (Log out all)", async () => {
    const {assign, queryClient} = setup();
    queryClient.setQueryData(["me"], {kept: true});
    const logout = vi.fn(async () => Promise.reject(expiredError()));
    const refresh = vi.fn(async () => Promise.reject(expiredError()));
    const thrown = await logoutAndLeave({queryClient, locale: "fa"}, {logout, refresh, incompleteWhenRefreshRefused: "logout_all_incomplete"}).catch(
      (e: unknown) => e,
    );
    // The other sessions of the account were not ended, so this is neither a success nor "the session has ended".
    expect(thrown).toBeInstanceOf(ApiError);
    expect(errorMessageKey(thrown)).toBe("logout_all_incomplete");
    expect(logout).toHaveBeenCalledTimes(1);
    expect(assign).not.toHaveBeenCalled();
    expect(queryClient.getQueryData(["me"])).toEqual({kept: true});
  });

  it("does not look like a logout when the refresh could not be answered, or the second logout fails", async () => {
    const down = new ApiError(503, "service_unavailable");
    {
      const {assign, queryClient} = setup();
      const calls = {logout: vi.fn(async () => Promise.reject(expiredError())), refresh: vi.fn(async () => Promise.reject(down))};
      await expect(logoutAndLeave({queryClient, locale: "fa"}, calls)).rejects.toBe(down);
      expect(assign).not.toHaveBeenCalled();
    }
    {
      const {assign, queryClient} = setup();
      let n = 0;
      const calls = {logout: vi.fn(async () => Promise.reject(++n === 1 ? expiredError() : down)), refresh: vi.fn(async () => undefined)};
      await expect(logoutAndLeave({queryClient, locale: "fa"}, calls)).rejects.toBe(down);
      expect(assign).not.toHaveBeenCalled();
    }
  });

  it("tries again when the logout after a refresh still meets a dead session cookie (the 204 with no Set-Cookie of AUTH 3.4)", async () => {
    const {assign, queryClient} = setup();
    const order: string[] = [];
    let n = 0;
    const logout = vi.fn(async () => {
      order.push("logout");
      if (++n <= 2) throw expiredError();
    });
    const refresh = vi.fn(async () => void order.push("refresh"));
    await logoutAndLeave({queryClient, locale: "fa"}, {logout, refresh});
    expect(order).toEqual(["logout", "refresh", "logout", "refresh", "logout"]);
    expect(assign).toHaveBeenCalledExactlyOnceWith("/fa/login");
  });

  it("does not say the session ended, and clears nothing, when the logout never gets through a live refresh (wp4-r2-4)", async () => {
    const {assign, queryClient} = setup();
    queryClient.setQueryData(["me"], meFixture());
    const logout = vi.fn(async () => Promise.reject(expiredError()));
    const refresh = vi.fn(async () => undefined);
    const thrown = await logoutAndLeave({queryClient, locale: "fa"}, {logout, refresh}).catch((e: unknown) => e);
    // The refresh cookie is alive, so "your session has ended" would be false: the text is the generic "try again".
    expect(thrown).toBeInstanceOf(ApiError);
    expect(errorMessageKey(thrown)).toBe("unknown");
    expect(hasCode(thrown, "session_expired")).toBe(false);
    expect(logout).toHaveBeenCalledTimes(3);
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(assign).not.toHaveBeenCalled();
    expect(queryClient.getQueryData(["me"])).toBeDefined();
  });

  it("throws any other logout failure and clears nothing", async () => {
    const {assign, queryClient} = setup();
    queryClient.setQueryData(["me"], meFixture());
    const failure = new ApiError(503, "service_unavailable");
    await expect(logoutAndLeave({queryClient, locale: "fa"}, {logout: async () => Promise.reject(failure), refresh: async () => undefined})).rejects.toBe(failure);
    expect(assign).not.toHaveBeenCalled();
    expect(queryClient.getQueryData(["me"])).toBeDefined();
  });

  it("tells the other tabs: the server answered a logout, which is the one leave that broadcasts", async () => {
    const {queryClient} = setup();
    const heard = listen();
    await logoutAndLeave({queryClient, locale: "fa"}, {logout: async () => undefined, refresh: async () => undefined});
    expect(await heard).toBe("logout");
  });

  it("does not tell the other tabs when the caller says false (admin has no channel)", async () => {
    const {queryClient} = setup();
    let message: unknown = "none";
    const channel = new BroadcastChannel(SESSION_CHANNEL);
    channel.onmessage = (e: MessageEvent) => (message = e.data);
    await logoutAndLeave({queryClient, locale: "en"}, {logout: async () => undefined}, {broadcast: false});
    await new Promise((r) => setTimeout(r, 30));
    channel.close();
    expect(message).toBe("none");
  });

  it("has no refresh for admin: a dead session just leaves", async () => {
    const {assign, queryClient} = setup();
    await logoutAndLeave({queryClient, locale: "en"}, {logout: async () => Promise.reject(expiredError())}, {broadcast: false});
    expect(assign).toHaveBeenCalledWith("/en/login");
  });
});

describe("startAdminGuard leaves when an admin call says the session ended (wp4-r6-4)", () => {
  // /setup is outside AdminGate, so nothing else reacts to a 401 there, and admin has no middleware.
  function setup(pathname = "/en/setup") {
    const assign = vi.fn();
    vi.stubGlobal("window", {
      location: {assign, pathname, search: ""},
      document: {documentElement: {style: {visibility: ""}}},
      addEventListener: () => undefined,
    });
    vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
    const queryClient = new QueryClient();
    const stop = startAdminGuard(queryClient, {locale: "en", currentNext: () => "/users"});
    return {assign, queryClient, stop};
  }
  // The cache tells its listeners in a batch, one timer later.
  const settle = () => new Promise((r) => setTimeout(r, 0));
  const fail = (code: ConstructorParameters<typeof ApiError>[1], status = 401) => () => Promise.reject(new ApiError(status, code));

  it("an admin query that answers 401 session_expired leaves for /login with the next page and the ended marker, once the page has had a session", async () => {
    const {assign, queryClient, stop} = setup();
    await queryClient.fetchQuery({queryKey: ["admin", "me"], queryFn: () => Promise.resolve({username: "root"})});
    await queryClient.fetchQuery({queryKey: ["admin", "users"], queryFn: fail("session_expired"), retry: false}).catch(() => undefined);
    await settle();
    expect(assign).toHaveBeenCalledExactlyOnceWith("/en/login?next=%2Fusers&ended=1");
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    stop();
  });

  // gate-r33-11: the first answer of a page load is already a 401 when no cookie came (a link from another site, a browser that never signed in).
  it("a 401 session_expired before any call of the page has answered leaves with the next page and no ended marker", async () => {
    const {assign, queryClient, stop} = setup();
    await queryClient.fetchQuery({queryKey: ["admin", "me"], queryFn: fail("session_expired"), retry: false}).catch(() => undefined);
    await settle();
    expect(assign).toHaveBeenCalledExactlyOnceWith("/en/login?next=%2Fusers");
    stop();
  });

  it("an admin mutation that answers 401 session_expired does too, and only once for many", async () => {
    const {assign, queryClient, stop} = setup();
    const run = () => queryClient.getMutationCache().build(queryClient, {mutationFn: fail("session_expired")}).execute(undefined).catch(() => undefined);
    await Promise.all([run(), run()]);
    await settle();
    expect(assign).toHaveBeenCalledTimes(1);
    stop();
  });

  it("leaves nothing else: another 401 code, another status and the login page itself are not a session end", async () => {
    const {assign, queryClient, stop} = setup();
    await queryClient.fetchQuery({queryKey: ["a"], queryFn: fail("invalid_credentials"), retry: false}).catch(() => undefined);
    await queryClient.fetchQuery({queryKey: ["b"], queryFn: fail("service_unavailable", 503), retry: false}).catch(() => undefined);
    await settle();
    expect(assign).not.toHaveBeenCalled();
    stop();

    const onLogin = setup("/en/login");
    await onLogin.queryClient.fetchQuery({queryKey: ["c"], queryFn: fail("session_expired"), retry: false}).catch(() => undefined);
    await settle();
    expect(onLogin.assign).not.toHaveBeenCalled();
    onLogin.stop();
  });

  it("stops listening when the page goes", async () => {
    const {assign, queryClient, stop} = setup();
    stop();
    await queryClient.fetchQuery({queryKey: ["d"], queryFn: fail("session_expired"), retry: false}).catch(() => undefined);
    await settle();
    expect(assign).not.toHaveBeenCalled();
  });
});

describe("startSessionBinding (what useSessionBinding mounts)", () => {
  /** The part of a BroadcastChannel the binding uses, with a way to deliver a message. */
  function fakeChannel() {
    const listeners = new Set<(e: Event) => void>();
    return {
      addEventListener: (_type: string, l: (e: Event) => void) => void listeners.add(l),
      removeEventListener: (_type: string, l: (e: Event) => void) => void listeners.delete(l),
      deliver: (data: unknown) => listeners.forEach((l) => l({data} as unknown as Event)),
      count: () => listeners.size,
    };
  }

  function setup(pathname = "/fa/profiles") {
    const assign = vi.fn();
    vi.stubGlobal("window", {location: {assign, pathname}});
    vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
    const queryClient = new QueryClient();
    const channel = fakeChannel();
    return {assign, queryClient, channel};
  }

  it("a refused refresh clears and leaves with next, read when it happens", () => {
    const {assign, queryClient, channel} = setup();
    let next: string | undefined = "/profiles";
    const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => next}, channel);
    next = "/preferences/account";
    handleSessionEnded();
    expect(assign).toHaveBeenCalledExactlyOnceWith("/fa/login?next=%2Fpreferences%2Faccount");
    stop();
  });

  it("does not leave the login page for the login page", () => {
    const {assign, queryClient, channel} = setup("/fa/login");
    const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, channel);
    handleSessionEnded();
    channel.deliver("logout");
    expect(assign).not.toHaveBeenCalled();
    stop();
  });

  it("another tab's logout clears and leaves here without telling the others again", async () => {
    const {assign, queryClient, channel} = setup();
    queryClient.setQueryData(meKeys.all, meFixture());
    let message: unknown = "none";
    const other = new BroadcastChannel(SESSION_CHANNEL);
    other.onmessage = (e: MessageEvent) => (message = e.data);
    const stop = startSessionBinding(queryClient, {locale: "en", currentNext: () => "/profiles"}, channel);
    channel.deliver("logout");
    await new Promise((r) => setTimeout(r, 30));
    other.close();
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(assign).toHaveBeenCalledExactlyOnceWith("/en/login");
    expect(message).toBe("none");
    stop();
  });

  it("another tab's login refetches /me, and nothing else", () => {
    const {assign, queryClient, channel} = setup();
    const invalidate = vi.spyOn(queryClient, "invalidateQueries").mockResolvedValue();
    const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, channel);
    channel.deliver("login");
    expect(invalidate).toHaveBeenCalledExactlyOnceWith({queryKey: meKeys.all});
    expect(assign).not.toHaveBeenCalled();
    stop();
  });

  describe("another account in the same browser (wp4-r2-1, wp4-r2-5)", () => {
    const other = () => meFixture({user: {id: "00000000-0000-4000-8000-0000000000b2"}});
    const otherTenant = () => meFixture({tenant: {id: "00000000-0000-4000-8000-0000000000c3"}});

    function reloading() {
      const reload = vi.fn();
      const assign = vi.fn();
      vi.stubGlobal("window", {location: {assign, reload, pathname: "/fa/preferences/account"}});
      vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
      const queryClient = new QueryClient();
      // The data of user A, in the kind of keys every screen uses: nothing in them names the user.
      queryClient.setQueryData(meKeys.all, meFixture());
      queryClient.setQueryData(["notifications", "list"], {pages: [{items: ["note of A"]}]});
      queryClient.setQueryData(["account", "sessions"], [{ip: "198.51.100.7"}]);
      return {reload, assign, queryClient};
    }

    /** A /me answer, delivered the way TanStack does: through the cache. */
    const answer = (queryClient: QueryClient, me: ReturnType<typeof meFixture>) =>
      queryClient.fetchQuery({queryKey: meKeys.all, queryFn: () => me, staleTime: 0});

    it("a /me for another user drops every cached row and loads the page again", async () => {
      const {reload, assign, queryClient} = reloading();
      const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, fakeChannel());
      await answer(queryClient, other());
      await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
      expect(queryClient.getQueryData(["notifications", "list"])).toBeUndefined();
      expect(queryClient.getQueryData(["account", "sessions"])).toBeUndefined();
      expect(queryClient.getQueryData(meKeys.all)).toBeUndefined();
      expect(assign).not.toHaveBeenCalled();
      stop();
    });

    it("a /me for the same user in another tenant counts as another account", async () => {
      const {reload, queryClient} = reloading();
      const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, fakeChannel());
      await answer(queryClient, otherTenant());
      await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
      stop();
    });

    it("a /me for the same account keeps the cache and does not reload", async () => {
      const {reload, queryClient} = reloading();
      const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, fakeChannel());
      await answer(queryClient, meFixture({user: {theme: "dark"}}));
      await new Promise((r) => setTimeout(r, 30));
      expect(reload).not.toHaveBeenCalled();
      expect(queryClient.getQueryData(["notifications", "list"])).toBeDefined();
      stop();
    });

    it("another tab's login as someone else, through the message, ends in a reload", async () => {
      const {reload, queryClient} = reloading();
      const channel = fakeChannel();
      const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, channel);
      const observer = new QueryObserver(queryClient, {queryKey: meKeys.all, queryFn: () => other(), staleTime: 60_000});
      const unsubscribe = observer.subscribe(() => undefined);
      channel.deliver("login");
      await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
      expect(queryClient.getQueryData(["account", "sessions"])).toBeUndefined();
      unsubscribe();
      stop();
    });

    it("the first /me only records who this tab is, and a stopped watch reloads nothing", async () => {
      const {reload, queryClient} = reloading();
      queryClient.removeQueries({queryKey: meKeys.all});
      const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, fakeChannel());
      await answer(queryClient, meFixture());
      stop();
      await answer(queryClient, other());
      await new Promise((r) => setTimeout(r, 30));
      expect(reload).not.toHaveBeenCalled();
    });

    it("admin has the same rule over its own /me, by username", async () => {
      const {reload, queryClient} = reloading();
      const key = adminMeKeys.all;
      queryClient.setQueryData(key, adminMeFixture({username: "first"}));
      queryClient.setQueryData(["admin", "users"], [{id: "u1"}]);
      const stop = watchIdentity<AdminMe>(queryClient, key, (me) => me.username);
      await queryClient.fetchQuery({queryKey: key, queryFn: () => adminMeFixture({username: "first"}), staleTime: 0});
      await new Promise((r) => setTimeout(r, 30));
      expect(reload).not.toHaveBeenCalled();
      await queryClient.fetchQuery({queryKey: key, queryFn: () => adminMeFixture({username: "second"}), staleTime: 0});
      await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
      expect(queryClient.getQueryData(["admin", "users"])).toBeUndefined();
      stop();
    });

    it("reloads once even when two watchers (two mounts) see the change", async () => {
      const {reload, queryClient} = reloading();
      const a = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, fakeChannel());
      const b = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, fakeChannel());
      await answer(queryClient, other());
      await vi.waitFor(() => expect(reload).toHaveBeenCalled());
      await new Promise((r) => setTimeout(r, 30));
      expect(reload).toHaveBeenCalledTimes(1);
      a();
      b();
    });
  });

  it("ignores a message that is not one of the two words, and stops listening when it is removed", () => {
    const {assign, queryClient, channel} = setup();
    const stop = startSessionBinding(queryClient, {locale: "fa", currentNext: () => undefined}, channel);
    channel.deliver("LOGOUT");
    channel.deliver({type: "logout"});
    expect(assign).not.toHaveBeenCalled();
    expect(channel.count()).toBe(1);
    stop();
    expect(channel.count()).toBe(0);
    handleSessionEnded();
    expect(assign).not.toHaveBeenCalled();
  });
});
