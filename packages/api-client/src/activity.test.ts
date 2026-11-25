import {environmentManager, onlineManager, QueryClient, QueryObserver} from "@tanstack/react-query";
import {afterEach, describe, expect, it, vi} from "vitest";

import {meFixture} from "./testing/fixtures.ts";
import {adminMeQueryOptions} from "./admin/session.ts";
import {
  ADMIN_IDLE_PAUSE_MS,
  ADMIN_PRESENCE_KEY,
  browserPresence,
  SHARED_WRITE_MS,
  type SharedPresence,
  ADMIN_SESSION_IDLE_MS,
  getIdleState,
  holdSignedInSurface,
  idlePauseMs,
  IDLE_PAUSE_MS,
  isUserPresent,
  pollEvery,
  refetchWhenPresent,
  SESSION_IDLE_MS,
  sessionIdleMs,
  subscribeIdleState,
  uncoverPage,
  INPUT_EVENTS,
  watchActivity,
} from "./activity.ts";
import {announcementsQueryOptions} from "./hooks/announcements.ts";
import {meQueryOptions} from "./hooks/me.ts";
import {notificationsQueryOptions, POLL_MS} from "./hooks/notifications.ts";
import {queryDefaults} from "./queryDefaults.ts";

afterEach(() => vi.useRealTimers());

/**
 * A window that can deliver events. `fire` sends what a person's input looks like: trusted, and with the
 * window itself as the target (so a `focus` is the window's own). `extra` is what a case changes.
 */
function fakeTarget() {
  const listeners = new Map<string, Set<(event: Event) => void>>();
  const target = {
    addEventListener: (type: string, l: (event: Event) => void) => void (listeners.get(type) ?? listeners.set(type, new Set()).get(type)!).add(l),
    removeEventListener: (type: string, l: (event: Event) => void) => void listeners.get(type)?.delete(l),
    fire: (type: string, extra: Record<string, unknown> = {}) =>
      listeners.get(type)?.forEach((l) => l({type, isTrusted: true, target, ...extra} as unknown as Event)),
    count: () => [...listeners.values()].reduce((n, set) => n + set.size, 0),
  };
  return target;
}

describe("the poll runs only while a person is at the page (wp4-r2-2)", () => {
  it("polls every interval while there is input, and stops after IDLE_PAUSE_MS without any", () => {
    vi.useFakeTimers();
    const queryClient = new QueryClient();
    const target = fakeTarget();
    const stop = watchActivity(queryClient, target);
    const every = pollEvery(POLL_MS);
    expect(every()).toBe(POLL_MS);
    vi.advanceTimersByTime(IDLE_PAUSE_MS - 1);
    expect(every()).toBe(POLL_MS);
    vi.advanceTimersByTime(2);
    expect(every()).toBe(false);
    expect(isUserPresent()).toBe(false);
    stop();
  });

  it("any input starts the count again", () => {
    vi.useFakeTimers();
    const queryClient = new QueryClient();
    const target = fakeTarget();
    const stop = watchActivity(queryClient, target);
    vi.advanceTimersByTime(IDLE_PAUSE_MS - 1_000);
    target.fire("keydown");
    vi.advanceTimersByTime(IDLE_PAUSE_MS - 1_000);
    expect(isUserPresent()).toBe(true);
    stop();
  });

  it("the first input after a pause refetches every active query: what the gate skipped is fetched now", async () => {
    vi.useFakeTimers({toFake: ["Date"]});
    const queryClient = new QueryClient();
    const polled = vi.fn(async () => "x");
    const other = vi.fn(async () => "y");
    const a = new QueryObserver(queryClient, {queryKey: ["notifications", "list"], queryFn: polled, staleTime: 60_000});
    const b = new QueryObserver(queryClient, {queryKey: ["account", "sessions"], queryFn: other, staleTime: 60_000});
    const unsubA = a.subscribe(() => undefined);
    const unsubB = b.subscribe(() => undefined);
    await vi.waitFor(() => expect(polled).toHaveBeenCalledTimes(1));
    const target = fakeTarget();
    const stop = watchActivity(queryClient, target);
    // Input while present: no refetch.
    target.fire("pointermove");
    await Promise.resolve();
    expect(polled).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + IDLE_PAUSE_MS + 1);
    target.fire("pointermove");
    await vi.waitFor(() => expect(polled).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(other).toHaveBeenCalledTimes(2));
    // And the interval runs again.
    expect(pollEvery(POLL_MS)()).toBe(POLL_MS);
    stop();
    unsubA();
    unsubB();
  });

  // wp4-r7-1: a screen-reader activate on a phone is a bare click, and a form fill is an input event.
  it.each(["click", "input"])("a bare %s counts as presence and takes the page up again after a pause", async (name) => {
    vi.useFakeTimers({toFake: ["Date"]});
    const queryClient = new QueryClient();
    const fetcher = vi.fn(async () => "x");
    const observer = new QueryObserver(queryClient, {queryKey: ["notifications", "list"], queryFn: fetcher, staleTime: 60_000});
    const unsubscribe = observer.subscribe(() => undefined);
    // Wait for the answer, not only the call: an invalidation that meets a fetch in flight is absorbed by it.
    await vi.waitFor(() => expect(observer.getCurrentResult().isSuccess).toBe(true));
    const target = fakeTarget();
    const stop = watchActivity(queryClient, target);
    vi.setSystemTime(Date.now() + IDLE_PAUSE_MS + 1);
    expect(isUserPresent()).toBe(false);
    target.fire(name);
    expect(isUserPresent()).toBe(true);
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    stop();
    unsubscribe();
  });

  it("listens for every input kind as a passive capturing listener, and scroll is not one of them (wp4-r8-3)", () => {
    const calls: Array<[string, unknown]> = [];
    const target = {addEventListener: (type: string, _l: unknown, options: unknown) => void calls.push([type, options]), removeEventListener: () => undefined};
    const stop = watchActivity(new QueryClient(), target);
    expect(calls.map(([type]) => type).sort()).toEqual([...INPUT_EVENTS].sort());
    for (const [, options] of calls) expect(options).toEqual({passive: true, capture: true});
    expect(INPUT_EVENTS).toEqual(expect.arrayContaining(["click", "input"]));
    expect(INPUT_EVENTS).not.toContain("scroll");
    stop();
  });

  // wp4-r8-1, r8-3. The class: an event the browser or the page made, not a person. Presence stays closed
  // after the pause, so a banner that goes away, a row that changes height, a focus the page moved or a
  // script's click can neither refetch nor slide the session.
  describe("events nobody at the page made do not count (wp4-r8-1, wp4-r8-3)", () => {
    async function paused() {
      vi.useFakeTimers({toFake: ["Date"]});
      const queryClient = new QueryClient();
      const fetcher = vi.fn(async () => "x");
      const observer = new QueryObserver(queryClient, {queryKey: ["notifications", "list"], queryFn: fetcher, staleTime: 60_000});
      const unsubscribe = observer.subscribe(() => undefined);
      await vi.waitFor(() => expect(observer.getCurrentResult().isSuccess).toBe(true));
      const target = fakeTarget();
      const stop = watchActivity(queryClient, target);
      vi.setSystemTime(Date.now() + IDLE_PAUSE_MS + 1);
      expect(isUserPresent()).toBe(false);
      return {
        target,
        fetcher,
        done() {
          stop();
          unsubscribe();
        },
      };
    }

    it("a scroll with no other input sends no request and leaves presence closed: the browser fires one when layout clamps", async () => {
      const {target, fetcher, done} = await paused();
      target.fire("scroll");
      await new Promise((r) => setTimeout(r, 20));
      expect(isUserPresent()).toBe(false);
      expect(fetcher).toHaveBeenCalledTimes(1);
      done();
    });

    it("an element's focus, which the page moved by itself, does not count; the window's own does", async () => {
      const {target, fetcher, done} = await paused();
      target.fire("focus", {target: {tagName: "BUTTON"}});
      await new Promise((r) => setTimeout(r, 20));
      expect(isUserPresent()).toBe(false);
      expect(fetcher).toHaveBeenCalledTimes(1);
      target.fire("focus");
      expect(isUserPresent()).toBe(true);
      await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
      done();
    });

    it.each(["click", "keydown", "pointerdown", "pointermove", "touchstart", "wheel", "input"])(
      "a script's %s (isTrusted false) is not a person",
      async (name) => {
        const {target, fetcher, done} = await paused();
        target.fire(name, {isTrusted: false});
        await new Promise((r) => setTimeout(r, 20));
        expect(isUserPresent()).toBe(false);
        expect(fetcher).toHaveBeenCalledTimes(1);
        done();
      },
    );

    it("a pointermove that stayed where the pointer was (Chrome repeats it after a layout change) does not count; a real move does", async () => {
      const {target, fetcher, done} = await paused();
      target.fire("pointermove", {clientX: 10, clientY: 20});
      // The first one has nothing to compare with and counts, so go quiet again before the repeat.
      await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
      vi.setSystemTime(Date.now() + IDLE_PAUSE_MS + 1);
      target.fire("pointermove", {clientX: 10, clientY: 20});
      await new Promise((r) => setTimeout(r, 20));
      expect(isUserPresent()).toBe(false);
      expect(fetcher).toHaveBeenCalledTimes(2);
      target.fire("pointermove", {clientX: 11, clientY: 20});
      expect(isUserPresent()).toBe(true);
      done();
    });

    it("a banner that goes away under a scrolled, unattended page and a reconnect do not reopen presence", async () => {
      const {target, fetcher, done} = await paused();
      onlineManager.setOnline(false);
      onlineManager.setOnline(true);
      // The offline banner leaves, the scroller clamps, and the browser fires scroll (measured in Chrome).
      target.fire("scroll");
      await new Promise((r) => setTimeout(r, 20));
      expect(isUserPresent()).toBe(false);
      expect(fetcher).toHaveBeenCalledTimes(1);
      done();
    });
  });

  it("removes every listener it added", () => {
    const target = fakeTarget();
    const stop = watchActivity(new QueryClient(), target);
    expect(target.count()).toBeGreaterThan(0);
    stop();
    expect(target.count()).toBe(0);
  });

  it("both feeds use the rule", () => {
    for (const options of [notificationsQueryOptions(), announcementsQueryOptions()]) {
      const every = options.refetchInterval as () => number | false;
      expect(every()).toBeTypeOf("number");
    }
  });

  it("TanStack follows the function: a false interval means no further fetch", async () => {
    // Node counts as a server, where TanStack schedules no interval at all.
    environmentManager.setIsServer(() => false);
    vi.useFakeTimers();
    const queryClient = new QueryClient();
    const fetcher = vi.fn(async () => "x");
    let present = true;
    const observer = new QueryObserver(queryClient, {queryKey: ["poll"], queryFn: fetcher, refetchInterval: () => (present ? 1_000 : false)});
    const unsubscribe = observer.subscribe(() => undefined);
    await vi.advanceTimersByTimeAsync(3_500);
    const whilePresent = fetcher.mock.calls.length;
    expect(whilePresent).toBeGreaterThanOrEqual(3);
    present = false;
    await vi.advanceTimersByTimeAsync(1_100); // the next fetch evaluates the function and stops the timer
    const atStop = fetcher.mock.calls.length;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetcher.mock.calls.length).toBe(atStop);
    unsubscribe();
    environmentManager.setIsServer(() => true);
  });
});

// wp4-r3-7: the interval was the only automatic refetch that stopped. A network that drops and comes
// back fires "online", and every stale query with an observer then fetched, which slides the idle limit.
describe("a reconnect or a focus with nobody at the page fetches nothing (wp4-r3-7)", () => {
  const stubs = () => ({
    me: vi.fn(async () => meFixture()),
    feed: vi.fn(async () => "feed"),
    sessions: vi.fn(async () => "sessions"),
  });

  /** The client as the app builds it, with /me, a feed and a plain query, each already fetched once and stale. */
  async function mounted(idleMs?: number) {
    // Node counts as a server, where TanStack subscribes to nothing.
    environmentManager.setIsServer(() => false);
    vi.useFakeTimers({toFake: ["Date"]});
    const queryClient = new QueryClient({defaultOptions: {queries: {...queryDefaults, staleTime: 0}}});
    queryClient.mount();
    const f = stubs();
    // The real option objects of /me and the feeds, with the network function swapped for a counter.
    const observers = [
      new QueryObserver(queryClient, {...meQueryOptions(), queryFn: f.me, staleTime: 0}),
      new QueryObserver(queryClient, {queryKey: ["notifications", "list"], queryFn: f.feed}),
      new QueryObserver(queryClient, {queryKey: ["account", "sessions"], queryFn: f.sessions}),
    ];
    const unsubscribe = observers.map((o) => o.subscribe(() => undefined));
    await vi.waitFor(() => expect(f.me).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(f.sessions).toHaveBeenCalledTimes(1));
    const target = fakeTarget();
    const stopWatching = watchActivity(queryClient, target, idleMs === undefined ? undefined : {idleMs});
    return {
      queryClient,
      f,
      target,
      stop() {
        stopWatching();
        for (const u of unsubscribe) u();
        queryClient.unmount();
        environmentManager.setIsServer(() => true);
        onlineManager.setOnline(true);
      },
    };
  }

  const total = (f: ReturnType<typeof stubs>) => f.me.mock.calls.length + f.feed.mock.calls.length + f.sessions.mock.calls.length;

  it("after IDLE_PAUSE_MS an offline-online cycle sends no request, and the first input then fetches", async () => {
    const {f, target, stop} = await mounted();
    vi.setSystemTime(Date.now() + IDLE_PAUSE_MS + 1);
    const before = total(f);
    onlineManager.setOnline(false);
    onlineManager.setOnline(true);
    await Promise.resolve();
    await new Promise((r) => setTimeout(r, 20));
    expect(total(f)).toBe(before);

    target.fire("pointermove");
    await vi.waitFor(() => expect(total(f)).toBeGreaterThan(before));
    stop();
  });

  // wp4-r4-3, the window of the admin app
  it("an admin offline-online cycle 6 minutes after the last input sends no /me", async () => {
    const {f, stop} = await mounted(idlePauseMs("admin"));
    vi.setSystemTime(Date.now() + 6 * 60_000);
    const before = f.me.mock.calls.length;
    onlineManager.setOnline(false);
    onlineManager.setOnline(true);
    await Promise.resolve();
    await new Promise((r) => setTimeout(r, 20));
    expect(f.me.mock.calls.length).toBe(before);
    stop();
  });

  it("with a person at the page a reconnect still refetches (the gate is not a switch-off)", async () => {
    const {f, stop} = await mounted();
    const before = total(f);
    onlineManager.setOnline(false);
    onlineManager.setOnline(true);
    await vi.waitFor(() => expect(total(f)).toBeGreaterThan(before));
    stop();
  });

  it("every automatic refetch of the panel and admin queries answers to the one gate", () => {
    expect(queryDefaults.refetchOnReconnect).toBe(refetchWhenPresent);
    expect(meQueryOptions().refetchOnWindowFocus).toBe(refetchWhenPresent);
    expect(adminMeQueryOptions().refetchOnWindowFocus).toBe(refetchWhenPresent);
    // And the gate really closes.
    vi.useFakeTimers({toFake: ["Date"]});
    const stop = watchActivity(new QueryClient(), fakeTarget());
    expect(refetchWhenPresent()).toBe(true);
    vi.setSystemTime(Date.now() + IDLE_PAUSE_MS + 1);
    expect(refetchWhenPresent()).toBe(false);
    stop();
  });
});

// wp4-r4-3: the admin session idles out after 15 min (R44). A 30 min gate would let every reconnect
// slide it for 30 more, so the window is the app's, and stays under that app's idle limit.
describe("the presence window is the app's own (wp4-r4-3)", () => {
  it("is shorter than each app's idle limit", () => {
    expect(idlePauseMs("panel")).toBe(IDLE_PAUSE_MS);
    expect(idlePauseMs("admin")).toBe(ADMIN_IDLE_PAUSE_MS);
    expect(IDLE_PAUSE_MS).toBeLessThan(2 * 60 * 60_000);
    expect(ADMIN_IDLE_PAUSE_MS).toBeLessThan(15 * 60_000);
  });

  it("the gate of the admin closes after its window, and the panel's is still open then", () => {
    vi.useFakeTimers({toFake: ["Date"]});
    const admin = watchActivity(new QueryClient(), fakeTarget(), {idleMs: idlePauseMs("admin")});
    vi.setSystemTime(Date.now() + 6 * 60_000);
    expect(refetchWhenPresent()).toBe(false);
    admin();
    const panel = watchActivity(new QueryClient(), fakeTarget(), {idleMs: idlePauseMs("panel")});
    vi.setSystemTime(Date.now() + 6 * 60_000);
    expect(refetchWhenPresent()).toBe(true);
    panel();
  });

});

// wp4-r6-3: after the presence pause nothing sends a request, so nothing ever sees the 401 of a session
// that idled out on the server, and the account stays on screen for whoever walks up to the tab.
describe("the idle cover (wp4-r6-3)", () => {
  const MIN = 60_000;

  /** A signed-in page, a cached account, and one observer that counts the requests the page would send. */
  function signedIn(app: "panel" | "admin" = "admin", {surface = true}: {surface?: boolean} = {}) {
    vi.useFakeTimers();
    const queryClient = new QueryClient();
    queryClient.setQueryData(["admin", "users"], [{phone: "0912"}]);
    const target = fakeTarget();
    const release = surface ? holdSignedInSurface() : () => undefined;
    const stopWatching = watchActivity(queryClient, target, {idleMs: idlePauseMs(app), coverMs: sessionIdleMs(app)});
    return {
      queryClient,
      target,
      stop() {
        stopWatching();
        release();
      },
    };
  }

  it("the cover limit is the session's idle limit, per app, and the presence window stays under it", () => {
    expect(sessionIdleMs("panel")).toBe(SESSION_IDLE_MS);
    expect(sessionIdleMs("admin")).toBe(ADMIN_SESSION_IDLE_MS);
    expect(SESSION_IDLE_MS).toBe(2 * 60 * MIN);
    expect(ADMIN_SESSION_IDLE_MS).toBe(15 * MIN);
    expect(idlePauseMs("panel")).toBeLessThan(SESSION_IDLE_MS);
    expect(idlePauseMs("admin")).toBeLessThan(ADMIN_SESSION_IDLE_MS);
  });

  it("admin: 15 minutes with no input covers the page and clears the cache, with no request", async () => {
    const {queryClient, stop} = signedIn("admin");
    const fetcher = vi.fn(async () => "x");
    const unsubscribe = new QueryObserver(queryClient, {queryKey: ["admin", "alerts"], queryFn: fetcher, enabled: false}).subscribe(() => undefined);
    vi.advanceTimersByTime(15 * MIN - 1_000);
    expect(getIdleState().covered).toBe(false);
    expect(queryClient.getQueryData(["admin", "users"])).toBeDefined();
    vi.advanceTimersByTime(2_000);
    expect(getIdleState()).toEqual({covered: true, ending: true, epoch: 1});
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(60 * MIN);
    expect(fetcher).not.toHaveBeenCalled();
    unsubscribe();
    stop();
  });

  it("the panel is covered after 2 hours, not before", () => {
    const {stop} = signedIn("panel");
    vi.advanceTimersByTime(2 * 60 * MIN - 1_000);
    expect(getIdleState().covered).toBe(false);
    vi.advanceTimersByTime(2_000);
    expect(getIdleState().covered).toBe(true);
    stop();
  });

  it("input keeps the page: the limit counts from the last one", () => {
    const {target, stop} = signedIn("admin");
    vi.advanceTimersByTime(14 * MIN);
    target.fire("keydown");
    vi.advanceTimersByTime(14 * MIN);
    expect(getIdleState().covered).toBe(false);
    vi.advanceTimersByTime(2 * MIN);
    expect(getIdleState().covered).toBe(true);
    stop();
  });

  it("input does not uncover the page: only uncoverPage does, as a fresh mount, and the limit starts again", () => {
    const {queryClient, target, stop} = signedIn("admin");
    vi.advanceTimersByTime(16 * MIN);
    expect(getIdleState()).toEqual({covered: true, ending: true, epoch: 1});
    // A mouse sensor that jitters, a desk that is knocked, an alt-tab, a stray click (wp4-r7-1).
    for (const name of INPUT_EVENTS) target.fire(name);
    expect(getIdleState()).toEqual({covered: true, ending: true, epoch: 1});
    uncoverPage();
    expect(getIdleState()).toEqual({covered: false, ending: true, epoch: 1});
    // Nothing was refetched from a cache that is empty; the remounted gate asks /me itself.
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    vi.advanceTimersByTime(14 * MIN);
    expect(getIdleState().covered).toBe(false);
    vi.advanceTimersByTime(2 * MIN);
    expect(getIdleState().covered).toBe(true);
    stop();
  });

  it("input while covered does not count as presence either", () => {
    const {target, stop} = signedIn("admin");
    vi.advanceTimersByTime(16 * MIN);
    target.fire("pointermove");
    expect(isUserPresent()).toBe(false);
    stop();
  });

  it("uncoverPage on a page that is not covered does nothing", () => {
    const {stop} = signedIn("admin");
    uncoverPage();
    expect(getIdleState()).toEqual({covered: false, ending: true, epoch: 0});
    stop();
  });

  it("a timer that fired late (a laptop that slept) is caught by the first input: the page is covered, and the input does not bring it back", () => {
    const {queryClient, target, stop} = signedIn("admin");
    // The clock jumps and no timer runs, as after sleep. The wake-up is an input.
    vi.setSystemTime(Date.now() + 3 * 60 * MIN);
    target.fire("focus");
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(getIdleState()).toEqual({covered: true, ending: true, epoch: 1});
    target.fire("pointermove");
    expect(getIdleState()).toEqual({covered: true, ending: true, epoch: 1});
    stop();
  });

  it("covers only a signed-in surface: a login form that waited for a code is left alone", () => {
    const {queryClient, target, stop} = signedIn("admin", {surface: false});
    vi.advanceTimersByTime(20 * MIN);
    expect(getIdleState().covered).toBe(false);
    expect(queryClient.getQueryData(["admin", "users"])).toBeDefined();
    vi.setSystemTime(Date.now() + 3 * 60 * MIN);
    target.fire("pointermove");
    expect(getIdleState()).toEqual({covered: false, ending: true, epoch: 0});
    stop();
  });

  it("a surface that was released (the page unmounted) is no surface", () => {
    vi.useFakeTimers();
    const queryClient = new QueryClient();
    const stop = watchActivity(queryClient, fakeTarget(), {idleMs: ADMIN_IDLE_PAUSE_MS, coverMs: ADMIN_SESSION_IDLE_MS});
    const release = holdSignedInSurface();
    release();
    release();
    vi.advanceTimersByTime(20 * MIN);
    expect(getIdleState().covered).toBe(false);
    stop();
  });

  it("tells its listeners, and stopping the watch puts the page back", () => {
    const {stop} = signedIn("admin");
    const heard = vi.fn();
    const off = subscribeIdleState(heard);
    vi.advanceTimersByTime(16 * MIN);
    expect(heard).toHaveBeenCalledTimes(1);
    stop();
    expect(getIdleState()).toEqual({covered: false, ending: true, epoch: 0});
    off();
  });

  it("the presence pause still works under the cover limit: the first input before it refetches, as before", async () => {
    vi.useFakeTimers({toFake: ["Date"]});
    const queryClient = new QueryClient();
    const fetcher = vi.fn(async () => "x");
    const unsubscribe = new QueryObserver(queryClient, {queryKey: ["admin", "alerts"], queryFn: fetcher, staleTime: 60 * MIN}).subscribe(() => undefined);
    // Settled, not only started: an invalidation meets a fetch still in flight and joins it.
    await vi.waitFor(() => expect(queryClient.getQueryState(["admin", "alerts"])?.fetchStatus).toBe("idle"));
    expect(fetcher).toHaveBeenCalledTimes(1);
    const target = fakeTarget();
    const release = holdSignedInSurface();
    const stop = watchActivity(queryClient, target, {idleMs: ADMIN_IDLE_PAUSE_MS, coverMs: ADMIN_SESSION_IDLE_MS});
    vi.setSystemTime(Date.now() + 6 * MIN);
    target.fire("pointermove");
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(getIdleState().covered).toBe(false);
    unsubscribe();
    release();
    stop();
  });
});

// wp4-r9-3: the admin session is one cookie that every admin tab shares, but lastInput is one document's.
// A background tab gets no input, so by its own clock it would end the session while the admin works in
// another tab. A fake store stands for localStorage, and a write to it stands for the other tab's input
// (the module keeps one watch at a time, so a second watchActivity in this process cannot be the other tab).
describe("presence shared across the admin tabs (wp4-r9-3)", () => {
  const MIN = 60_000;

  function fakeStore(): SharedPresence & {value: number | undefined; writes: number[]} {
    const store = {
      value: undefined as number | undefined,
      writes: [] as number[],
      read: () => store.value,
      write: (ms: number) => {
        store.value = ms;
        store.writes.push(ms);
      },
    };
    return store;
  }

  function adminTab(shared: SharedPresence) {
    vi.useFakeTimers();
    const queryClient = new QueryClient();
    const onCover = vi.fn();
    const target = fakeTarget();
    // As in the app: the cover unmounts the page, and the gate's cleanup releases the surface. It happens
    // right after the cover has called its handlers, so by the recheck there is no surface left (wp4-r11-4).
    const release = holdSignedInSurface((info) => {
      onCover(info);
      release();
    });
    const stopWatching = watchActivity(queryClient, target, {idleMs: ADMIN_IDLE_PAUSE_MS, coverMs: ADMIN_SESSION_IDLE_MS, shared});
    return {
      target,
      onCover,
      stop() {
        stopWatching();
        release();
      },
    };
  }

  it("a tab whose own input is old covers itself but is told the session is live when another tab had input", () => {
    const store = fakeStore();
    const {onCover, stop} = adminTab(store);
    // The other tab: input at minute 10 of this tab's silence.
    vi.advanceTimersByTime(10 * MIN);
    store.value = Date.now();
    vi.advanceTimersByTime(5 * MIN + 1_000);
    expect(getIdleState()).toMatchObject({covered: true, ending: false});
    expect(onCover).toHaveBeenCalledExactlyOnceWith({sessionLive: true});
    stop();
  });

  it("15 minutes with no input in any tab: the cover is told to end the session, exactly once", () => {
    const store = fakeStore();
    const {onCover, stop} = adminTab(store);
    vi.advanceTimersByTime(15 * MIN + 1_000);
    expect(getIdleState()).toMatchObject({covered: true, ending: true});
    expect(onCover).toHaveBeenCalledExactlyOnceWith({sessionLive: false});
    vi.advanceTimersByTime(60 * MIN);
    expect(onCover).toHaveBeenCalledTimes(1);
    stop();
  });

  it("another tab's input that is itself older than the limit does not keep the session", () => {
    const store = fakeStore();
    const {onCover, stop} = adminTab(store);
    store.value = Date.now() - 30 * MIN;
    vi.advanceTimersByTime(15 * MIN + 1_000);
    expect(onCover).toHaveBeenCalledExactlyOnceWith({sessionLive: false});
    stop();
  });

  it("without usable storage nothing is shared and the tab ends the session (fails closed)", () => {
    const {onCover, stop} = adminTab({read: () => undefined, write: () => undefined});
    vi.advanceTimersByTime(15 * MIN + 1_000);
    expect(onCover).toHaveBeenCalledExactlyOnceWith({sessionLive: false});
    stop();
  });

  it("a stored time far in the future (a clock that moved back) is stale, not now", () => {
    const store = fakeStore();
    const {onCover, stop} = adminTab(store);
    store.value = Date.now() + 10 * 60 * MIN;
    vi.advanceTimersByTime(15 * MIN + 1_000);
    expect(onCover).toHaveBeenCalledExactlyOnceWith({sessionLive: false});
    stop();
  });

  it("a time a little ahead (a clock correction) counts as now, and the session still ends a limit after it", () => {
    const store = fakeStore();
    const {onCover, stop} = adminTab(store);
    vi.advanceTimersByTime(15 * MIN - 1_000);
    store.value = Date.now() + 30_000;
    vi.advanceTimersByTime(2_000);
    expect(onCover).toHaveBeenCalledExactlyOnceWith({sessionLive: true});
    vi.advanceTimersByTime(16 * MIN);
    expect(onCover).toHaveBeenLastCalledWith({sessionLive: false});
    expect(onCover).toHaveBeenCalledTimes(2);
    stop();
  });

  // wp4-r10-1 and r10-4: the tab covered while another tab was in use must not wait for that other tab to end
  // the session, which it cannot do once it is closed.
  describe("a tab covered while another tab was in use (wp4-r10-1, r10-4)", () => {
    it("ends the session by itself when the other tab goes away: exactly one end, never earlier", () => {
      const store = fakeStore();
      const {onCover, stop} = adminTab(store);
      // The other tab has input at minute 10 and is then closed: it never writes again.
      vi.advanceTimersByTime(10 * MIN);
      store.value = Date.now();
      vi.advanceTimersByTime(5 * MIN + 1_000);
      expect(onCover).toHaveBeenCalledExactlyOnceWith({sessionLive: true});
      expect(getIdleState().ending).toBe(false);
      // Minute 24: the other tab’s input is still inside the limit.
      vi.advanceTimersByTime(9 * MIN);
      expect(onCover).toHaveBeenCalledTimes(1);
      // Minute 25 and a little: fifteen minutes after that input, nothing else has been written.
      vi.advanceTimersByTime(MIN);
      expect(onCover).toHaveBeenCalledTimes(2);
      expect(onCover).toHaveBeenLastCalledWith({sessionLive: false});
      expect(getIdleState()).toMatchObject({covered: true, ending: true});
      vi.advanceTimersByTime(120 * MIN);
      expect(onCover).toHaveBeenCalledTimes(2);
      stop();
    });

    it("keeps waiting while the other tab goes on having input, and ends a limit after its last one", () => {
      const store = fakeStore();
      const {onCover, stop} = adminTab(store);
      vi.advanceTimersByTime(10 * MIN);
      store.value = Date.now();
      vi.advanceTimersByTime(5 * MIN + 1_000);
      expect(onCover).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(4 * MIN);
      store.value = Date.now(); // about minute 19: the other tab is still being used
      vi.advanceTimersByTime(7 * MIN); // minute 26: past the first input's limit, inside the second's
      expect(onCover).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(9 * MIN); // minute 35: a limit after minute 19
      expect(onCover).toHaveBeenCalledTimes(2);
      expect(onCover).toHaveBeenLastCalledWith({sessionLive: false});
      stop();
    });

    // wp4-r11-4: the page is unmounted by the cover, so no surface is held while Continue is pressed. The
    // write is what tells the other tabs that this one is in use again.
    it("Continue writes the shared store although the covered page holds no surface", () => {
      const store = fakeStore();
      const {stop} = adminTab(store);
      vi.advanceTimersByTime(10 * MIN);
      store.value = Date.now();
      vi.advanceTimersByTime(5 * MIN + 1_000);
      expect(getIdleState().covered).toBe(true);
      expect(store.writes).toHaveLength(0);
      uncoverPage();
      expect(store.writes).toHaveLength(1);
      expect(store.value).toBe(Date.now());
      stop();
    });

    it("Continue before the limit runs out cancels the look: it ends nothing", () => {
      const store = fakeStore();
      const {target, onCover, stop} = adminTab(store);
      vi.advanceTimersByTime(10 * MIN);
      store.value = Date.now();
      vi.advanceTimersByTime(5 * MIN + 1_000);
      uncoverPage();
      expect(getIdleState().covered).toBe(false);
      target.fire("keydown");
      vi.advanceTimersByTime(14 * MIN);
      expect(onCover).toHaveBeenCalledTimes(1);
      stop();
    });
  });

  it("the page mounting writes nothing, and nothing is written without a signed-in surface (a login form)", () => {
    vi.useFakeTimers();
    const store = fakeStore();
    const target = fakeTarget();
    const stopWatching = watchActivity(new QueryClient(), target, {idleMs: ADMIN_IDLE_PAUSE_MS, coverMs: ADMIN_SESSION_IDLE_MS, shared: store});
    expect(store.writes).toHaveLength(0);
    target.fire("keydown");
    expect(store.writes).toHaveLength(0);
    stopWatching();

    const tab = adminTab(store);
    expect(store.writes).toHaveLength(0);
    tab.stop();
  });

  it("this tab's own input is written to the store, at most once per SHARED_WRITE_MS", () => {
    const store = fakeStore();
    const {target, stop} = adminTab(store);
    target.fire("keydown");
    expect(store.writes).toHaveLength(1);
    for (let i = 0; i < 5; i++) {
      vi.advanceTimersByTime(1_000);
      target.fire("keydown");
    }
    expect(store.writes).toHaveLength(1);
    vi.advanceTimersByTime(SHARED_WRITE_MS);
    target.fire("keydown");
    expect(store.writes).toHaveLength(2);
    expect(store.value).toBe(Date.now());
    stop();
  });

  it("the panel shares nothing: no store, no write", () => {
    vi.useFakeTimers();
    const onCover = vi.fn();
    const release = holdSignedInSurface(onCover);
    const stop = watchActivity(new QueryClient(), fakeTarget(), {idleMs: IDLE_PAUSE_MS, coverMs: SESSION_IDLE_MS});
    vi.advanceTimersByTime(SESSION_IDLE_MS + 1_000);
    expect(onCover).toHaveBeenCalledExactlyOnceWith({sessionLive: false});
    release();
    stop();
  });

  it("browserPresence reads and writes localStorage under its key, and survives storage that throws", () => {
    const data = new Map<string, string>();
    vi.stubGlobal("window", {localStorage: {getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v)}});
    const presence = browserPresence(ADMIN_PRESENCE_KEY);
    expect(presence.read()).toBeUndefined();
    presence.write(1234);
    expect(data.get(ADMIN_PRESENCE_KEY)).toBe("1234");
    expect(presence.read()).toBe(1234);
    data.set(ADMIN_PRESENCE_KEY, "not a number");
    expect(presence.read()).toBeUndefined();
    vi.stubGlobal("window", {
      get localStorage(): never {
        throw new Error("blocked");
      },
    });
    expect(presence.read()).toBeUndefined();
    expect(() => presence.write(5)).not.toThrow();
    vi.unstubAllGlobals();
  });
});
