import {readFileSync} from "node:fs";
import path from "node:path";
import {afterEach, describe, expect, it, vi} from "vitest";

import {isPageLeaving, markPageLeaving, resetPageLeaving} from "./pageLeaving.ts";

// wp8-r9-6: the language switch reloads the page, and React unmounts nothing for it. A page that has started
// that load is left, whatever the `here` and `mounted` checks of the sign-in code say.

afterEach(() => {
  resetPageLeaving();
  vi.unstubAllGlobals();
});

describe("pageLeaving", () => {
  it("is false until a load is started, and true after", () => {
    vi.stubGlobal("window", {addEventListener: () => undefined});
    expect(isPageLeaving()).toBe(false);
    markPageLeaving();
    expect(isPageLeaving()).toBe(true);
  });

  it("a page restored from the back/forward cache is live again; a normal pageshow changes nothing", async () => {
    // The listener is added on the first mark of a module instance, so this case takes a fresh one.
    vi.resetModules();
    const fresh = await import("./pageLeaving.ts");
    let onShow: ((event: {persisted: boolean}) => void) | undefined;
    vi.stubGlobal("window", {addEventListener: (type: string, fn: typeof onShow) => void (type === "pageshow" && (onShow = fn))});
    fresh.markPageLeaving();
    expect(onShow).toBeDefined();
    onShow!({persisted: false});
    expect(fresh.isPageLeaving()).toBe(true);
    onShow!({persisted: true});
    expect(fresh.isPageLeaving()).toBe(false);
  });
});


// wp8-r10-3: a load can end with no new document (Escape, Stop, window.stop()); no pagehide fires then, so the mark
// would stay for the life of the page and every sign-in on it would be ended.
describe("a load that is cancelled is not leaving", () => {
  class Target {
    private fns = new Map<string, Set<(event: Event) => void>>();
    addEventListener(type: string, fn: (event: Event) => void) {
      (this.fns.get(type) ?? this.fns.set(type, new Set()).get(type)!).add(fn);
    }
    removeEventListener(type: string, fn: (event: Event) => void) {
      this.fns.get(type)?.delete(fn);
    }
    fire(type: string, event: object = {}) {
      for (const fn of [...(this.fns.get(type) ?? [])]) fn(event as Event);
    }
  }

  const task = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

  async function fresh() {
    vi.resetModules();
    const mod = await import("./pageLeaving.ts");
    const navigation = new Target();
    vi.stubGlobal("window", Object.assign(new Target(), {navigation}));
    return {mod, navigation};
  }

  it("with the Navigation API: an abort that comes alone (Stop, Escape) clears the mark; a completed load does not", async () => {
    const {mod, navigation} = await fresh();
    mod.markPageLeaving();
    const load = new AbortController();
    navigation.fire("navigate", {signal: load.signal});
    await task();
    expect(mod.isPageLeaving()).toBe(true);
    load.abort();
    // The decision waits one task, to see whether a navigation comes with the abort.
    expect(mod.isPageLeaving()).toBe(true);
    await task();
    expect(mod.isPageLeaving()).toBe(false);
    // The next switch marks it again, with a new load.
    mod.markPageLeaving();
    expect(mod.isPageLeaving()).toBe(true);
  });

  // wp8-r11-4. Chrome aborts the signal of a pending load when a later navigation starts, and the load still commits.
  it("an abort with a same-document navigation (history.replaceState of the tab list) keeps the mark, in either order", async () => {
    for (const order of ["abort-first", "navigate-first"]) {
      const {mod, navigation} = await fresh();
      mod.markPageLeaving();
      const load = new AbortController();
      navigation.fire("navigate", {signal: load.signal});
      await task();
      const same = new AbortController();
      if (order === "abort-first") load.abort();
      navigation.fire("navigate", {signal: same.signal, destination: {sameDocument: true}});
      if (order === "navigate-first") load.abort();
      await task();
      await task();
      expect(mod.isPageLeaving(), order).toBe(true);
    }
  });

  it("an abort with a second cross-document load (a second language pick) keeps the mark and the second load is the one watched", async () => {
    for (const order of ["abort-first", "navigate-first"]) {
      const {mod, navigation} = await fresh();
      mod.markPageLeaving();
      const first = new AbortController();
      navigation.fire("navigate", {signal: first.signal});
      await task();
      // The second pick marks again, then starts its load.
      mod.markPageLeaving();
      const second = new AbortController();
      if (order === "abort-first") first.abort();
      navigation.fire("navigate", {signal: second.signal, destination: {sameDocument: false}});
      if (order === "navigate-first") first.abort();
      await task();
      await task();
      expect(mod.isPageLeaving(), order).toBe(true);
      // Cancelling the second load, with nothing following, is a Stop: the mark goes.
      second.abort();
      await task();
      expect(mod.isPageLeaving(), order).toBe(false);
    }
  });

  it("the abort of an older load that comes later, on its own, does not clear the mark of the newer one", async () => {
    const {mod, navigation} = await fresh();
    mod.markPageLeaving();
    const first = new AbortController();
    const second = new AbortController();
    navigation.fire("navigate", {signal: first.signal});
    await task();
    mod.markPageLeaving();
    navigation.fire("navigate", {signal: second.signal});
    await task();
    first.abort();
    await task();
    expect(mod.isPageLeaving()).toBe(true);
  });

  it("without it: the next key or click proves the page is alive", async () => {
    for (const type of ["keydown", "pointerdown"]) {
      vi.resetModules();
      const fresh = await import("./pageLeaving.ts");
      const win = new Target();
      vi.stubGlobal("window", win);
      fresh.markPageLeaving();
      expect(fresh.isPageLeaving()).toBe(true);
      win.fire(type);
      expect(fresh.isPageLeaving()).toBe(false);
    }
  });
});

describe("who asks and who marks", () => {
  const read = (rel: string) => readFileSync(path.resolve(import.meta.dirname, rel), "utf8");

  it("the language switch marks the page before it starts the load", () => {
    const source = read("localeSwitch.ts");
    expect(source.indexOf("markPageLeaving()")).toBeGreaterThan(-1);
    expect(source.indexOf("markPageLeaving()")).toBeLessThan(source.indexOf("window.location.replace"));
  });

  it("every path that finishes a sign-in asks: useCompleteSignIn and the passkey step", () => {
    expect(read("../auth/useCompleteSignIn.ts")).toMatch(/isPageLeaving\(\)/);
    expect(read("../auth/LoginSteps.tsx")).toMatch(/isPageLeaving\(\)/);
  });
});
