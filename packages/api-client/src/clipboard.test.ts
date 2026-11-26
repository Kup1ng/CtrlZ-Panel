import {afterEach, beforeEach, describe, expect, it, vi} from "vitest";

// gate-r5-8: a one-time secret that a copy put in the system clipboard is overwritten when the screen closes and at logout.
// gate-r6-6, gate-r6-7, gate-r6-8: a refused wipe is retried, a copy made by hand is noticed, a later copy of the person's own is left alone,
// and the page that a full load opens picks the wipe up again.

type Listener = (event?: unknown) => void;

function target() {
  const listeners = new Map<string, Set<Listener>>();
  return {
    listeners,
    addEventListener: (name: string, fn: Listener) => {
      if (!listeners.has(name)) listeners.set(name, new Set());
      listeners.get(name)!.add(fn);
    },
    removeEventListener: (name: string, fn: Listener) => {
      listeners.get(name)?.delete(fn);
    },
    dispatch: (name: string, extra: object = {}) => {
      for (const fn of Array.from(listeners.get(name) ?? [])) fn({type: name, ...extra});
    },
    count: () => Array.from(listeners.values()).reduce((n, set) => n + set.size, 0),
  };
}

type Env = ReturnType<typeof setupEnv>;

/** A browser as far as clipboard.ts looks at it: a window, a document with a selection, sessionStorage and a clipboard. */
function setupEnv(options: {write?: (text: string) => Promise<void>; flag?: boolean} = {}) {
  const win = target();
  const secret = {};
  // `text` is what the selection reads as; "" is a copy of nothing (Ctrl+C with nothing selected, gate-r7-9).
  const selection = {rangeCount: 1, isCollapsed: false, touches: false, text: "", containsNode: (el: unknown) => el === secret && selection.touches, toString: () => selection.text};
  const doc = Object.assign(target(), {
    visibilityState: "visible",
    activeElement: null as null | {selectionStart: number | null; selectionEnd: number | null},
    getSelection: () => selection,
    querySelectorAll: () => [secret],
  });
  const store = new Map<string, string>(options.flag ? [["ctrlz_clip_pending", "1"]] : []);
  const writeText = vi.fn(options.write ?? (async () => {}));
  vi.stubGlobal("window", win);
  vi.stubGlobal("document", doc);
  vi.stubGlobal("sessionStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  });
  vi.stubGlobal("navigator", {clipboard: {writeText}});
  // The other tabs of the origin, as far as clipboard.ts looks at them (gate-r7-10). Every channel object of the module is recorded, so a test
  // can read what this tab told the others and can speak as a sibling. The real BroadcastChannel would let the modules of different tests hear
  // each other, which is what a stub is for here.
  const posted: unknown[] = [];
  const channels: Array<{emit: (data: unknown) => void}> = [];
  class FakeChannel {
    private readonly handlers = new Set<Listener>();
    constructor(public readonly name: string) {
      channels.push(this);
    }
    addEventListener(_name: string, fn: Listener) {
      this.handlers.add(fn);
    }
    postMessage(data: unknown) {
      posted.push(data);
    }
    unref() {}
    emit(data: unknown) {
      for (const fn of Array.from(this.handlers)) fn({data});
    }
  }
  vi.stubGlobal("BroadcastChannel", FakeChannel);
  const sibling = (data: unknown) => channels.forEach((c) => c.emit(data));
  return {win, doc, selection, store, writeText, posted, sibling};
}

async function load() {
  vi.resetModules();
  return import("./clipboard.ts");
}

const flush = () => new Promise((r) => setTimeout(r, 0));
const pending = (env: Env) => env.store.get("ctrlz_clip_pending");

describe("copyOneTimeSecret and wipeCopiedSecret", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("writes the secret, and a wipe overwrites it with an empty string, once", async () => {
    const env = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("ABCD EFGH");
    expect(holdsCopiedSecret()).toBe(true);
    expect(pending(env)).toBe("1");
    expect(env.writeText).toHaveBeenLastCalledWith("ABCD EFGH");
    await wipeCopiedSecret();
    expect(env.writeText).toHaveBeenLastCalledWith("");
    expect(holdsCopiedSecret()).toBe(false);
    expect(pending(env)).toBeUndefined();
    await wipeCopiedSecret();
    expect(env.writeText).toHaveBeenCalledTimes(2);
  });

  // gate-r13-8. Copy, then Escape before the browser has answered: the cleanup's wipe finds nothing remembered, and the write lands afterwards.
  it("overwrites a copy that was still on its way when the wipe was asked for (gate-r13-8)", async () => {
    let land: () => void = () => {};
    const env = setupEnv({
      write: (text) => (text === "" ? Promise.resolve() : new Promise<void>((resolve) => void (land = resolve))),
    });
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    const copy = copyOneTimeSecret("SECRET");
    await wipeCopiedSecret(); // the dialog closed here
    expect(env.writeText, "the secret is not in the clipboard yet, so nothing is written over it").toHaveBeenCalledTimes(1);
    land();
    await copy;
    await flush();
    expect(env.writeText.mock.calls.map((c) => c[0])).toEqual(["SECRET", ""]);
    expect(holdsCopiedSecret()).toBe(false);
    expect(pending(env)).toBeUndefined();
  });

  it("does not let the wish to wipe of a copy that failed reach a later copy", async () => {
    let fail: (e: unknown) => void = () => {};
    const env = setupEnv({
      write: (text) => (text === "" ? Promise.resolve() : new Promise<void>((_, reject) => void (fail = reject))),
    });
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    const first = copyOneTimeSecret("A");
    await wipeCopiedSecret();
    fail(new DOMException("denied", "NotAllowedError"));
    await expect(first).rejects.toThrow("denied");
    env.writeText.mockImplementation(async () => {});
    await copyOneTimeSecret("B");
    await flush();
    expect(holdsCopiedSecret(), "the second copy was not asked to be wiped").toBe(true);
    expect(env.writeText).toHaveBeenLastCalledWith("B");
  });

  it("writes nothing when nothing was copied, so it never clears what the person copied themselves", async () => {
    const env = setupEnv();
    const {wipeCopiedSecret} = await load();
    await wipeCopiedSecret();
    expect(env.writeText).not.toHaveBeenCalled();
  });

  it("does not remember a copy that failed, and passes the failure on to the caller", async () => {
    const env = setupEnv({
      write: async () => {
        throw new DOMException("denied", "NotAllowedError");
      },
    });
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await expect(copyOneTimeSecret("x")).rejects.toThrow("denied");
    expect(holdsCopiedSecret()).toBe(false);
    expect(pending(env)).toBeUndefined();
    await wipeCopiedSecret();
    expect(env.writeText).toHaveBeenCalledTimes(1);
  });

  it("never rejects from a wipe: a refused write, a throwing one and no clipboard at all", async () => {
    const env = setupEnv();
    const {copyOneTimeSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("x");
    env.writeText.mockImplementation(() => Promise.reject(new Error("no gesture")));
    await expect(wipeCopiedSecret()).resolves.toBeUndefined();
    env.writeText.mockImplementation(() => {
      throw new Error("sync");
    });
    await expect(wipeCopiedSecret()).resolves.toBeUndefined();
    vi.stubGlobal("navigator", {});
    await expect(wipeCopiedSecret()).resolves.toBeUndefined();
  });

  // gate-r6-6
  it("keeps the copy remembered when the browser refuses the wipe, and writes again at the next focus", async () => {
    const env = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("SECRET");
    env.writeText.mockImplementation(() => Promise.reject(new DOMException("Document is not focused", "NotAllowedError")));
    await wipeCopiedSecret();
    expect(holdsCopiedSecret()).toBe(true);
    expect(pending(env)).toBe("1");
    expect(env.win.count()).toBeGreaterThan(0);

    env.writeText.mockImplementation(async () => {});
    env.win.dispatch("focus");
    await flush();
    expect(env.writeText).toHaveBeenLastCalledWith("");
    expect(holdsCopiedSecret()).toBe(false);
    expect(pending(env)).toBeUndefined();
    // The retry listeners are gone once a write was accepted: only the pagehide one stays.
    expect(env.win.listeners.get("focus")?.size ?? 0).toBe(0);
    expect(env.win.listeners.get("pointerdown")?.size ?? 0).toBe(0);
    expect(env.doc.listeners.get("visibilitychange")?.size ?? 0).toBe(0);
  });

  it.each([
    ["pointerdown", "win"],
    ["keydown", "win"],
    ["visibilitychange", "doc"],
  ] as const)("retries on %s, and not while the document is hidden", async (name, where) => {
    const env = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("SECRET");
    env.writeText.mockImplementation(() => Promise.reject(new Error("refused")));
    await wipeCopiedSecret();
    env.writeText.mockImplementation(async () => {});
    env.writeText.mockClear();
    env.doc.visibilityState = "hidden";
    env[where].dispatch(name);
    await flush();
    expect(env.writeText).not.toHaveBeenCalled();
    env.doc.visibilityState = "visible";
    env[where].dispatch(name);
    await flush();
    expect(env.writeText).toHaveBeenCalledWith("");
    expect(holdsCopiedSecret()).toBe(false);
  });

  it("keeps retrying while every attempt is refused, one write at a time", async () => {
    const env = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("SECRET");
    env.writeText.mockImplementation(() => Promise.reject(new Error("refused")));
    await wipeCopiedSecret();
    env.win.dispatch("focus");
    await flush();
    env.win.dispatch("pointerdown");
    await flush();
    expect(holdsCopiedSecret()).toBe(true);
    expect(env.writeText).toHaveBeenCalledTimes(4);
  });

  it("tries once more when the page is hidden for good", async () => {
    const env = setupEnv();
    const {copyOneTimeSecret} = await load();
    await copyOneTimeSecret("SECRET");
    env.win.dispatch("pagehide");
    await flush();
    expect(env.writeText).toHaveBeenLastCalledWith("");
  });

  it("does not wipe on pagehide when nothing is held", async () => {
    const env = setupEnv();
    const {copyOneTimeSecret} = await load();
    await copyOneTimeSecret("x");
    env.writeText.mockClear();
    env.selection.text = "something else";
    env.doc.dispatch("copy");
    env.win.dispatch("pagehide");
    await flush();
    expect(env.writeText).not.toHaveBeenCalled();
  });

  // gate-r6-8, the page that a full load opens
  it("picks a refused wipe up on the next page of the tab, and wipes there at once", async () => {
    const env = setupEnv({flag: true});
    const {holdsCopiedSecret} = await load();
    await flush();
    expect(env.writeText).toHaveBeenCalledWith("");
    expect(holdsCopiedSecret()).toBe(false);
    expect(pending(env)).toBeUndefined();
  });

  it("keeps the flag on that page when the tab is in the background, and wipes when it is looked at", async () => {
    const env = setupEnv({flag: true, write: () => Promise.reject(new Error("Document is not focused"))});
    const {holdsCopiedSecret} = await load();
    await flush();
    expect(holdsCopiedSecret()).toBe(true);
    expect(pending(env)).toBe("1");
    env.writeText.mockImplementation(async () => {});
    env.win.dispatch("focus");
    await flush();
    expect(holdsCopiedSecret()).toBe(false);
    expect(pending(env)).toBeUndefined();
  });

  it("does nothing on load without the flag, and without a window", async () => {
    const env = setupEnv();
    await load();
    await flush();
    expect(env.writeText).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
    vi.stubGlobal("navigator", {clipboard: {writeText: vi.fn()}});
    await expect(load()).resolves.toBeDefined();
  });

  it("still works when sessionStorage is blocked", async () => {
    const env = setupEnv();
    vi.stubGlobal("sessionStorage", {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
      removeItem: () => {
        throw new Error("blocked");
      },
    });
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("x");
    await wipeCopiedSecret();
    expect(env.writeText).toHaveBeenLastCalledWith("");
    expect(holdsCopiedSecret()).toBe(false);
  });

  // gate-r6-8, a copy made by hand
  it("remembers a copy of the secret that the person made by hand, so closing wipes it", async () => {
    const env = setupEnv();
    const {holdsCopiedSecret, wipeCopiedSecret, copyOneTimeSecret} = await load();
    await copyOneTimeSecret("x"); // installs the listeners; then the person copies by hand from a fresh state
    await wipeCopiedSecret();
    env.writeText.mockClear();
    expect(holdsCopiedSecret()).toBe(false);

    env.selection.touches = true;
    env.doc.dispatch("copy");
    expect(holdsCopiedSecret()).toBe(true);
    expect(pending(env)).toBe("1");
    await wipeCopiedSecret();
    expect(env.writeText).toHaveBeenCalledWith("");
  });

  it("listens for a hand copy from the moment the module is loaded, with no button pressed before", async () => {
    const env = setupEnv();
    const {holdsCopiedSecret, wipeCopiedSecret} = await load();
    env.selection.touches = true;
    env.doc.dispatch("copy");
    expect(holdsCopiedSecret()).toBe(true);
    await wipeCopiedSecret();
    expect(env.writeText).toHaveBeenCalledWith("");
  });

  // gate-r28-7: "Copy link to highlight" writes the secret into a URL from the browser process and fires no copy event in the page.
  it("holds a secret whose selection a context menu was opened on, with no copy event, and the close wipes it (gate-r28-7)", async () => {
    const env = setupEnv();
    const {holdsCopiedSecret, wipeCopiedSecret} = await load();
    env.selection.touches = true;
    env.doc.dispatch("contextmenu");
    expect(holdsCopiedSecret()).toBe(true);
    expect(pending(env)).toBe("1");
    await wipeCopiedSecret();
    expect(env.writeText).toHaveBeenCalledWith("");
  });

  it("ignores a context menu that opens on a selection touching no secret, and on no selection (gate-r28-7)", async () => {
    const env = setupEnv();
    const {holdsCopiedSecret} = await load();
    env.selection.touches = false;
    env.selection.text = "ordinary text";
    env.doc.dispatch("contextmenu");
    expect(holdsCopiedSecret()).toBe(false);
    env.selection.touches = true;
    env.selection.isCollapsed = true;
    env.doc.dispatch("contextmenu");
    expect(holdsCopiedSecret()).toBe(false);
    env.selection.isCollapsed = false;
    env.selection.rangeCount = 0;
    env.doc.dispatch("contextmenu");
    expect(holdsCopiedSecret()).toBe(false);
  });

  // gate-r6-7
  it("lets go of the memory when the person copies something else from the page, so that is not wiped", async () => {
    const env = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("SECRET");
    env.writeText.mockClear();
    env.selection.touches = false;
    env.selection.text = "something else";
    env.doc.dispatch("copy");
    expect(holdsCopiedSecret()).toBe(false);
    expect(pending(env)).toBeUndefined();
    await wipeCopiedSecret();
    expect(env.writeText).not.toHaveBeenCalled();
  });

  // gate-r7-9. Chrome fires `copy` for Ctrl+C with nothing selected and writes nothing, so the secret is still in the clipboard.
  it("keeps the memory when a copy takes nothing: no selection, a collapsed caret, a button with the focus, an input with no selection", async () => {
    const e = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("SECRET");
    e.writeText.mockClear();
    e.selection.rangeCount = 0;
    e.doc.dispatch("copy");
    expect(holdsCopiedSecret(), "no range").toBe(true);
    e.selection.rangeCount = 1;
    e.selection.isCollapsed = true;
    e.doc.dispatch("copy");
    expect(holdsCopiedSecret(), "collapsed caret").toBe(true);
    e.doc.activeElement = {selectionStart: 3, selectionEnd: 3};
    e.doc.dispatch("copy");
    expect(holdsCopiedSecret(), "input caret with no selection").toBe(true);
    e.doc.dispatch("copy", {clipboardData: {types: []}});
    expect(holdsCopiedSecret(), "a handler that set no data").toBe(true);
    expect(pending(e)).toBe("1");
    await wipeCopiedSecret();
    expect(e.writeText).toHaveBeenCalledWith("");
    expect(holdsCopiedSecret()).toBe(false);
  });

  it("lets go when the copy takes text: a selection, a selection inside an input (reported as collapsed), or data that a handler set", async () => {
    const makers: Array<(x: Env) => void> = [
      (x) => {
        x.selection.text = "other";
      },
      (x) => {
        x.selection.isCollapsed = true;
        x.doc.activeElement = {selectionStart: 0, selectionEnd: 4};
      },
    ];
    for (const make of makers) {
      const e = setupEnv();
      const {copyOneTimeSecret, holdsCopiedSecret} = await load();
      await copyOneTimeSecret("SECRET");
      make(e);
      e.doc.dispatch("copy");
      expect(holdsCopiedSecret()).toBe(false);
    }
    const e = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret} = await load();
    await copyOneTimeSecret("SECRET");
    e.doc.dispatch("copy", {clipboardData: {types: ["text/plain"]}});
    expect(holdsCopiedSecret()).toBe(false);
  });

  // gate-r25-7: Ctrl+X in a field fires `cut`, not `copy`, and puts the person's text in the clipboard.
  it("lets go when the person cuts text from a field, and keeps the memory when a cut takes nothing", async () => {
    const e = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret} = await load();
    await copyOneTimeSecret("SECRET");
    e.doc.dispatch("cut");
    expect(holdsCopiedSecret(), "a cut with nothing selected writes nothing").toBe(true);
    e.selection.isCollapsed = true;
    e.doc.activeElement = {selectionStart: 0, selectionEnd: 4};
    e.doc.dispatch("cut");
    expect(holdsCopiedSecret()).toBe(false);
  });

  it("lets go of a sibling's copy when the person cuts text in this tab", async () => {
    const e = setupEnv();
    const {wipeCopiedSecret} = await load();
    await wipeCopiedSecret();
    e.sibling("held");
    e.posted.length = 0;
    e.selection.text = "typed";
    e.doc.dispatch("cut");
    expect(e.posted).toContain("clear");
    await wipeCopiedSecret();
    expect(e.writeText, "what the person cut here is theirs").not.toHaveBeenCalled();
  });

  // gate-r7-10. The memory is per tab and the clipboard is not: tab 1 copies, tab 2 (the one with the focus) logs out or signs in as someone else.
  describe("a copy made in another tab", () => {
    it("tells the others that a copy exists, never what it is, and that the clipboard was cleared", async () => {
      const e = setupEnv();
      const {copyOneTimeSecret, wipeCopiedSecret} = await load();
      await copyOneTimeSecret("THE-SECRET");
      expect(e.posted).toContain("held");
      await wipeCopiedSecret();
      expect(e.posted).toContain("clear");
      expect(JSON.stringify(e.posted)).not.toContain("THE-SECRET");
    });

    it("answers a page that has just loaded when it holds a copy, and stays quiet when it does not", async () => {
      const e = setupEnv();
      const {copyOneTimeSecret, wipeCopiedSecret} = await load();
      await wipeCopiedSecret();
      e.posted.length = 0;
      e.sibling("query");
      expect(e.posted).toEqual([]);
      await copyOneTimeSecret("x");
      e.posted.length = 0;
      e.sibling("query");
      expect(e.posted).toEqual(["held"]);
    });

    it("is wiped by a tab that copied nothing itself, so a logout or a sign-in there empties the clipboard, and the copying tab forgets", async () => {
      const e = setupEnv();
      const {holdsCopiedSecret, wipeCopiedSecret} = await load();
      await wipeCopiedSecret();
      expect(e.writeText, "nothing is known yet").not.toHaveBeenCalled();
      e.sibling("held");
      expect(holdsCopiedSecret(), "the copy is the sibling's, not this tab's").toBe(false);
      await wipeCopiedSecret();
      expect(e.writeText).toHaveBeenCalledTimes(1);
      expect(e.writeText).toHaveBeenLastCalledWith("");
      expect(e.posted).toContain("clear");
      await wipeCopiedSecret();
      expect(e.writeText, "once it is cleared there is nothing to write").toHaveBeenCalledTimes(1);
    });

    // gate-r13-9. Tab B knows only of A's copy; the person copies a phone number in B. A must hear it, or A's close empties that number.
    it("releases a sibling's copy when the person copies something else in this tab, and tells the sibling (gate-r13-9)", async () => {
      const e = setupEnv();
      const {wipeCopiedSecret} = await load();
      await wipeCopiedSecret();
      e.sibling("held");
      e.posted.length = 0;
      e.selection.touches = false;
      e.selection.text = "0912 000 0000";
      e.doc.dispatch("copy");
      expect(e.posted).toContain("clear");
      await wipeCopiedSecret();
      expect(e.writeText, "what the person copied here is theirs").not.toHaveBeenCalled();
    });

    it("keeps a sibling's copy when a copy in this tab takes nothing", async () => {
      const e = setupEnv();
      const {wipeCopiedSecret} = await load();
      await wipeCopiedSecret();
      e.sibling("held");
      e.posted.length = 0;
      e.selection.touches = false;
      e.selection.text = "";
      e.doc.dispatch("copy");
      expect(e.posted).not.toContain("clear");
      await wipeCopiedSecret();
      expect(e.writeText).toHaveBeenLastCalledWith("");
    });

    it("forgets its own copy when a sibling says the clipboard is clear", async () => {
      const e = setupEnv();
      const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
      await copyOneTimeSecret("x");
      e.writeText.mockClear();
      e.sibling("clear");
      expect(holdsCopiedSecret()).toBe(false);
      expect(pending(e)).toBeUndefined();
      await wipeCopiedSecret();
      expect(e.writeText, "a wipe now would erase what the person copied after").not.toHaveBeenCalled();
    });

    it("keeps trying when the write of the focused tab is refused, and the sibling is not told it is clear", async () => {
      const e = setupEnv({
        write: async () => {
          throw new DOMException("no focus", "NotAllowedError");
        },
      });
      const {wipeCopiedSecret} = await load();
      e.sibling("held");
      await wipeCopiedSecret();
      expect(e.posted).not.toContain("clear");
      e.writeText.mockImplementation(async () => {});
      e.win.dispatch("pointerdown");
      await flush();
      expect(e.writeText).toHaveBeenLastCalledWith("");
      expect(e.posted).toContain("clear");
    });

    // gate-r9-7: logoutLocal starts a full load right after the wipe, which ends the listeners of this document. The refused wipe of a sibling's copy
    // has to be remembered across that load, or the tab the person is looking at never retries it.
    it("remembers a refused wipe of a sibling's copy across a full load, and the next page retries it on focus (gate-r9-7)", async () => {
      const refuse = async () => {
        throw new DOMException("no gesture", "NotAllowedError");
      };
      const before = setupEnv({write: refuse});
      const first = await load();
      before.sibling("held");
      await first.wipeCopiedSecret();
      expect(pending(before), "the flag, which only hold() used to set").toBe("1");
      expect(before.posted).not.toContain("clear");

      // The next page of the same tab: a new window and module, the same sessionStorage.
      const after = setupEnv({write: refuse, flag: pending(before) === "1"});
      await load();
      await flush();
      expect(after.writeText, "the page tries at once").toHaveBeenLastCalledWith("");
      after.writeText.mockImplementation(async () => {});
      after.win.dispatch("focus");
      await flush();
      expect(after.writeText).toHaveBeenCalledTimes(2);
      expect(pending(after), "once the write is accepted nothing is left to resume").toBeUndefined();
      expect(after.posted).toContain("clear");
    });

    it("leaves no flag behind when the sibling reported clear while the refused write was on its way (gate-r9-7)", async () => {
      let fail: (reason: unknown) => void = () => {};
      const e = setupEnv();
      const {wipeCopiedSecret} = await load();
      e.sibling("held");
      e.writeText.mockImplementationOnce(() => new Promise<void>((_resolve, reject) => (fail = reject)));
      const wiping = wipeCopiedSecret();
      e.sibling("clear");
      fail(new DOMException("no gesture", "NotAllowedError"));
      await wiping;
      expect(pending(e)).toBeUndefined();
    });

    it("keeps a newer sibling copy that was announced while the write was on its way", async () => {
      let done: () => void = () => {};
      const e = setupEnv();
      const {wipeCopiedSecret} = await load();
      e.sibling("held");
      e.writeText.mockImplementationOnce(() => new Promise<void>((resolve) => (done = resolve)));
      const wiping = wipeCopiedSecret();
      e.sibling("held");
      done();
      await wiping;
      expect(e.posted, "the write may have come before the newer copy").not.toContain("clear");
      await wipeCopiedSecret();
      expect(e.posted).toContain("clear");
    });
  });

  it("keeps a newer secret that was copied while the wipe of the older one was on its way", async () => {
    let release: () => void = () => {};
    const env = setupEnv();
    const {copyOneTimeSecret, holdsCopiedSecret, wipeCopiedSecret} = await load();
    await copyOneTimeSecret("OLD");
    env.writeText.mockImplementationOnce(() => new Promise<void>((resolve) => (release = resolve)));
    const wiping = wipeCopiedSecret();
    env.selection.touches = true;
    env.doc.dispatch("copy");
    release();
    await wiping;
    expect(holdsCopiedSecret()).toBe(true);
  });
});
