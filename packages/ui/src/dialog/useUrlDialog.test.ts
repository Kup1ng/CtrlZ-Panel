import {afterEach, describe, expect, it, vi} from "vitest";

import {DIALOG_PARAMS, pushedKey, urlWith} from "./useUrlDialog.ts";

describe("urlWith", () => {
  it("sets the parameter and keeps the others, the path and the fragment", () => {
    expect(urlWith("https://x.test/fa/profiles?a=1#top", "ruleDialog", "42")).toBe("/fa/profiles?a=1&ruleDialog=42#top");
  });

  it("replaces an existing value and removes on null", () => {
    expect(urlWith("https://x.test/fa/p?helpPane=a&b=2", "helpPane", "c")).toBe("/fa/p?helpPane=c&b=2");
    expect(urlWith("https://x.test/fa/p?helpPane=a&b=2", "helpPane", null)).toBe("/fa/p?b=2");
    expect(urlWith("https://x.test/fa/p?helpPane=a", "helpPane", null)).toBe("/fa/p");
  });

  it("escapes a value instead of letting it add a parameter", () => {
    expect(urlWith("https://x.test/p", "step", "1&evil=1")).toBe("/p?step=1%26evil%3D1");
  });
});

describe("DIALOG_PARAMS", () => {
  it("holds the ten parameters of the wireframe notes (T-117), then the shell and the admin ones", () => {
    expect([...DIALOG_PARAMS]).toEqual([
      "profileDialog",
      "serviceDialog",
      "ruleDialog",
      "deviceDialog",
      "endpointGroupDialog",
      "ipDialog",
      "deviceId",
      "helpPane",
      "setupOs",
      "step",
      "notificationsDialog",
      "dialog",
    ]);
  });

  it("has no parameter that could carry a secret (R21)", () => {
    for (const p of DIALOG_PARAMS) expect(p).not.toMatch(/ticket|secret|code|password|token|otp|recovery/i);
  });

  it("keeps one storage key per parameter", () => {
    expect(new Set(DIALOG_PARAMS.map(pushedKey)).size).toBe(DIALOG_PARAMS.length);
  });
});

// The hook's own logic (wp7-r1-5): it was covered only through the browser. A small stand-in for the
// browser's history, storage and the page's search parameters is enough, because the hook reads nothing else.
describe("useUrlDialog", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
    vi.doUnmock("next/navigation");
  });

  async function setup(startUrl: string) {
    vi.resetModules();
    const store = new Map<string, string>();
    const listeners = new Map<string, () => void>();
    const win = {
      location: {href: startUrl},
      history: {
        pushState: vi.fn((_s: unknown, _t: string, url: string) => void (win.location.href = new URL(url, win.location.href).href)),
        replaceState: vi.fn((_s: unknown, _t: string, url: string) => void (win.location.href = new URL(url, win.location.href).href)),
        back: vi.fn(),
      },
      addEventListener: (name: string, fn: () => void) => void listeners.set(name, fn),
    };
    vi.stubGlobal("window", win);
    vi.stubGlobal("sessionStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });
    vi.doMock("next/navigation", () => ({useSearchParams: () => new URL(win.location.href).searchParams}));
    const {renderToString} = await import("react-dom/server");
    const {createElement} = await import("react");
    const mod = await import("./useUrlDialog.ts");
    let dialog!: ReturnType<typeof mod.useUrlDialog>;
    const read = () => {
      renderToString(
        createElement(() => {
          dialog = mod.useUrlDialog("ruleDialog");
          return null;
        }),
      );
      return dialog;
    };
    return {win, store, listeners, read, mod};
  }

  it("pushes one entry to open, and Back is what closes a dialog this tab opened", async () => {
    const {win, store, read, mod} = await setup("https://x.test/fa/p?a=1");
    read().open("tall");
    expect(win.history.pushState).toHaveBeenCalledOnce();
    expect(win.location.href).toBe("https://x.test/fa/p?a=1&ruleDialog=tall");
    expect(store.get(mod.pushedKey("ruleDialog"))).toBe("1");
    expect(read().isOpen).toBe(true);
    read().close();
    expect(win.history.back).toHaveBeenCalledOnce();
    expect(win.history.replaceState).not.toHaveBeenCalled();
    expect(store.has(mod.pushedKey("ruleDialog"))).toBe(false);
  });

  it("changes the value of an open dialog in place, with no new entry", async () => {
    const {win, read} = await setup("https://x.test/fa/p?ruleDialog=first");
    read().open("second");
    expect(win.history.pushState).not.toHaveBeenCalled();
    expect(win.history.replaceState).toHaveBeenCalledOnce();
    expect(win.location.href).toBe("https://x.test/fa/p?ruleDialog=second");
  });

  it("strips the parameter instead of calling back() when the visitor arrived on the link", async () => {
    const {win, read} = await setup("https://x.test/fa/p?ruleDialog=tall&a=1#x");
    expect(read().value).toBe("tall");
    read().close();
    expect(win.history.back).not.toHaveBeenCalled();
    expect(win.location.href).toBe("https://x.test/fa/p?a=1#x");
  });

  it("treats an empty value as closed", async () => {
    const {read} = await setup("https://x.test/fa/p?ruleDialog=");
    expect(read().isOpen).toBe(false);
    expect(read().value).toBeNull();
  });

  it("forgets the pushed flag when the history moved past the entry, so a later close cannot leave the app", async () => {
    const {win, store, listeners, read, mod} = await setup("https://x.test/fa/p");
    read().open("tall");
    expect(store.get(mod.pushedKey("ruleDialog"))).toBe("1");
    win.location.href = "https://x.test/fa/p"; // Back: the parameter is gone
    listeners.get("popstate")!();
    expect(store.has(mod.pushedKey("ruleDialog"))).toBe(false);
  });

  it("keeps the flag of a dialog that is still in the URL on popstate", async () => {
    const {win, store, listeners, read, mod} = await setup("https://x.test/fa/p");
    read().open("tall");
    listeners.get("popstate")!();
    expect(win.location.href).toContain("ruleDialog=tall");
    expect(store.get(mod.pushedKey("ruleDialog"))).toBe("1");
  });
});
