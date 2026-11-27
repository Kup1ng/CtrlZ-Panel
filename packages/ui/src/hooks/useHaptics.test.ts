import {afterEach, describe, expect, it, vi} from "vitest";

import {buzz, setHapticsEnabled} from "./useHaptics.ts";

// T-310. `buzz` has three guards, and a touch screen with the preference on is the only place that pulses. No DOM here: the three
// globals it reads are stubbed one by one, so each test breaks exactly one guard.

function stage({enabled = true, coarse = true, vibrate = true, storage = true} = {}) {
  const vibrateFn = vi.fn(() => true);
  const store = new Map<string, string>(enabled ? [["ctrlz.haptics", "1"]] : []);
  vi.stubGlobal("navigator", vibrate ? {vibrate: vibrateFn} : {});
  vi.stubGlobal("matchMedia", (query: string) => ({matches: coarse && query === "(pointer: coarse)"}));
  vi.stubGlobal(
    "localStorage",
    storage
      ? {getItem: (key: string) => store.get(key) ?? null, setItem: (key: string, value: string) => void store.set(key, value)}
      : {
          getItem: () => {
            throw new Error("blocked");
          },
          setItem: () => {
            throw new Error("blocked");
          },
        },
  );
  return vibrateFn;
}

afterEach(() => vi.unstubAllGlobals());

describe("buzz (T-310)", () => {
  it("pulses once for 10 ms when the preference is on, the pointer is coarse and the browser can vibrate", () => {
    const vibrate = stage();
    expect(buzz()).toBe(true);
    expect(vibrate).toHaveBeenCalledTimes(1);
    expect(vibrate).toHaveBeenCalledWith(10);
  });

  it("does nothing when the preference is off, which is the default", () => {
    const vibrate = stage({enabled: false});
    expect(buzz()).toBe(false);
    expect(vibrate).not.toHaveBeenCalled();
  });

  it("does nothing with a mouse or a trackpad (the pointer is not coarse)", () => {
    const vibrate = stage({coarse: false});
    expect(buzz()).toBe(false);
    expect(vibrate).not.toHaveBeenCalled();
  });

  it("does nothing where the browser has no navigator.vibrate (iOS Safari)", () => {
    stage({vibrate: false});
    expect(buzz()).toBe(false);
  });

  it("does nothing, and does not throw, when storage is blocked", () => {
    const vibrate = stage({storage: false});
    expect(buzz()).toBe(false);
    expect(vibrate).not.toHaveBeenCalled();
  });

  it("does nothing outside a browser", () => {
    vi.stubGlobal("navigator", undefined);
    expect(buzz()).toBe(false);
  });

  it("follows the switch of Account, which writes the same key", () => {
    const vibrate = stage({enabled: false});
    setHapticsEnabled(true);
    expect(buzz()).toBe(true);
    setHapticsEnabled(false);
    expect(buzz()).toBe(false);
    expect(vibrate).toHaveBeenCalledTimes(1);
  });
});
