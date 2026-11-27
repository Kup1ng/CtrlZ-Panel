import {afterEach, beforeEach, describe, expect, it, vi} from "vitest";

import {createLeaveClear} from "./newProfile.ts";

// S1-r3-2: React StrictMode mounts, cleans up and mounts again at once; only a leave with no entering after it clears the New mark.

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("the leave that clears the New mark (S1-r3-2)", () => {
  it("does not clear on StrictMode's simulated unmount, which is followed by the effect again", () => {
    const clear = vi.fn();
    const guard = createLeaveClear(clear);
    guard.enter();
    guard.leave();
    guard.enter();
    vi.runAllTimers();
    expect(clear).not.toHaveBeenCalled();
  });

  it("clears once the screen is really left", () => {
    const clear = vi.fn();
    const guard = createLeaveClear(clear);
    guard.enter();
    guard.leave();
    vi.runAllTimers();
    expect(clear).toHaveBeenCalledTimes(1);
  });
});
