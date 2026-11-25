import {afterEach, describe, expect, it, vi} from "vitest";

import {replaceUrlAfterRouterMount} from "./routerHistory.ts";

// gate-r21-9: a write from a mount effect reaches the browser's own replaceState, because the router patches it in an effect of its own
// that runs after the page's, in the same flush. The write is one task later, through whatever replaceState is on window.history then.

function fakeHistory() {
  const calls: unknown[][] = [];
  const history = {replaceState: (...args: unknown[]) => void calls.push(["native", ...args])};
  // What Next's effect does after the page's effect ran.
  const routerPatches = () => {
    history.replaceState = (...args: unknown[]) => void calls.push(["router", ...args]);
  };
  return {history, calls, routerPatches};
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("replaceUrlAfterRouterMount", () => {
  it("writes nothing in the effect itself, and writes through the router's replaceState once that is installed", () => {
    vi.useFakeTimers();
    const {history, calls, routerPatches} = fakeHistory();
    vi.stubGlobal("window", {history});
    replaceUrlAfterRouterMount(() => "/fa/invite");
    expect(calls).toEqual([]);
    routerPatches();
    vi.advanceTimersByTime(0);
    expect(calls).toEqual([["router", null, "", "/fa/invite"]]);
  });

  it("asks for the address when it writes, and writes nothing for null", () => {
    vi.useFakeTimers();
    const {history, calls} = fakeHistory();
    vi.stubGlobal("window", {history});
    let address: string | null = "/early";
    replaceUrlAfterRouterMount(() => address);
    address = null;
    vi.advanceTimersByTime(10);
    expect(calls).toEqual([]);
  });

  it("can be cancelled before it writes, as an effect cleanup does", () => {
    vi.useFakeTimers();
    const {history, calls} = fakeHistory();
    vi.stubGlobal("window", {history});
    const cancel = replaceUrlAfterRouterMount(() => "/x");
    cancel();
    vi.advanceTimersByTime(1000);
    expect(calls).toEqual([]);
  });

  it("cancelling after the write is harmless", () => {
    vi.useFakeTimers();
    const {history, calls} = fakeHistory();
    vi.stubGlobal("window", {history});
    const cancel = replaceUrlAfterRouterMount(() => "/x");
    vi.advanceTimersByTime(1);
    cancel();
    expect(calls).toEqual([["native", null, "", "/x"]]);
  });
});
