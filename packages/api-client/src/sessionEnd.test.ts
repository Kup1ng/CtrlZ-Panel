import {describe, expect, it, vi} from "vitest";

import {onSessionEnd, runSessionEnd, sessionGuard} from "./sessionEnd.ts";

describe("session end handlers (S1-r2-4)", () => {
  it("runs every registered handler once, and not an unregistered one", () => {
    const a = vi.fn();
    const b = vi.fn();
    const offA = onSessionEnd(a);
    const offB = onSessionEnd(b);
    runSessionEnd();
    expect([a.mock.calls.length, b.mock.calls.length]).toEqual([1, 1]);
    offA();
    runSessionEnd();
    expect([a.mock.calls.length, b.mock.calls.length]).toEqual([1, 2]);
    offB();
  });

  it("a handler that throws does not stop the others", () => {
    const after = vi.fn();
    const off = [
      onSessionEnd(() => {
        throw new Error("boom");
      }),
      onSessionEnd(after),
    ];
    expect(() => runSessionEnd()).not.toThrow();
    expect(after).toHaveBeenCalledTimes(1);
    for (const o of off) o();
  });
});

describe("the session guard (S1-r3-5)", () => {
  it("is alive until a session ends, and a guard taken later is alive again", () => {
    const first = sessionGuard();
    expect(first()).toBe(true);
    runSessionEnd();
    expect(first()).toBe(false);
    const second = sessionGuard();
    expect(second()).toBe(true);
    expect(first()).toBe(false);
  });

  it("counts a session that ends while a handler throws", () => {
    const guard = sessionGuard();
    const off = onSessionEnd(() => {
      throw new Error("boom");
    });
    runSessionEnd();
    expect(guard()).toBe(false);
    off();
  });
});
