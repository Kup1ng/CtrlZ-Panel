import {afterEach, describe, expect, it, vi} from "vitest";

// There is no DOM in the unit tests, and renderToString runs no effect and no state update. A tiny
// renderer stands in for React's useState and useEffect so the hook runs its real lifecycle: render,
// effects after it, a state change that renders again, cleanup when the deps change. The browser
// proof is the e2e case in apps/panel/e2e/session.spec.ts.
const host = vi.hoisted(() => {
  type Effect = {deps: unknown[] | undefined; cleanup: (() => void) | void};
  return {
    state: [] as unknown[],
    effects: [] as Effect[],
    cursor: {state: 0, effect: 0},
    rerender: () => undefined as void,
  };
});

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useState: <T,>(init: T | (() => T)) => {
    const i = host.cursor.state++;
    if (!(i in host.state)) host.state[i] = typeof init === "function" ? (init as () => T)() : init;
    const set = (next: T | ((p: T) => T)) => {
      host.state[i] = typeof next === "function" ? (next as (p: T) => T)(host.state[i] as T) : next;
      host.rerender();
    };
    return [host.state[i], set];
  },
  useEffect: (effect: () => (() => void) | void, deps?: unknown[]) => {
    const i = host.cursor.effect++;
    const before = host.effects[i];
    if (before && deps && before.deps && deps.every((d, k) => Object.is(d, before.deps![k]))) return;
    if (before && typeof before.cleanup === "function") before.cleanup();
    host.effects[i] = {deps, cleanup: effect()};
  },
}));

import type {Announcement} from "./announcements.ts";
import {armAnnouncementChange, isAnnouncementLive, nextAnnouncementChangeAt, useAnnouncementNow} from "./announcements.ts";

type Row = Pick<Announcement, "starts_at" | "ends_at">;
const START = new Date("2026-11-10T12:00:00Z");
const MIN = 60_000;

afterEach(() => {
  for (const e of host.effects) if (typeof e?.cleanup === "function") e.cleanup();
  host.state.length = 0;
  host.effects.length = 0;
  vi.useRealTimers();
});

/** Mounts the hook for `rows` and returns what a banner list would show now, the way BannerStack filters. */
function mount(rows: Row[]) {
  const shown = {live: 0, renders: 0};
  const Probe = () => {
    host.cursor.state = 0;
    host.cursor.effect = 0;
    const now = useAnnouncementNow(rows);
    shown.live = rows.filter((a) => isAnnouncementLive(a, now)).length;
    shown.renders += 1;
  };
  host.rerender = Probe;
  Probe();
  return shown;
}

describe("nextAnnouncementChangeAt", () => {
  it("is the nearest start still ahead, or one millisecond after the nearest end", () => {
    const rows: Row[] = [
      {starts_at: "2026-11-01T00:00:00Z", ends_at: "2026-11-10T12:30:00Z"},
      {starts_at: "2026-11-10T12:10:00Z"},
      {starts_at: "2026-11-01T00:00:00Z", ends_at: "2026-11-10T11:00:00Z"},
    ];
    expect(nextAnnouncementChangeAt(rows, START)).toBe(Date.parse("2026-11-10T12:10:00Z"));
    expect(nextAnnouncementChangeAt([rows[0]!], START)).toBe(Date.parse("2026-11-10T12:30:00Z") + 1);
  });

  it("is undefined when nothing will change", () => {
    expect(nextAnnouncementChangeAt([], START)).toBeUndefined();
    expect(nextAnnouncementChangeAt([{starts_at: "2026-11-01T00:00:00Z"}, {starts_at: "2026-11-01T00:00:00Z", ends_at: "2026-11-02T00:00:00Z"}], START)).toBeUndefined();
  });

  it("agrees with isAnnouncementLive: the answer is different on either side of the moment", () => {
    const rows: Row[] = [{starts_at: "2026-11-10T12:10:00Z", ends_at: "2026-11-10T12:30:00Z"}];
    for (const row of rows) {
      const first = nextAnnouncementChangeAt([row], START)!;
      expect(isAnnouncementLive(row, new Date(first - 1))).toBe(false);
      expect(isAnnouncementLive(row, new Date(first))).toBe(true);
      const last = nextAnnouncementChangeAt([row], new Date(first))!;
      expect(isAnnouncementLive(row, new Date(last - 1))).toBe(true);
      expect(isAnnouncementLive(row, new Date(last))).toBe(false);
    }
  });
});

describe("armAnnouncementChange", () => {
  it("fires once when the moment comes, and not before", () => {
    vi.useFakeTimers({now: START});
    const due = vi.fn();
    armAnnouncementChange(START.getTime() + 5 * MIN, due);
    vi.advanceTimersByTime(5 * MIN - 1);
    expect(due).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(due).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(60 * MIN);
    expect(due).toHaveBeenCalledTimes(1);
  });

  it("waits out a distance longer than setTimeout can hold, which would fire at once", () => {
    vi.useFakeTimers({now: START});
    const due = vi.fn();
    const days = 40 * 24 * 60 * MIN;
    armAnnouncementChange(START.getTime() + days, due);
    vi.advanceTimersByTime(days - 1);
    expect(due).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(due).toHaveBeenCalledTimes(1);
  });

  it("can be cancelled", () => {
    vi.useFakeTimers({now: START});
    const due = vi.fn();
    const cancel = armAnnouncementChange(START.getTime() + MIN, due);
    cancel();
    vi.advanceTimersByTime(10 * MIN);
    expect(due).not.toHaveBeenCalled();
  });
});

// wp4-r12-1: the banner list judged the window once per render, and nothing rendered when time passed.
describe("useAnnouncementNow moves the window with no render from anywhere else", () => {
  it("takes a banner away after its ends_at, with the data unchanged", () => {
    vi.useFakeTimers({now: START});
    const shown = mount([{starts_at: "2026-11-01T00:00:00Z", ends_at: "2026-11-10T12:30:00Z"}]);
    expect(shown.live).toBe(1);
    vi.advanceTimersByTime(30 * MIN);
    expect(shown.live).toBe(1); // the end is inclusive
    vi.advanceTimersByTime(1);
    expect(shown.live).toBe(0);
  });

  it("brings a banner in when its starts_at comes", () => {
    vi.useFakeTimers({now: START});
    const shown = mount([{starts_at: "2026-11-10T12:05:00Z"}]);
    expect(shown.live).toBe(0);
    vi.advanceTimersByTime(5 * MIN - 1);
    expect(shown.live).toBe(0);
    vi.advanceTimersByTime(1);
    expect(shown.live).toBe(1);
  });

  it("goes on to the next change after the first one, and then stops asking", () => {
    vi.useFakeTimers({now: START});
    const shown = mount([{starts_at: "2026-11-10T12:05:00Z", ends_at: "2026-11-10T12:20:00Z"}]);
    expect(shown.live).toBe(0);
    vi.advanceTimersByTime(5 * MIN);
    expect(shown.live).toBe(1);
    vi.advanceTimersByTime(15 * MIN + 1);
    expect(shown.live).toBe(0);
    const renders = shown.renders;
    vi.advanceTimersByTime(24 * 60 * MIN);
    expect(shown.renders).toBe(renders);
  });

  it("sets no timer when no row will change", () => {
    vi.useFakeTimers({now: START});
    const shown = mount([{starts_at: "2026-11-01T00:00:00Z"}]);
    expect(vi.getTimerCount()).toBe(0);
    expect(shown.live).toBe(1);
  });
});
