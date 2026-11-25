import {describe, expect, it} from "vitest";

import type {ThemeMode} from "../theme/config.ts";
import {createThemeWriter} from "./themeWriter.ts";

// A fake server and page. `answer(n)` lets the test decide when the n-th PATCH is answered, and the
// effect of the gate (adopt the theme of the newest /me) runs right after each answer.
function setup() {
  let page: ThemeMode = "system";
  let server: ThemeMode = "system";
  let inFlight = 0;
  let maxInFlight = 0;
  const sent: ThemeMode[] = [];
  const open: Array<() => void> = [];
  const writer = createThemeWriter({
    adoptServerMode: (m) => {
      page = m;
    },
    write: (mode) => {
      sent.push(mode);
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      return new Promise<void>((resolve) => {
        open.push(() => {
          server = mode;
          inFlight--;
          // The answer is a whole Me that holds `mode`: the cache changes and the gate's effect runs.
          writer.adopt(mode);
          resolve();
        });
      });
    },
  });
  // What the theme controller does: commit locally, then tell the writer.
  const choose = (mode: ThemeMode) => {
    page = mode;
    writer.request(mode);
  };
  return {writer, choose, sent, open, state: () => ({page, server, maxInFlight})};
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe("the theme write of the gate", () => {
  it("ends on the last choice when the first answer arrives after the second choice", async () => {
    const t = setup();
    t.choose("dark");
    t.choose("light");
    // Dark is in flight, light waits. Its answer carries dark, which must not reach the page.
    t.open[0]!();
    expect(t.state().page).toBe("light");
    await settle();
    t.open[1]!();
    await settle();
    expect(t.sent).toEqual(["dark", "light"]);
    expect(t.state()).toMatchObject({page: "light", server: "light"});
  });

  it("never has two writes in flight, so the server cannot take them in the wrong order", async () => {
    const t = setup();
    t.choose("dark");
    t.choose("light");
    t.choose("dark");
    expect(t.state().maxInFlight).toBe(1);
    expect(t.sent).toEqual(["dark"]);
    t.open[0]!();
    await settle();
    t.open[1]!();
    await settle();
    // The middle choice was replaced by the last one: it was never sent.
    expect(t.sent).toEqual(["dark", "dark"]);
    expect(t.state()).toMatchObject({page: "dark", server: "dark", maxInFlight: 1});
    expect(t.writer.busy).toBe(false);
  });

  it("adopts the server's theme when nothing of ours is pending (another device)", () => {
    const t = setup();
    t.writer.adopt("dark");
    expect(t.state().page).toBe("dark");
  });

  it("does not adopt while a write is in flight", () => {
    const t = setup();
    t.choose("light");
    t.writer.adopt("dark");
    expect(t.state().page).toBe("light");
    expect(t.writer.busy).toBe(true);
  });

  it("goes on with the next choice after a write failed", async () => {
    const sent: ThemeMode[] = [];
    const writer = createThemeWriter({
      adoptServerMode: () => undefined,
      write: (mode) => {
        sent.push(mode);
        return sent.length === 1 ? Promise.reject(new Error("503")) : Promise.resolve();
      },
    });
    writer.request("dark");
    writer.request("light");
    await settle();
    await settle();
    expect(sent).toEqual(["dark", "light"]);
    expect(writer.busy).toBe(false);
  });
});

// T-308. A write the server refused used to leave the page on the new theme and the account on the old one, so the next load flipped it
// back with no word. The rule is that the server wins: the page goes back at once, and the failure is reported once, for the last choice.
describe("a theme write that fails (T-308)", () => {
  function failing(serverStart: ThemeMode = "light") {
    let page: ThemeMode = serverStart;
    const reported: Array<{error: unknown; restored: ThemeMode | undefined}> = [];
    const outcomes: Array<"ok" | Error> = [];
    const writer = createThemeWriter({
      adoptServerMode: (m) => {
        page = m;
      },
      write: () => {
        const next = outcomes.shift() ?? "ok";
        return next === "ok" ? Promise.resolve() : Promise.reject(next);
      },
      onWriteFailed: (error, restored) => reported.push({error, restored}),
    });
    writer.adopt(serverStart);
    const choose = (mode: ThemeMode) => {
      page = mode;
      writer.request(mode);
    };
    return {writer, choose, outcomes, reported, page: () => page};
  }

  it("puts the server's theme back and reports the error when the last choice is refused", async () => {
    const t = failing("light");
    const boom = new Error("503");
    t.outcomes.push(boom);
    t.choose("dark");
    expect(t.page()).toBe("dark");
    await settle();
    expect(t.page()).toBe("light");
    expect(t.reported).toEqual([{error: boom, restored: "light"}]);
    expect(t.writer.busy).toBe(false);
  });

  it("says nothing when a later choice was saved after the failed one: the later one decided", async () => {
    const t = failing("light");
    t.outcomes.push(new Error("503"), "ok");
    t.choose("dark");
    t.choose("system");
    await settle();
    await settle();
    expect(t.reported).toEqual([]);
    expect(t.page()).toBe("system");
  });

  it("goes back to the theme the last successful write saved, not to the one the tab started with", async () => {
    const t = failing("light");
    t.outcomes.push("ok", new Error("503"));
    t.choose("dark");
    await settle();
    t.choose("system");
    await settle();
    expect(t.page()).toBe("dark");
    expect(t.reported.map((r) => r.restored)).toEqual(["dark"]);
  });

  it("does not report a success, and does not touch the page", async () => {
    const t = failing("light");
    t.choose("dark");
    await settle();
    expect(t.reported).toEqual([]);
    expect(t.page()).toBe("dark");
  });
});
