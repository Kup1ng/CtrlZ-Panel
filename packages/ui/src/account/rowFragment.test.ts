import {describe, expect, it} from "vitest";

import {rowAfterBellClosed, rowToHandle} from "./useRowFragment.ts";

// webi-r1-1: a fragment is acted on once. useUrlDialog keeps it in the address on every open and close of every dialog, and each
// of those runs the effect again, which must not move the page or the focus a second time.
describe("rowToHandle", () => {
  it("moves to the row of a new fragment and remembers it", () => {
    expect(rowToHandle("#sessions", undefined, false)).toEqual({row: "sessions", handled: undefined});
  });

  it("does nothing for a fragment that was handled, however often the search parameters change", () => {
    expect(rowToHandle("#sessions", "sessions", false)).toEqual({row: undefined, handled: "sessions"});
  });

  it("moves again when the fragment names another row", () => {
    expect(rowToHandle("#password", "sessions", false)).toEqual({row: "password", handled: "sessions"});
  });

  it("forgets a row once the address has no row fragment, so the same link works again later", () => {
    expect(rowToHandle("", "sessions", false)).toEqual({row: undefined, handled: undefined});
    expect(rowToHandle("#phone", "sessions", false)).toEqual({row: undefined, handled: undefined});
  });

  it("always moves for a hashchange, which is a person's own navigation", () => {
    expect(rowToHandle("#sessions", "sessions", true)).toEqual({row: "sessions", handled: "sessions"});
  });
});

// webi-r2-2: a link of the bell to the row the page is at changes only the search parameters, and the fragment was handled
// already, so the second press moved nothing. The link names its row, and the move waits for the bell to close.
describe("rowAfterBellClosed", () => {
  it("gives the row a link named once the bell has just closed", () => {
    expect(rowAfterBellClosed("sessions", true, false)).toBe("sessions");
  });

  it("gives nothing when the bell was closed with no link (Escape), or while it is open, or when it only opens", () => {
    expect(rowAfterBellClosed(undefined, true, false)).toBeUndefined();
    expect(rowAfterBellClosed("sessions", true, true)).toBeUndefined();
    expect(rowAfterBellClosed("sessions", false, true)).toBeUndefined();
    expect(rowAfterBellClosed("sessions", false, false)).toBeUndefined();
  });

  it("a forced move reaches the row even when it was handled, which is what the link needs", () => {
    expect(rowToHandle("#sessions", "sessions", true)).toEqual({row: "sessions", handled: "sessions"});
  });
});
