import {describe, expect, it, vi} from "vitest";

import {FOCUS_MAIN_WAIT_MS, focusMainWhenBack} from "./focusMain.ts";

// wp4-r9-1: after the idle cover's Continue, focus is on <body> and the page comes back as a skeleton
// first. Focus goes to #main-content once it exists, and only while focus is still nowhere.
function fakeDoc() {
  const body = {tagName: "BODY"};
  const state = {active: body as unknown, main: undefined as undefined | {focus: () => void}};
  const doc = {
    body,
    get activeElement() {
      return state.active;
    },
    getElementById: (id: string) => (id === "main-content" ? (state.main ?? null) : null),
  } as unknown as Document;
  let notify: () => void = () => undefined;
  let disconnected = false;
  const observe = (onChange: () => void) => {
    notify = onChange;
    return {disconnect: () => void (disconnected = true)};
  };
  return {doc, state, body, observe, mutate: () => notify(), isDisconnected: () => disconnected};
}

describe("focusing the page after the idle cover", () => {
  it("waits for #main-content and focuses it when it appears", () => {
    const d = fakeDoc();
    const stop = focusMainWhenBack(d.doc, d.observe);
    d.mutate(); // the skeleton renders: no main-content yet
    const focus = vi.fn();
    d.state.main = {focus};
    expect(focus).not.toHaveBeenCalled();
    d.mutate();
    expect(focus).toHaveBeenCalledTimes(1);
    expect(d.isDisconnected()).toBe(true);
    d.mutate();
    expect(focus).toHaveBeenCalledTimes(1);
    stop();
  });

  it("focuses at once when the page is already there", () => {
    const d = fakeDoc();
    const focus = vi.fn();
    d.state.main = {focus};
    focusMainWhenBack(d.doc, d.observe);
    expect(focus).toHaveBeenCalledTimes(1);
  });

  it("leaves focus alone when it is somewhere else already", () => {
    const d = fakeDoc();
    d.state.active = {tagName: "INPUT"};
    const focus = vi.fn();
    d.state.main = {focus};
    focusMainWhenBack(d.doc, d.observe);
    d.mutate();
    expect(focus).not.toHaveBeenCalled();
    expect(d.isDisconnected()).toBe(true);
  });

  it("gives up after FOCUS_MAIN_WAIT_MS", () => {
    vi.useFakeTimers();
    const d = fakeDoc();
    focusMainWhenBack(d.doc, d.observe, (fn, ms) => setTimeout(fn, ms) as unknown, (id) => clearTimeout(id as never));
    vi.advanceTimersByTime(FOCUS_MAIN_WAIT_MS + 1);
    expect(d.isDisconnected()).toBe(true);
    const focus = vi.fn();
    d.state.main = {focus};
    d.mutate();
    expect(focus).not.toHaveBeenCalled();
    vi.useRealTimers();
  });
});
