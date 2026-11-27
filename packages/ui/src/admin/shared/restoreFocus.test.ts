import {afterEach, beforeEach, describe, expect, it, vi} from "vitest";

import {createButton, focusIsLost, modalityAfter, pickBannerTarget, focusTargetAfterWrite, rememberFocus, restoreFocusLater, whenGone, type FocusOrigin} from "./restoreFocus.ts";

// wp10-r7-1. The focus counts as lost on <body>, on nothing, and on a node that left the document; anywhere else it is
// somebody's choice (React Aria's own restore, or the person) and is left alone.
describe("focusIsLost", () => {
  const body = {isConnected: true} as unknown as HTMLElement;
  it("is lost on the body, on nothing and on a node that is gone", () => {
    expect(focusIsLost({activeElement: body, body})).toBe(true);
    expect(focusIsLost({activeElement: null, body})).toBe(true);
    expect(focusIsLost({activeElement: {isConnected: false} as unknown as HTMLElement, body})).toBe(true);
  });
  it("is not lost on an element in the page", () => {
    expect(focusIsLost({activeElement: {isConnected: true} as unknown as HTMLElement, body})).toBe(false);
  });
});

// wp10-r8-2. The browser cases cannot fail deterministically on the old code (React Aria's own restore usually wins the race),
// so the behaviour is also pinned here, on a small stand-in for the page: a dialog that leaves later, a focus that is lost,
// and a header button that the helper has to find. The real selector is checked in the browser case of admin-keyboard.spec.ts,
// which makes React Aria's restore fail, so that only restoreFocusLater can put the focus back.
type Node = {
  isConnected: boolean;
  disabled?: boolean;
  attributes: Record<string, string>;
  focus: ReturnType<typeof vi.fn>;
  getAttribute: (name: string) => string | null;
  contains: (other: unknown) => boolean;
  closest: (selector: string) => Node | null;
  matches: (selector: string) => boolean;
  parentElement: Node | null;
  querySelector: (selector: string) => Node | null;
  querySelectorAll: (selector: string) => Node[];
  getClientRects: () => unknown[];
};

function node(init: Partial<Node> = {}): Node {
  const self: Node = {
    isConnected: true,
    attributes: {},
    getAttribute: (name) => self.attributes[name] ?? null,
    focus: vi.fn(() => {
      page.activeElement = self;
    }),
    contains: (other) => other === self,
    closest: () => null,
    matches: () => false,
    parentElement: null,
    querySelector: () => null,
    querySelectorAll: (selector) => {
      const found = self.querySelector(selector);
      return found ? [found] : [];
    },
    getClientRects: () => [{}],
    ...init,
  };
  return self;
}

type Page = {
  body: Node;
  activeElement: Node;
  dialogs: Node[];
  selectors: string[];
  dialogSelectors: string[];
  header: Node | null;
};
let page: Page;
let frames: (() => void)[];

/** Runs the queued animation frames, one round, as a browser would between two paints. */
function paint(rounds = 1) {
  for (let i = 0; i < rounds; i++) {
    const queued = frames;
    frames = [];
    for (const callback of queued) callback();
  }
}

beforeEach(() => {
  const body = node();
  page = {body, activeElement: body, dialogs: [], selectors: [], dialogSelectors: [], header: null};
  frames = [];
  vi.stubGlobal("window", {});
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => frames.push(callback));
  vi.stubGlobal("CSS", {escape: (value: string) => value});
  vi.stubGlobal("document", {
    get body() {
      return page.body;
    },
    get activeElement() {
      return page.activeElement;
    },
    querySelectorAll: (selector: string) => {
      page.dialogSelectors.push(selector);
      return page.dialogs;
    },
    querySelector: (selector: string) => {
      page.selectors.push(selector);
      return page.header;
    },
  });
});

afterEach(() => vi.unstubAllGlobals());

describe("restoreFocusLater", () => {
  it("waits for a dialog that is leaving, then gives the lost focus to the target", () => {
    const target = node();
    const dialog = node();
    page.dialogs = [dialog];
    restoreFocusLater(() => target as unknown as HTMLElement);
    paint(4);
    expect(target.focus, "a dialog is still in the page").not.toHaveBeenCalled();
    page.dialogs = [];
    paint(5);
    expect(target.focus).toHaveBeenCalledTimes(1);
    expect(page.activeElement).toBe(target);
  });

  it("leaves a focus that is somewhere meaningful alone", () => {
    const target = node();
    const elsewhere = node();
    page.activeElement = elsewhere;
    restoreFocusLater(() => target as unknown as HTMLElement);
    paint(5);
    expect(target.focus).not.toHaveBeenCalled();
    expect(page.activeElement).toBe(elsewhere);
  });

  it("gives the focus to the target when the focused node left the page", () => {
    const target = node();
    page.activeElement = node({isConnected: false});
    restoreFocusLater(() => target as unknown as HTMLElement);
    paint(5);
    expect(target.focus).toHaveBeenCalledTimes(1);
  });

  it("does nothing, and does not throw, when the target is gone or never found", () => {
    restoreFocusLater(() => null);
    restoreFocusLater(() => node({isConnected: false}) as unknown as HTMLElement);
    paint(5);
    expect(page.activeElement).toBe(page.body);
  });

  it("does not wait for the dialog the form stays in (a failed save in an edit dialog)", () => {
    const field = node();
    const dialog = node({contains: (other) => other === field});
    page.dialogs = [dialog];
    restoreFocusLater(() => field as unknown as HTMLElement, {staying: field as unknown as Element});
    paint(4);
    expect(field.focus).toHaveBeenCalledTimes(1);
  });

  it("still waits for another dialog when the form's own stays", () => {
    const field = node();
    const mine = node({contains: (other) => other === field});
    const leaving = node();
    page.dialogs = [mine, leaving];
    restoreFocusLater(() => field as unknown as HTMLElement, {staying: field as unknown as Element});
    paint(4);
    expect(field.focus).not.toHaveBeenCalled();
    page.dialogs = [mine];
    paint(4);
    expect(field.focus).toHaveBeenCalledTimes(1);
  });
});

describe("a toast", () => {
  // A toast is an alertdialog (aria-modal false) that stays for seconds. Waiting for it made every restore wait for the give-up time.
  it("is not a dialog the focus waits for", () => {
    restoreFocusLater(() => null);
    paint(2);
    expect(page.dialogSelectors.length).toBeGreaterThan(0);
    for (const selector of page.dialogSelectors) expect(selector).toContain(':not([data-slot="toast"])');
  });
});

describe("createButton", () => {
  it("looks for the page header's button with this accessible name, and finds nothing when there is none", () => {
    expect(createButton("Create user")).toBeNull();
    expect(page.selectors).toEqual(['.page-header button[aria-label="Create user"]']);
    const button = node();
    page.header = button;
    expect(createButton("Create user")).toBe(button);
  });

  it("is what restoreFocusLater focuses after the dialog has left", () => {
    const button = node();
    page.header = button;
    restoreFocusLater(() => createButton("Create user"));
    paint(5);
    expect(button.focus).toHaveBeenCalledTimes(1);
  });
});

// wp10-r8-1, wp10-r9-1. After a write the focus goes back to the field that had it, which the pending state disabled. When the
// control that had it removed itself (the Confirm of a draft block, a Retry whose error cleared) the containers it sat in, remembered
// while it was still there, say where the focus goes.
const asOrigin = (element: Node, scopes: Node[] = []) => ({element, scopes}) as unknown as FocusOrigin;
const isForm = (selector: string) => selector.startsWith("form");

describe("focusTargetAfterWrite", () => {
  it("is the element that had the focus when it can take it again", () => {
    const field = node();
    expect(focusTargetAfterWrite(asOrigin(field))).toBe(field);
  });

  it("is nothing when the element and every container it sat in left the page with their dialog", () => {
    expect(focusTargetAfterWrite(asOrigin(node({isConnected: false}), [node({isConnected: false})]))).toBeNull();
    expect(focusTargetAfterWrite(asOrigin(node({isConnected: false})))).toBeNull();
    expect(focusTargetAfterWrite(null)).toBeNull();
  });

  it("is the first field of its form when the element cannot take the focus (a Save button that is off once nothing is left to save)", () => {
    const first = node();
    const form = node({matches: isForm, querySelector: (selector) => (selector.startsWith("input") ? first : null)});
    const save = node({disabled: true});
    expect(focusTargetAfterWrite(asOrigin(save, [form]))).toBe(first);
  });

  it("falls back to an enabled button of the container when it has no field", () => {
    const button = node();
    const form = node({matches: isForm, querySelector: (selector) => (selector.startsWith("button") ? button : null)});
    const off = node({attributes: {"aria-disabled": "true"}});
    off.disabled = true;
    expect(focusTargetAfterWrite(asOrigin(off, [form]))).toBe(button);
  });

  // The Confirm of the registration draft: the whole draft block unmounts with the button, the card and its form stay.
  it("is the first field of the form when the control removed itself with its block (Confirm, Retry, a conflict answer)", () => {
    const field = node();
    const form = node({matches: isForm, querySelector: (selector) => (selector.startsWith("input") ? field : null)});
    const block = node({isConnected: false});
    const confirm = node({isConnected: false});
    expect(focusTargetAfterWrite(asOrigin(confirm, [block, form]))).toBe(field);
  });

  it("passes over a plain wrapper that holds only a Cancel button for the form with the fields", () => {
    const cancel = node();
    const field = node();
    const row = node({querySelector: (selector) => (selector.startsWith("button") ? cancel : null)});
    const form = node({matches: isForm, querySelector: (selector) => (selector.startsWith("input") ? field : null)});
    expect(focusTargetAfterWrite(asOrigin(node({isConnected: false}), [row, form]))).toBe(field);
  });

  // wp10-r16-2. The Users header holds a search field collapsed to its button, with no box. It came first in the container that
  // survived the error boundary, focus() on it did nothing, and the focus stayed on <body>.
  it("passes over a field that takes no space (a collapsed search input) for the next one", () => {
    const collapsed = node({getClientRects: () => []});
    const visible = node();
    const wrapper = node({querySelectorAll: (selector) => (selector.startsWith("input") ? [collapsed, visible] : [])});
    expect(focusTargetAfterWrite(asOrigin(node({isConnected: false}), [wrapper]))).toBe(visible);
  });

  it("is nothing when every field of the container takes no space and it holds no button", () => {
    const collapsed = node({getClientRects: () => []});
    const wrapper = node({querySelectorAll: (selector) => (selector.startsWith("input") ? [collapsed] : [])});
    expect(focusTargetAfterWrite(asOrigin(node({isConnected: false}), [wrapper]))).toBeNull();
  });

  it("does not return an element that took no space even when it is the one that had the focus", () => {
    expect(focusTargetAfterWrite(asOrigin(node({getClientRects: () => []})))).toBeNull();
  });

  it("uses a plain container when no form-like one is left", () => {
    const field = node();
    const wrapper = node({querySelector: (selector) => (selector.startsWith("input") ? field : null)});
    expect(focusTargetAfterWrite(asOrigin(node({isConnected: false}), [wrapper]))).toBe(field);
  });
});

describe("rememberFocus", () => {
  it("collects the containers up to the main region, and stops after a dialog", () => {
    const main = node({matches: (selector) => selector.includes("main")});
    const card = node({parentElement: main});
    const dialog = node({parentElement: card, matches: (selector) => selector.includes("dialog")});
    const form = node({parentElement: dialog});
    const button = node({parentElement: form});
    const origin = rememberFocus(button as unknown as HTMLElement);
    expect(origin?.scopes).toEqual([form, dialog]);
    expect(rememberFocus(null)).toBeNull();
    expect(rememberFocus(node({parentElement: card}) as unknown as HTMLElement)?.scopes).toEqual([card]);
  });
});

// wp10-r13-1. Where the focus goes when a shell banner has been dismissed.
describe("pickBannerTarget", () => {
  it("is the button now in the dismissed banner place, else the last one, else the main region", () => {
    expect(pickBannerTarget(["a", "b", "c"], 1, "main")).toBe("b");
    expect(pickBannerTarget(["a", "b"], 2, "main")).toBe("b");
    expect(pickBannerTarget(["a"], -1, "main")).toBe("a");
    expect(pickBannerTarget([], 0, "main")).toBe("main");
    expect(pickBannerTarget([], 0, null)).toBeNull();
  });
});

// wp10-r16-2. The reset of a render-error boundary returns nothing, so the focus check waits until the Retry button has left the
// page. A check made after two frames could come before React has swapped the error for the page.
describe("whenGone", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("resolves when the element has left the page, not before", async () => {
    const element = node();
    let done = false;
    void whenGone(element as unknown as HTMLElement).then(() => (done = true));
    await vi.advanceTimersByTimeAsync(400);
    expect(done, "the element is still in the page").toBe(false);
    element.isConnected = false;
    await vi.advanceTimersByTimeAsync(100);
    expect(done).toBe(true);
  });

  it("gives up after the limit when the segment throws again and the button stays", async () => {
    const element = node();
    let done = false;
    void whenGone(element as unknown as HTMLElement, 1000).then(() => (done = true));
    await vi.advanceTimersByTimeAsync(900);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(200);
    expect(done).toBe(true);
  });

  it("resolves at once for nothing", async () => {
    let done = false;
    void whenGone(null).then(() => (done = true));
    await vi.advanceTimersByTimeAsync(0);
    expect(done).toBe(true);
  });
});

// wp10-r20-1. Only a keyboard interaction makes the focus worth giving back; after a pointer press on Save the focus stays where the
// pointer put it, or the page scrolls to the first field and a phone opens its soft keyboard.
describe("modalityAfter", () => {
  it("a key press is the keyboard, a pointer press is not", () => {
    expect(modalityAfter(false, {type: "keydown", key: "Enter"})).toBe(true);
    expect(modalityAfter(false, {type: "keydown", key: "Tab"})).toBe(true);
    expect(modalityAfter(true, {type: "pointerdown"})).toBe(false);
    expect(modalityAfter(true, {type: "mousedown"})).toBe(false);
    expect(modalityAfter(true, {type: "touchstart"})).toBe(false);
  });
  it("a modifier alone starts a chord (Ctrl+click) and changes nothing", () => {
    for (const key of ["Shift", "Control", "Alt", "Meta"]) {
      expect(modalityAfter(false, {type: "keydown", key})).toBe(false);
      expect(modalityAfter(true, {type: "keydown", key})).toBe(true);
    }
  });
  it("a click with no pointer behind it (detail 0) is the keyboard or an assistive technology; a real click changes nothing", () => {
    expect(modalityAfter(false, {type: "click", detail: 0})).toBe(true);
    expect(modalityAfter(false, {type: "click", detail: 1})).toBe(false);
    expect(modalityAfter(true, {type: "click", detail: 1})).toBe(true);
  });
  it("any other event says nothing", () => {
    expect(modalityAfter(true, {type: "focus"})).toBe(true);
    expect(modalityAfter(false, {type: "focus"})).toBe(false);
  });
});
