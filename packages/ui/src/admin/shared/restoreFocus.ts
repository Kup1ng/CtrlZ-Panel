// Where the keyboard focus goes when a dialog of the admin app is gone (spec 17.5, wp10-r7-1).
//
// React Aria hands the focus back by itself, to the element that was focused when the dialog's focus scope mounted, and
// when that element is gone, to the nearest one still in the page. That is right for a dialog that opens from a button
// and closes while the button is there. It fails in two places this app has:
//
//   - A state-only result panel opens at the moment the form that made it closes. Its scope may mount while the form's
//     scope is still on its way out, or just after it left, and then it has no element to go back to (the submit button
//     it saw is gone) and the focus falls to <body>. Which of the two happens depends on the animation, so a test passes
//     on one run and fails on the next.
//   - A confirm dialog whose action removes its own trigger (revoking an invite takes the Revoke button away) has nothing
//     left to go back to.
//
// So the focus is checked once the dialog has really left, and only when it is lost (on <body>, or on a node that is no
// longer in the page) it goes to `target`. A focus that React Aria already restored, or that the person moved on
// purpose, is left alone. Plain functions with no state of their own, so a component that unmounts together with its
// dialog (the result panel) can still call it from its cleanup.

import {DIALOG_SELECTOR} from "../../hooks/dialogSelector.ts";

// A toast is not a dialog the focus has to wait for: counting it made every restore after a toast wait for the give-up time, and lose
// races to a later one. The selector is shared with the shell's shortcuts (hooks/dialogSelector.ts).
const DIALOG = DIALOG_SELECTOR;
/** A dialog that is still on its exit animation stops the wait this long after the call; the focus is checked then at the latest. */
const GIVE_UP_MS = 1500;
/** Frames to let React Aria's own restore (one frame after the dialog unmounts) run before the check. */
const SETTLE_FRAMES = 2;

/** True when nothing is focused: <body>, or an element that left the document. Exported for the unit test. */
export function focusIsLost(doc: Pick<Document, "activeElement" | "body">): boolean {
  const active = doc.activeElement;
  return !active || active === doc.body || !active.isConnected;
}

/** A dialog of the page that is not the one `staying` is in: the ones whose exit the focus has to wait for. */
function leavingDialogs(staying: Element | null | undefined): boolean {
  return [...document.querySelectorAll(DIALOG)].some((dialog) => !(staying && dialog.contains(staying)));
}

/**
 * Focus `target()` once no dialog is left in the page, unless the focus is somewhere meaningful already. A form that sits in a
 * dialog which stays open (a failed save in an edit dialog) names itself in `options.staying`, so the wait is for the dialogs
 * that are leaving and not for the one that is staying (it would never end, and the focus would be lost until the give-up time).
 */
export function restoreFocusLater(target: () => HTMLElement | null | undefined, options: {staying?: Element | null} = {}): void {
  if (typeof window === "undefined") return;
  const started = performance.now();
  const settle = (frames: number) => {
    if (frames > 0) return void requestAnimationFrame(() => settle(frames - 1));
    if (!focusIsLost(document)) return;
    const element = target();
    if (element?.isConnected) element.focus({preventScroll: false});
  };
  const waitForExit = () => {
    if (leavingDialogs(options.staying) && performance.now() - started < GIVE_UP_MS) return void requestAnimationFrame(waitForExit);
    settle(SETTLE_FRAMES);
  };
  requestAnimationFrame(waitForExit);
}

/** The "+" button of the page header with this accessible name: where a create dialog was opened from. */
export function createButton(label: string): HTMLElement | null {
  return document.querySelector<HTMLElement>(`.page-header button[aria-label="${CSS.escape(label)}"]`);
}

/** The grid with this accessible name. A table is focusable as a whole, and the next Tab continues from it into its first row. */
export function gridOf(label: string): HTMLElement | null {
  return document.querySelector<HTMLElement>(`[role="grid"][aria-label="${CSS.escape(label)}"]`);
}

/** The selected tab of the tab list with this accessible name: where the focus goes when the section above the tabs is gone. */
export function selectedTabOf(label: string): HTMLElement | null {
  return document.querySelector<HTMLElement>(`[role="tablist"][aria-label="${CSS.escape(label)}"] [role="tab"][aria-selected="true"]`);
}

// How the last interaction was made (wp10-r20-1). Giving the focus back is for a person who works with the keyboard and would
// otherwise start again from the skip link. For a pointer it is harm: a press on Save leaves Save focused, Save is off once the
// write succeeds, and the fallback is the first field of the form, so the page scrolled up to it and a phone opened its soft
// keyboard. So the focus is remembered only after a keyboard interaction. It is tracked here, from the events, and not read from
// :focus-visible, which a key press on a button focused by a click may not set.

/** The new modality after `event`, or `current` when the event says nothing. Pure, for the unit test. */
export function modalityAfter(current: boolean, event: {type: string; key?: string; detail?: number}): boolean {
  switch (event.type) {
    case "keydown":
      // A modifier alone is the start of a chord such as Ctrl+click, not a keyboard interaction.
      return ["Shift", "Control", "Alt", "Meta", "AltGraph", "CapsLock"].includes(event.key ?? "") ? current : true;
    case "pointerdown":
    case "mousedown":
    case "touchstart":
      return false;
    case "click":
      // A click with no pointer behind it (detail 0) comes from the keyboard or an assistive technology, which both need the focus kept.
      return event.detail === 0 ? true : current;
    default:
      return current;
  }
}

/** True until a pointer is used: a page that no one has touched is driven by script or keyboard. */
let keyboardDriven = true;

/** Starts following the interaction modality on `target`; returns the stop function. Capture phase, so no handler can hide an event. */
export function trackModality(target: Pick<EventTarget, "addEventListener" | "removeEventListener">): () => void {
  const types = ["keydown", "pointerdown", "mousedown", "touchstart", "click"] as const;
  const onEvent = (event: Event) => {
    keyboardDriven = modalityAfter(keyboardDriven, event as unknown as {type: string; key?: string; detail?: number});
  };
  for (const type of types) target.addEventListener(type, onEvent, true);
  return () => {
    for (const type of types) target.removeEventListener(type, onEvent, true);
  };
}

if (typeof document !== "undefined") trackModality(document);

/**
 * The element that has the focus now, for a write or a removal to give it back when it ends. Not <body>, which is "nothing", and
 * nothing at all after a pointer interaction: the focus is then left where the pointer put it (wp10-r20-1).
 */
export function focusedElement(): HTMLElement | null {
  if (typeof document === "undefined" || !keyboardDriven) return null;
  const active = document.activeElement;
  return active instanceof HTMLElement && active !== document.body ? active : null;
}

const FIELD =
  'input:not([disabled]):not([type=hidden]):not([tabindex="-1"]), textarea:not([disabled]), select:not([disabled]), [role="radio"][tabindex="0"], [role="switch"]:not([aria-disabled="true"])';
const BUTTON = "button:not([disabled])";
const FORM_LIKE = 'form, fieldset, [role="dialog"], [role="alertdialog"]';

/**
 * The element that had the focus and the containers it sat in, remembered together (wp10-r9-1). A control that removes itself when
 * it is used (the Confirm of a draft block that closes, the Retry of an error that clears, a conflict note's answer) is gone by
 * the time the focus is wanted back, and the element alone then says nothing. Its containers, collected while it was still
 * in the page, say where it was: the nearest one that is still in the page is where the focus goes.
 */
export type FocusOrigin = {element: HTMLElement; scopes: HTMLElement[]};

/** Containers stop below the page's main region (never the sidebar), and after the first dialog, which is a scope of its own. */
const SCOPE_STOP = "main, body";

export function rememberFocus(element: HTMLElement | null): FocusOrigin | null {
  if (!element) return null;
  const scopes: HTMLElement[] = [];
  for (let node = element.parentElement; node && !node.matches(SCOPE_STOP); node = node.parentElement) {
    scopes.push(node);
    if (node.matches(DIALOG)) break;
  }
  return {element, scopes};
}

/** The element can take the focus. */
function usable(element: HTMLElement | null | undefined): element is HTMLElement {
  return !!element && element.isConnected && rendered(element) && !(element as HTMLInputElement).disabled && element.getAttribute("aria-disabled") !== "true";
}

/**
 * False for an element that takes no space (display:none, a search field that is collapsed to its button): focus() on it does
 * nothing, so choosing it as the target leaves the focus on <body> while the code believes it gave it back (wp10-r16-2: the Users
 * header holds a collapsed search input, and it was the first field of the container that survived the error).
 */
function rendered(element: HTMLElement): boolean {
  return element.getClientRects().length > 0;
}

/** The first element of `scope` that matches `selector` and can show a focus ring. */
function firstRendered(scope: HTMLElement, selector: string): HTMLElement | null {
  return [...scope.querySelectorAll<HTMLElement>(selector)].find(rendered) ?? null;
}

/** What a dialog around a form that stays is judged by: the element, or else the nearest remembered container that is still in the page. */
function survivor(origin: FocusOrigin): HTMLElement | null {
  if (origin.element.isConnected) return origin.element;
  return origin.scopes.find((scope) => scope.isConnected) ?? null;
}

/**
 * Where the focus goes when a write that disabled the form has ended, or a control that removed itself has gone (wp10-r8-1,
 * wp10-r9-1):
 *   - the element that had it, when it can take it again;
 *   - else the first field of a container it sat in that is still in the page (a Save button that is off once nothing is left
 *     to save, or a Retry that cleared its own error: the form), then that container's first enabled button. A form, fieldset
 *     or dialog is tried before a plain wrapper, which may hold only a Cancel button;
 *   - else nothing, and the focus is left to React Aria and the page, as when the form has left with its dialog.
 */
export function focusTargetAfterWrite(origin: FocusOrigin | null): HTMLElement | null {
  if (!origin) return null;
  if (usable(origin.element)) return origin.element;
  const alive = origin.scopes.filter((scope) => scope.isConnected);
  const formLike = alive.filter((scope) => scope.matches(FORM_LIKE));
  for (const scope of [...formLike, ...alive.filter((candidate) => !formLike.includes(candidate))]) {
    const found = firstRendered(scope, FIELD) ?? firstRendered(scope, BUTTON);
    if (found) return found;
  }
  return null;
}

/** Gives the focus back to what `origin` stands for once the write or the removal is over, if it is lost by then. */
export function restoreFocusAfter(origin: FocusOrigin | null, prefer?: () => HTMLElement | null | undefined): void {
  if (!origin) return;
  restoreFocusLater(() => prefer?.() || focusTargetAfterWrite(origin), {staying: survivor(origin)});
}

/**
 * The field a note under it belongs to: the nearest focusable control before `note` in the document, without leaving the
 * form. A conflict note sits under its field, so this is the field to return to when the note answers itself away.
 */
export function fieldBefore(note: Element | null): HTMLElement | null {
  const stop = `${SCOPE_STOP}, ${FORM_LIKE}`;
  for (let node: Element | null = note; node && !node.matches(stop); node = node.parentElement) {
    for (let sibling = node.previousElementSibling; sibling; sibling = sibling.previousElementSibling) {
      const own = sibling.matches(FIELD) ? [sibling as HTMLElement] : [];
      const found = [...own, ...sibling.querySelectorAll<HTMLElement>(FIELD)].at(-1);
      if (found) return found;
    }
  }
  return null;
}

/**
 * Runs `action`, which removes the control that was pressed (a conflict note's answer, the Cancel of a draft, a Retry), and then
 * gives the focus back if it is lost: to the field `near` belongs to when there is one, else to the nearest container of the
 * control that is still there. Without it the focus falls to <body> and the next Tab starts at the skip link (wp10-r9-1). For an
 * action that returns a promise the focus is given back when it settles, after the form's own pending state is over.
 */
export function keepFocus(action: () => unknown, near?: Element | null, prefer?: () => HTMLElement | null | undefined): void {
  const origin = rememberFocus(focusedElement());
  const field = near ? fieldBefore(near) : null;
  // `prefer` is asked first, once the action has settled, for a control whose container leaves with it (the last alert of a
  // section that then renders nothing): the remembered scopes are gone, and the first field of the page's wrapper is not where
  // a keyboard user was going.
  const done = () => restoreFocusAfter(origin, () => prefer?.() || (usable(field) ? field : null));
  const result = action();
  if (result && typeof (result as Promise<unknown>).then === "function") void (result as Promise<unknown>).finally(done);
  else done();
}

// The shell's banners (wp10-r13-1). The close button of a banner leaves with its banner, and with the last one the whole stack
// renders nothing. The stack sits above the page, outside <main>, so the container search of rememberFocus would walk up to the
// whole shell and land on the sidebar: the target is named here instead.

/** The close buttons of the banners that are shown, in the order they are on the page. */
const BANNER_BUTTONS = ".banner-stack__item button";
/** The page's main region, the target of the skip link. It has tabindex -1, so it can take the focus and is not in the Tab order. */
const MAIN_REGION = "#main-content";

/**
 * Where the focus goes when the banner whose close button was number `index` has left: the button now in its place (the next
 * banner), else the last one, else `fallback` (the main region, when the stack is gone). Pure, for the unit test.
 */
export function pickBannerTarget<T>(buttons: readonly T[], index: number, fallback: T | null): T | null {
  if (buttons.length === 0) return fallback;
  return buttons[Math.min(Math.max(index, 0), buttons.length - 1)] ?? fallback;
}

/**
 * Runs `action`, which dismisses a banner (an alert's acknowledgement, a hidden notice), and gives the focus back if it is
 * lost: to the next banner's close button, or to the main region when there is none. Without it the focus falls to <body> with
 * the banner and the next Tab starts at the skip link.
 */
export function keepBannerFocus(action: () => unknown): void {
  const buttons = () => [...document.querySelectorAll<HTMLElement>(BANNER_BUTTONS)];
  const index = buttons().indexOf(focusedElement() as HTMLElement);
  keepFocus(action, null, () => pickBannerTarget(buttons(), index, document.querySelector<HTMLElement>(MAIN_REGION)));
}

/**
 * The onRetry of an error that is replaced by the content when the retry succeeds (a section error, a failed lookup in a dialog):
 * the Retry button that has the focus leaves with it, and the focus would fall to <body> (wp10-r15-1). Once the retry has
 * settled, the focus goes to the first field (else button) of the nearest container that is still in the page, and failing that to
 * the main region, which is the skip link's target. A retry that fails again leaves the button where it is, and nothing moves.
 * `retry` must return the promise of the refetch, so that the focus is checked after the answer and not before it.
 */
export function keepRetry(retry: () => unknown): () => void {
  return () => {
    const origin = rememberFocus(focusedElement());
    const done = () =>
      restoreFocusAfter(origin, () => focusTargetAfterWrite(origin) ?? document.querySelector<HTMLElement>(MAIN_REGION));
    const result = retry();
    if (result && typeof (result as Promise<unknown>).then === "function") void (result as Promise<unknown>).finally(done);
    else done();
  };
}

/** Resolves once `element` has left the page, or after `limitMs`: a boundary's reset has no promise to wait for. */
export function whenGone(element: Element | null, limitMs = 2000): Promise<void> {
  return new Promise((resolve) => {
    const started = Date.now();
    const look = () => {
      if (!element?.isConnected || Date.now() - started >= limitMs) resolve();
      else setTimeout(look, 40);
    };
    look();
  });
}

/**
 * The onRetry of a render-error boundary (Next's `reset`, wp10-r16-2). `reset` returns nothing and renders the segment again,
 * so there is no promise for keepRetry to wait on, and checking after two frames may come before React has swapped the error for
 * the page. The check waits until the Retry button that had the focus has left the page; if the segment throws again and the
 * button stays, nothing moves.
 */
export function keepReset(reset: () => void): () => void {
  return keepRetry(() => {
    const pressed = focusedElement();
    reset();
    return whenGone(pressed);
  });
}
