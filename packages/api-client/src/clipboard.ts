// The one place that writes to the system clipboard (gate-r5-8; ctrlz/no-storage bans `navigator.clipboard` anywhere else).
//
// The TOTP secret and the recovery codes are built to live in a component's state and nowhere else, but a copy puts them in a store that
// outlives the screen, the tab and the session: the next person at a shared PC reads it with Ctrl+V, and on Windows the clipboard
// history (Win+V, and its cloud sync when the person turned it on) keeps it as well. A page cannot reach the history, so the most it can do
// is not to leave the last value in the clipboard itself: it is overwritten with an empty string when the screen that offered the copy
// closes and when the session is left. The history outside the web API is said on the screen (spec 12.3).
//
// A browser refuses that write when the document has no focus (Chrome) or when there is no user gesture (Safari), and the cases that matter
// most for a shared PC are such cases: the idle cover, a logout from another tab. So (gate-r6-6, gate-r6-8):
//  - a refused write is not given up. The copy stays remembered, and the next focus, visibility change, pointer press or key press of the
//    document tries again;
//  - the memory is a flag in sessionStorage as well (a boolean, never the secret), so the page that a full load opens (login after a
//    logout, the same page after a reload) picks it up and tries again when this tab is looked at;
//  - a copy that the person made by hand from the secret on screen (it is `select-all`) is noticed by the `copy` event, so it is remembered
//    like one made with the button;
//  - `pagehide` tries once more, best effort.
// What a page can never do is wipe a copy after its tab has been closed with no write accepted; the note on the screen says so.
//
// The clipboard is shared by every tab of the origin, the memory is not (gate-r7-10). A copy made in tab 1 and a logout (or a sign-in as
// another person) in tab 2: tab 1 hears of it, but it is in the background, so the browser refuses its write; tab 2 has the focus and the
// gesture, and held nothing. So the tabs tell each other on a BroadcastChannel: "held" when a copy is remembered, "clear" when the clipboard
// no longer holds it (a write was accepted, or the person copied something else), "query" when a page loads. A tab that knows a sibling
// holds a copy overwrites too, from its own gesture, and its "clear" makes the sibling forget. Only the fact that a copy exists is sent,
// never the secret.
//
// The other side (gate-r6-7): the wipe empties whatever the clipboard holds. A page cannot read it, but it sees every copy made in the page:
// a `copy` event that takes other text than a marked secret means the clipboard no longer holds the secret, so the memory is dropped and
// the person's own later copy is left alone. A `copy` that takes nothing (Ctrl+C with no selection fires the event and writes nothing)
// changes nothing and the memory stays (gate-r7-9). A copy made in another app after the secret is out of sight, and the note says it is emptied too.
// The same rule holds across tabs (gate-r13-9): a tab that only knows of a sibling's copy also lets go, and tells the sibling, when the person
// copies text in it, so the sibling's close does not empty that text.
//
// A Copy whose write the browser has not answered yet is not remembered, so a wipe asked for in that window (the dialog closed by Escape, Cancel
// or the idle cover) would find nothing to do and the write would land afterwards with no screen left to wipe it. The wipe is therefore kept as a
// wish and acted on when the write lands (gate-r13-8).

/** Mark every element that shows a one-time secret with this attribute, so a manual copy of it is recognised. */
export const ONE_TIME_SECRET_ATTRIBUTE = "data-one-time-secret";

const PENDING_KEY = "ctrlz_clip_pending";
const SECRET_SELECTOR = `[${ONE_TIME_SECRET_ATTRIBUTE}]`;
const WINDOW_EVENTS = ["focus", "pointerdown", "keydown"] as const;

const CLIP_CHANNEL = "ctrlz-clip";

type ClipMessage = "held" | "clear" | "query";

let held = false;
/** Another tab of the origin reported a copy that nobody has overwritten since. */
let siblingHeld = false;
/** Counts the "held" messages, so a wipe that was on its way when a newer one arrived does not clear it. */
let siblingCopies = 0;
let armed = false;
let copies = 0;
let writing: Promise<void> | null = null;
/** Copy writes that the browser has not answered yet (gate-r13-8). */
let copying = 0;
/** A wipe was asked for while a copy was still on its way: that copy is overwritten as soon as it lands. */
let wipeAfterCopy = false;
let installedOn: unknown = null;

function setFlag(on: boolean) {
  try {
    if (on) sessionStorage.setItem(PENDING_KEY, "1");
    else sessionStorage.removeItem(PENDING_KEY);
  } catch {
    // Storage is blocked: the flag is then only a help for the next page, and this page still retries.
  }
}

let clipChannel: BroadcastChannel | null | undefined;

/** One channel object per tab: a message reaches the OTHER objects of the name only, so this tab never hears itself. */
function channel(): BroadcastChannel | null {
  if (clipChannel !== undefined) return clipChannel;
  try {
    clipChannel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(CLIP_CHANNEL);
    // Node (the unit tests) would otherwise wait for it; a browser has no such method.
    (clipChannel as {unref?: () => void} | null)?.unref?.();
    clipChannel?.addEventListener("message", (event) => onSibling((event as MessageEvent).data));
    // A page that has just loaded cannot know what the others hold: ask, and the holder answers "held".
    clipChannel?.postMessage("query" satisfies ClipMessage);
  } catch {
    clipChannel = null;
  }
  return clipChannel;
}

function post(message: ClipMessage) {
  try {
    channel()?.postMessage(message);
  } catch {
    // No channel: the tabs do not know of each other, and each still wipes what it copied itself.
  }
}

/** The clipboard no longer holds a copy that this page knew of: forget it here, with no message. */
function forget() {
  held = false;
  siblingHeld = false;
  setFlag(false);
  disarm();
}

function onSibling(message: unknown) {
  if (message === "held") {
    siblingHeld = true;
    siblingCopies += 1;
    return;
  }
  if (message === "clear") {
    forget();
    return;
  }
  if (message === "query" && held) post("held");
}

function hold() {
  copies += 1;
  held = true;
  setFlag(true);
  post("held");
}

function release() {
  forget();
  post("clear");
}

function onRetry() {
  if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
  void overwrite();
}

function arm() {
  if (armed || typeof window === "undefined" || typeof window.addEventListener !== "function") return;
  armed = true;
  for (const name of WINDOW_EVENTS) window.addEventListener(name, onRetry, {capture: true, passive: true});
  document.addEventListener?.("visibilitychange", onRetry, {capture: true, passive: true});
}

function disarm() {
  if (!armed) return;
  armed = false;
  for (const name of WINDOW_EVENTS) window.removeEventListener(name, onRetry, {capture: true});
  document.removeEventListener?.("visibilitychange", onRetry, {capture: true});
}

/** True when the selection that is being copied takes in any element that shows a one-time secret. */
function selectionTouchesSecret(): boolean {
  try {
    const selection = document.getSelection();
    if (!selection || selection.rangeCount === 0 || selection.isCollapsed) return false;
    for (const element of Array.from(document.querySelectorAll(SECRET_SELECTOR))) {
      if (selection.containsNode(element, true)) return true;
    }
  } catch {
    // An environment without a selection API cannot have a secret on screen to copy by hand.
  }
  return false;
}

/**
 * True when this copy puts text in the clipboard. Ctrl+C with nothing selected fires a `copy` event too (focus on a button, a collapsed
 * caret, an input with no selection) and writes nothing: the clipboard still holds what was there, so it must not make the memory forget a
 * secret (gate-r7-9). A selection inside an input or a textarea is reported by the document as collapsed, so its text is read from the
 * element as well. A handler that took over the copy and set its own data counts as a copy of something.
 */
function copiesText(event: Event): boolean {
  try {
    if (document.getSelection()?.toString()) return true;
    // Duck-typed: only an input or a textarea has a selection range (a button or a checkbox has null there).
    const active = document.activeElement as {selectionStart?: number | null; selectionEnd?: number | null} | null;
    if (active && typeof active.selectionStart === "number" && active.selectionStart !== active.selectionEnd) return true;
    const data = (event as ClipboardEvent).clipboardData;
    if (data && data.types.length > 0) return true;
  } catch {
    // An environment without these APIs cannot copy text the page cannot see; the memory stays.
    return false;
  }
  return false;
}

function onCopyEvent(event: Event) {
  if (selectionTouchesSecret()) {
    hold();
    return;
  }
  // The person copied something else from this page: the clipboard no longer holds the secret, and what it holds is theirs. A copy of
  // nothing leaves the clipboard as it was, so the secret is still there and still to be wiped.
  // A tab that only knows of a sibling's copy counts too (gate-r13-9): it cannot wipe on the sibling's behalf and keep the person's text, and
  // the sibling would otherwise wipe what the person copied here when its own screen closes. release() forgets here and tells the others.
  if ((held || siblingHeld) && copiesText(event)) release();
}

/**
 * The context menu of a selected secret (gate-r28-7). The secret and every recovery code are select-all, so one click selects the whole value,
 * and the browser's own menu then offers "Copy link to highlight": the browser writes <page address>#:~:text=<the selection> itself, from outside
 * the page, and fires no `copy` event in it. The page cannot see that write, so opening the menu on a selected secret is taken as a copy: the memory
 * is held and the close-time wipe empties the clipboard, whatever the menu ended in. The cost is the one the copy note already states, that
 * closing empties whatever the clipboard holds. A menu on a selection that touches no secret changes nothing.
 */
function onContextMenu() {
  if (selectionTouchesSecret()) hold();
}

function onPageHide() {
  // A sibling's copy is not this page's to retry when it closes: the sibling's own page does that.
  if (held) void overwrite();
}

/** Listens on the current window once; the listeners cost nothing while no secret was copied. */
function install() {
  if (typeof window === "undefined" || typeof document === "undefined" || installedOn === window) return;
  installedOn = window;
  document.addEventListener?.("copy", onCopyEvent, {capture: true, passive: true});
  // Ctrl+X in a field replaces the clipboard with the person's text and fires `cut`, not `copy` (gate-r25-7): the same rules apply, or the
  // close-time wipe would empty text the person cut after copying a secret. The event comes before the text leaves the field, so the selection is still readable.
  document.addEventListener?.("cut", onCopyEvent, {capture: true, passive: true});
  document.addEventListener?.("contextmenu", onContextMenu, {capture: true, passive: true});
  window.addEventListener?.("pagehide", onPageHide, {capture: true, passive: true});
}

/** One overwrite at a time. Keeps the memory and arms the retry when the browser refuses. */
function overwrite(): Promise<void> {
  // A wipe that runs while a Copy is still waiting for the browser finds nothing remembered yet, and the write then lands with no screen left
  // to wipe it (the dialog closed in between: Escape, Cancel, an idle cover). The wish is kept and copyOneTimeSecret acts on it (gate-r13-8).
  if (copying > 0) wipeAfterCopy = true;
  if (!held && !siblingHeld) return Promise.resolve();
  if (writing) return writing;
  const seen = copies;
  const seenSiblings = siblingCopies;
  writing = (async () => {
    try {
      await navigator.clipboard.writeText("");
    } catch {
      // No focus or no gesture, or no clipboard API: try again when the document is looked at.
      arm();
      // The listeners die with this document, and logoutLocal and reloadForNewIdentity start a full load right after the wipe. Only hold() sets the
      // flag, so a tab that copied nothing and was refused a sibling's wipe would forget it, and the wipe would depend on the background tab that
      // copied being focused again (gate-r9-7). The flag is set while a copy is known, whoever made it, so the next page of this tab picks it up.
      // The state is read after the await: a "clear" that arrived meanwhile has already forgotten the copy, and then no flag is left behind.
      if (held || siblingHeld) setFlag(true);
      return;
    }
    // A copy that was made while this write was on its way, here or in another tab, is a newer secret that the write may have preceded.
    if (copies === seen && siblingCopies === seenSiblings) release();
  })().finally(() => {
    writing = null;
  });
  return writing;
}

/**
 * Copies a one-time secret. Rejects as navigator.clipboard.writeText does, so the caller can say that the copy failed; only a copy that
 * succeeded is remembered, so a failed one is not "wiped" over what the person had copied themselves.
 */
export async function copyOneTimeSecret(text: string): Promise<void> {
  install();
  copying += 1;
  let wiped = false;
  try {
    await navigator.clipboard.writeText(text);
    hold();
    wiped = wipeAfterCopy;
  } finally {
    copying -= 1;
    // With no copy left on its way a wish to wipe has nothing to wait for: a failed copy put nothing in the clipboard.
    if (copying === 0) wipeAfterCopy = false;
  }
  // A wipe that was already writing may have gone out before this copy landed, so the new one follows it.
  if (wiped) void (writing ?? Promise.resolve()).then(() => overwrite());
}

/** True while this tab has put a one-time secret in the clipboard and not yet overwritten it. A sibling's copy is not counted. */
export function holdsCopiedSecret(): boolean {
  return held;
}

/**
 * Overwrites what a copy of a one-time secret put there, if anything. Best effort and never rejects. The callers do not wait for it,
 * because they leave the page; a refusal is retried by the listeners above and, after a full load, by resumePendingWipe.
 */
export function wipeCopiedSecret(): Promise<void> {
  install();
  // Opens the channel, so that a tab that has never copied still hears the siblings that did.
  channel();
  return overwrite();
}

/**
 * Picks up a copy that the previous page of this tab left in the clipboard (the flag in sessionStorage) and tries to overwrite it at once,
 * then at the next sign of life. Runs when this module loads in a browser, so the login page and a reloaded page do it with no component.
 */
export function resumePendingWipe(): void {
  if (typeof window === "undefined") return;
  install();
  // Every page listens from the start: a sibling's "held" must be known before this tab is asked to wipe.
  channel();
  let pending = false;
  try {
    pending = sessionStorage.getItem(PENDING_KEY) === "1";
  } catch {
    // Blocked storage: there is no flag to resume.
  }
  if (!pending) return;
  held = true;
  arm();
  void overwrite();
}

resumePendingWipe();

/**
 * Copies text that is not a secret (a node's advertised address, a domain): it is not remembered and nothing wipes it later, because
 * the person copied it to paste it somewhere else. Rejects as navigator.clipboard.writeText does. It lives here because this file is the
 * one place that may touch the clipboard (ctrlz/no-storage).
 */
export async function copyPlainText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}
