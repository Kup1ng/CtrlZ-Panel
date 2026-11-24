import type {QueryClient} from "@tanstack/react-query";

// Spec 8.5 and 14.4. The bell polls every 60 s, and the API slides the idle limit of the session on
// every authenticated request (AUTH 3.3). A tab that is visible but unattended would therefore keep
// the session alive for as long as the screen stays on, and the idle limit would never fire. So the
// poll runs only while someone is at the page: it stops after IDLE_PAUSE_MS without input, and the
// next input takes it up again with one refetch. Half an hour is well under the shortest idle limit
// that has a poll behind it (2 h, a session without Remember me).
//
// The interval is not the only automatic refetch. TanStack also refetches stale queries when the
// network comes back ("online") and when the window gets focus, and a flaky Wi-Fi link does the first
// every few minutes with nobody there, sliding the idle limit just the same. So ONE gate,
// `refetchWhenPresent`, is the answer to all three, and it is set as the default of every panel
// query (queryDefaults.ts): a query added later is covered without anyone remembering to ask. What the
// gate skips is not lost: the first input after a pause refetches every active query.

//
// The window belongs to the app and must stay under that app's own idle limit, or the gate itself
// keeps the session alive: the panel idles out after 2 h (AUTH 3.3), the admin console after 15 min
// (R44), and for as long as the gate is open an "online" event refetches /me and slides that limit.
// 30 min is far under 2 h but twice the admin's 15, so the admin gets 5 (wp4-r4-3).
export const IDLE_PAUSE_MS = 30 * 60_000;
export const ADMIN_IDLE_PAUSE_MS = 5 * 60_000;

// The session's own idle limits (AUTH 3.3): 2 h for a panel session (the shortest, without Remember me)
// and 15 min for the admin console (R44). After that long with no input, the page stops showing the
// account (see "The idle cover" below).
export const SESSION_IDLE_MS = 2 * 60 * 60_000;
export const ADMIN_SESSION_IDLE_MS = 15 * 60_000;

export type PresenceApp = "panel" | "admin";

/** How long with no input before the page is covered, per app: the session's idle limit. */
export const sessionIdleMs = (app: PresenceApp): number => (app === "admin" ? ADMIN_SESSION_IDLE_MS : SESSION_IDLE_MS);

/** How long after the last input a person still counts as being at the page, per app. */
export const idlePauseMs = (app: PresenceApp): number => (app === "admin" ? ADMIN_IDLE_PAUSE_MS : IDLE_PAUSE_MS);

// One app per page (the panel and the admin console are different hosts), so one module value.
let pauseMs = IDLE_PAUSE_MS;

// Input that means a person is there. Movement is included: reading with a mouse is not typing.
// `click` and `input` are here for the people who never produce the others: a screen-reader "activate"
// on a phone (TalkBack, VoiceOver) arrives as a synthetic `click` with no pointer, key or touch event
// before it, and a switch or voice control does the same (wp4-r7-1). The listener is a capturing one on
// the window, so it hears events that do not bubble too.
//
// `scroll` is NOT here (wp4-r8-3, r8-1). A scroll container fires a trusted `scroll` whenever layout
// clamps or anchors its position (a banner above it goes away, a row above it changes height, an image
// loads), with nobody at the page, so counting it let a Wi-Fi drop or a poll answer reopen presence and
// slide the session. A reader who only scrolls is not lost: the cover has a Continue button, and a
// click, a key or a touch counts at once.
export const INPUT_EVENTS = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart", "focus", "click", "input"] as const;

/**
 * Whether an event is a person. The browser makes events of its own that look like input, and one
 * that counted would reopen presence with nobody there (the class behind wp4-r8-1 and r8-3):
 *  - a script's `dispatchEvent` is `isTrusted === false`;
 *  - `focus` counts only as the window's own focus (the person came back to the tab). An element's
 *    focus is a page that moved its own focus after a refetch or opened a dialog; a person who moves
 *    focus did it with a key, a click or a touch, which count on their own;
 *  - a `pointermove` counts only when the pointer is somewhere else than at the last one. Chrome
 *    repeats the last move after a layout change under a still cursor.
 */
function isPersonInput(event: Event, target: unknown, lastPointer: {x?: number; y?: number}): boolean {
  if (event.isTrusted === false) return false;
  if (event.type === "focus") return event.target === target;
  if (event.type === "pointermove") {
    const {clientX: x, clientY: y} = event as PointerEvent;
    if (typeof x !== "number" || typeof y !== "number") return true;
    const moved = x !== lastPointer.x || y !== lastPointer.y;
    lastPointer.x = x;
    lastPointer.y = y;
    return moved;
  }
  return true;
}

// The page loading counts as input.
let lastInput = Date.now();

/** True while the last input is younger than the app's window (IDLE_PAUSE_MS for the panel). */
export function isUserPresent(now = Date.now()): boolean {
  return now - lastInput < pauseMs;
}

/**
 * `refetchOnReconnect` and `refetchOnWindowFocus` of a query: refetch only while a person is at the page.
 * TanStack then still applies its own staleness rule on top.
 */
export const refetchWhenPresent = (): boolean => isUserPresent();

/**
 * `refetchInterval` of a polling query. TanStack asks again after every fetch, so a pause starts
 * at most one interval late, and `false` stops the timer until the resume refetch below.
 */
export function pollEvery(ms: number): () => number | false {
  return () => (isUserPresent() ? ms : false);
}

// The idle cover (wp4-r6-3). Pausing the requests keeps the session from being slid, which is right, but
// it also means nothing ever sees the 401 of a session that idled out on the server, so an unattended
// tab keeps the account on screen for anyone who walks up to it (the user list of the admin console
// with phone numbers, a one-time password or a TOTP secret, the session list with IPs). So when the
// app's own session idle limit passes with no input, the page is covered: AppProviders unmounts
// everything below it, which takes the open dialogs with it, and the cache is cleared. That sends no
// request, so it cannot slide the limit. The page comes back only when someone asks for it: the cover's
// Continue button calls uncoverPage, and the page remounts, so the gate's `/me` decides: a live session
// shows the page again (a Remember me session recovers through the refresh), a dead one leaves for the
// login page: the panel through logoutLocal with `next` and no ended marker (its login page does not read one),
// the admin through leaveEndedAdminSession, which adds `?ended=1` (gate-r8-10). Input does NOT uncover (wp4-r7-1). A mouse sensor that jitters, a desk that is
// knocked or an alt-tab would otherwise bring the account back and, through that /me, slide the idle
// limit, so a passer-by's nudge could renew a session the owner had left. It also gives a keyboard or
// screen-reader user something to activate, which "move the mouse" did not.
//
// Only a signed-in surface is covered: a login form that has waited 15 minutes for a code is not an
// account on screen, and wiping it would cost the person what they typed. A surface announces itself
// with holdSignedInSurface (the session binding and the admin guard, which every signed-in page mounts).

export type IdleState = {
  /** Show the cover instead of the page. */
  covered: boolean;
  /**
   * This cover is ending the session, so there is nothing to continue. False when another tab of the
   * same browser has had input within the limit (see SharedPresence): the page is hidden here, but the
   * session is alive and Continue brings it back.
   */
  ending: boolean;
  /** Changes at every cover, so a page that comes back after one is a fresh mount even when the cover and the input meet in one step. */
  epoch: number;
};

let idleState: IdleState = {covered: false, ending: true, epoch: 0};
const idleListeners = new Set<() => void>();

function setIdleState(next: IdleState) {
  idleState = next;
  idleListeners.forEach((l) => l());
}

/** For useSyncExternalStore: the snapshot is replaced on every change, never mutated. */
export const getIdleState = (): IdleState => idleState;

export function subscribeIdleState(listener: () => void): () => void {
  idleListeners.add(listener);
  return () => void idleListeners.delete(listener);
}

/** What a surface learns when the page is covered. */
export type CoverInfo = {
  /** Another tab of this browser has had input within the limit, so the shared session is still in use. */
  sessionLive: boolean;
};

type Surface = {onCover?: (info: CoverInfo) => void};
const signedInSurfaces = new Set<Surface>();

/**
 * A signed-in page is mounted. Returns the release. Each call is its own entry, so overlapping mounts
 * (StrictMode, a route change) are safe. `onCover` runs after the page has been covered: the admin
 * guard ends the session there (wp4-r8-4), because the cover alone hides the page but leaves a live
 * session behind it, unless another tab is still using that session (`sessionLive`, wp4-r9-3).
 */
export function holdSignedInSurface(onCover?: (info: CoverInfo) => void): () => void {
  const surface: Surface = {onCover};
  signedInSurfaces.add(surface);
  return () => void signedInSurfaces.delete(surface);
}

// Presence across the tabs of one browser (wp4-r9-3). `lastInput` is the state of one document, but the
// admin session it guards is one cookie that every admin tab shares, and the server slides its idle limit
// on the requests of whichever tab is in use. A background tab gets no input, so by its own clock alone
// it would end the session (the admin cover logs out, wp4-r8-4) while the admin works in another tab.
// So the admin writes a non-secret timestamp of its last input to localStorage, and a tab that is
// covered by its own clock ends the session only when the newest timestamp of every tab is also past
// the limit. Without usable storage nothing is shared and the tab ends the session, which fails closed.
export type SharedPresence = {
  /** The newest input of any tab, in ms since the epoch, or undefined when nothing usable is stored. */
  read: () => number | undefined;
  write: (ms: number) => void;
};

/** How often one tab writes its input to the shared store: a pointer move must not cost a storage write. */
export const SHARED_WRITE_MS = 10_000;

/** A stored time this far ahead of now is a clock that was corrected; further than that it is stale. */
export const SHARED_FUTURE_SLACK_MS = 60_000;

export const ADMIN_PRESENCE_KEY = "ctrlz.admin.lastInput";

/** localStorage under `key`. Every access is guarded: storage is missing or throws in private windows and with blocked site data. */
export function browserPresence(key: string): SharedPresence {
  return {
    read() {
      try {
        const value = Number(window.localStorage.getItem(key));
        return Number.isFinite(value) && value > 0 ? value : undefined;
      } catch {
        return undefined;
      }
    },
    write(ms) {
      try {
        window.localStorage.setItem(key, String(ms));
      } catch {
        // No storage: this tab stands alone, and ends the session by its own clock.
      }
    },
  };
}

// Set by the one watchActivity that is running.
let uncover: (() => void) | undefined;

/**
 * Records input, and on the first one after a pause refetches every active query: the interval of the
 * polling ones starts again, and whatever a reconnect or a focus skipped while nobody was there is
 * fetched now. Mounted once by AppProviders, with the window of its app. Returns what removes it.
 */
export function watchActivity(
  queryClient: QueryClient,
  target: Pick<EventTarget, "addEventListener" | "removeEventListener">,
  {idleMs = IDLE_PAUSE_MS, coverMs = SESSION_IDLE_MS, shared}: {idleMs?: number; coverMs?: number; shared?: SharedPresence} = {},
): () => void {
  pauseMs = idleMs;
  lastInput = Date.now();

  // The shared store is written on a person's input at a signed-in surface and on Continue, never when
  // the page mounts and never from a login form: a page load is not a person at an account, and the
  // login page, the page a cover leaves for and a browser's reload of an error page would otherwise
  // count as presence for every other tab (wp4-r10-4).
  let lastShared = 0;
  const share = (now: number, force = false) => {
    // `force` is Continue: the button exists only on a page that was covered, which needs a signed-in
    // surface, and that surface is unmounted while the cover shows, so counting them would skip the write
    // (wp4-r11-4).
    if (!shared || (!force && (signedInSurfaces.size === 0 || now - lastShared < SHARED_WRITE_MS))) return;
    lastShared = now;
    shared.write(now);
  };

  /**
   * How long the newest input of any tab keeps the shared session in use: more than 0 means another
   * tab is being used. A stored time further in the future than a clock correction explains is stale,
   * not "now": the clock moved back, and counting it would keep the session alive without limit.
   */
  const sharedLeft = (): number => {
    const at = shared?.read();
    const now = Date.now();
    if (at === undefined || at > now + SHARED_FUTURE_SLACK_MS) return 0;
    return coverMs - (now - Math.min(at, now));
  };

  // A tab covered while another tab was in use ends nothing at once, but it must not wait for that
  // other tab to do it: the other tab can be closed, navigated away or discarded before its own cover
  // fires, and then nobody would end the session at the limit, while this tab's Continue would still
  // revive it (wp4-r10-1, r10-4). So it looks at the shared time again when the limit measured from it
  // runs out, and ends the session if no tab has had input since.
  let recheckTimer: ReturnType<typeof setTimeout> | undefined;
  // The surfaces that were held when the page was covered. The cover unmounts the page, and with it the
  // gate whose cleanup releases its surface, so by the time the recheck fires `signedInSurfaces` is empty
  // and looping over it would end nothing: no logout, no leave, a status line that never moves, and an F5
  // that revives the session (wp4-r11-4). The handlers are closures that need no mounted page.
  let coverHandlers: Surface[] = [];
  const recheck = () => {
    recheckTimer = undefined;
    if (!idleState.covered || idleState.ending) return;
    const left = sharedLeft();
    if (left > 0) {
      recheckTimer = setTimeout(recheck, left);
      return;
    }
    setIdleState({...idleState, ending: true});
    const handlers = coverHandlers;
    coverHandlers = [];
    for (const surface of handlers) surface.onCover?.({sessionLive: false});
  };

  const cover = () => {
    const left = sharedLeft();
    const sessionLive = left > 0;
    void queryClient.cancelQueries();
    queryClient.clear();
    setIdleState({covered: true, ending: !sessionLive, epoch: idleState.epoch + 1});
    clearTimeout(recheckTimer);
    recheckTimer = sessionLive ? setTimeout(recheck, left) : undefined;
    // Kept only while a recheck is still to come: a cover that ends the session has nothing left to run.
    const handlers = [...signedInSurfaces];
    coverHandlers = sessionLive ? handlers : [];
    for (const surface of handlers) surface.onCover?.({sessionLive});
  };

  // One timer for the page, not one per input: when it fires it looks at the clock and re-arms for
  // what is left, so a stream of pointer moves costs nothing.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const arm = (delay: number) => {
    clearTimeout(timer);
    timer = setTimeout(check, delay);
  };
  function check() {
    if (idleState.covered) return;
    const left = coverMs - (Date.now() - lastInput);
    if (left > 0) return arm(left);
    if (signedInSurfaces.size > 0) cover();
    else arm(coverMs);
  }
  arm(coverMs);

  const lastPointer: {x?: number; y?: number} = {};
  const onInput = (event: Event) => {
    if (!isPersonInput(event, target, lastPointer)) return;
    // A covered page ignores input: only uncoverPage brings it back, and an input that does not count
    // must not move the clock either (wp4-r7-1).
    if (idleState.covered) return;
    const now = Date.now();
    const wasPaused = !isUserPresent(now);
    // A sleeping laptop or a throttled background tab fires the timer late, and the first sign of
    // life can be this very input: the limit has passed, so the page is covered (cleared and
    // unmounted) and the input does not count.
    if (now - lastInput >= coverMs && signedInSurfaces.size > 0) return cover();
    lastInput = now;
    share(now);
    if (wasPaused) void queryClient.invalidateQueries();
  };
  // The Continue button of the cover: the page comes back as a fresh mount, and the limit starts again.
  uncover = () => {
    if (!idleState.covered) return;
    clearTimeout(recheckTimer);
    recheckTimer = undefined;
    coverHandlers = [];
    lastInput = Date.now();
    share(lastInput, true);
    setIdleState({...idleState, covered: false, ending: true});
    arm(coverMs);
  };
  for (const name of INPUT_EVENTS) target.addEventListener(name, onInput, {passive: true, capture: true});
  return () => {
    for (const name of INPUT_EVENTS) target.removeEventListener(name, onInput, {capture: true});
    clearTimeout(timer);
    clearTimeout(recheckTimer);
    coverHandlers = [];
    uncover = undefined;
    pauseMs = IDLE_PAUSE_MS;
    if (idleState.covered || idleState.epoch !== 0) setIdleState({covered: false, ending: true, epoch: 0});
  };
}

/** What the cover's Continue button calls. Does nothing when the page is not covered. */
export function uncoverPage(): void {
  uncover?.();
}
