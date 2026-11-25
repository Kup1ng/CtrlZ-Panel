import {hashKey, type QueryClient} from "@tanstack/react-query";

import {wipeCopiedSecret} from "./clipboard.ts";
import {ApiError, hasCode, type ErrorCode} from "./errors.ts";
import type {components} from "./generated/panel";

// Spec 14.4. Everything about the session that is not a hook: the cross-tab channel,
// what leaving the session does, and how `/me` is read as a status. Nothing here
// stores a token, a ticket or `Me`: cookies are HttpOnly, and memory is the only
// place the query cache lives (no persister).

export type Me = components["schemas"]["Me"];

export const SESSION_CHANNEL = "ctrlz-session";

export type SessionMessage = "logout" | "login";

const LOCALE_RE = /^[a-z]{2}$/;
const DEFAULT_LOCALE = "fa";
// The page itself, with the one trailing slash that Next redirects away. Same locale shape as LOCALE_RE.
const LOGIN_PATH = /^\/[a-z]{2}\/login\/?$/;

/** The query parameter that tells the login page the session ended on its own (spec 11.4): `?ended=1`. */
export const ENDED_PARAM = "ended";

export type LoginTarget = {
  /** A path without locale, already validated by the caller. */
  next?: string;
  /** The session ended by itself (idle, revoked), so the login page says so. */
  ended?: boolean;
};

/** `/<locale>/login`, with `next` and the `ended` marker when given. */
export function loginUrl(locale: string, {next, ended}: LoginTarget = {}): string {
  const prefix = `/${LOCALE_RE.test(locale) ? locale : DEFAULT_LOCALE}/login`;
  const query = new URLSearchParams();
  if (next) query.set("next", next);
  if (ended) query.set(ENDED_PARAM, "1");
  const text = query.toString();
  return text ? `${prefix}?${text}` : prefix;
}

let channel: BroadcastChannel | null | undefined;

/**
 * The one channel of this tab, for sending and for listening. A message is delivered
 * to every OTHER channel object of the same name, in this tab too, so a second object
 * for the listener would make a tab obey its own "logout" and navigate twice. One object
 * hears the other tabs only.
 */
export function sessionChannel(): BroadcastChannel | null {
  if (channel !== undefined) return channel;
  try {
    channel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(SESSION_CHANNEL);
    // Node (the unit tests) would otherwise wait for it; a browser has no such method.
    (channel as {unref?: () => void} | null)?.unref?.();
  } catch {
    channel = null;
  }
  return channel;
}

function post(message: SessionMessage) {
  try {
    sessionChannel()?.postMessage(message);
  } catch {
    // No channel (an old or locked-down browser): other tabs find out at their next request.
  }
}

/** Tells the other tabs that this one signed in, so they refetch `/me` (spec 14.4). */
export function broadcastLogin() {
  post("login");
}

export function parseSessionMessage(data: unknown): SessionMessage | undefined {
  return data === "logout" || data === "login" ? data : undefined;
}

// A flag, not data: `Me.user.locale` is applied once per tab session (spec 4.2).
const LOCALE_SYNCED = "ctrlz.localeSynced";

/** True the first time it is asked in this tab session, so the saved language is applied once (spec 4.2). */
export function takeLocaleSync(): boolean {
  try {
    if (sessionStorage.getItem(LOCALE_SYNCED) === "1") return false;
    sessionStorage.setItem(LOCALE_SYNCED, "1");
    return true;
  } catch {
    // No storage: skip the redirect rather than risk a loop.
    return false;
  }
}

/** A new login in this tab applies its user's language again. */
export function resetLocaleSync() {
  try {
    sessionStorage.removeItem(LOCALE_SYNCED);
  } catch {
    // Nothing was stored.
  }
}

/**
 * What every successful sign-in does before it navigates (password, OTP, TOTP, passkey, register,
 * invite): the saved language is applied once again in this tab, the other tabs refetch /me, and a secret that another tab copied is wiped.
 * One function, so no sign-in path has to remember the two calls (wp4-r7-2).
 */
export function completeSignIn() {
  resetLocaleSync();
  broadcastLogin();
  // Another tab may have copied a secret of the person who was signed in before (gate-r7-10). That tab is in the background and the browser
  // refuses its wipe; this one has the focus, so it writes, when a sibling has said that it holds a copy. A no-op when none did.
  void wipeCopiedSecret();
}

/**
 * True on the login page of any language, and only on the page itself. Automatic redirects to it (a refused refresh, a
 * message from another tab, the gate) skip it, so a login page can never bounce to itself.
 *
 * Not on a path below it: /<lang>/login/<anything> has no page of its own, it falls to the catch-all and, with a session cookie, renders the
 * signed-in shell with the 404 inside it. That page holds the previous account's cache, so every end of the session must act there, and
 * a prefix match would have made each of them skip it as "already on the login page" (gate-r20-6).
 */
export function isOnLoginPath(): boolean {
  // No window (a test in Node) or no location is "not on a login page": the callers ask this before they decide to leave.
  if (typeof window === "undefined") return false;
  return LOGIN_PATH.test(window.location?.pathname ?? "");
}

export type SessionContext = {queryClient: QueryClient; locale: string};

let leaving = false;
let pageShowTarget: object | undefined;

/**
 * A page that holds a live session, or has just ended one, is never shown again as it was restored
 * from the back/forward cache (`pageshow` with `persisted`). The cache brings a document back with the
 * DOM it had: the previous account's rows, which nothing re-renders, because the query cache that fed
 * them is empty (after a logout) or was never asked again (the session ended elsewhere while the
 * document sat in the cache). Safari does this even for no-store pages and does not evict on a cookie
 * change; Chrome mostly evicts, which hides the problem (wp4-r4-2, wp4-r5-7). So the restored page is
 * hidden and loaded again, and the proxy sends a visitor without cookies to the login page. The
 * presence gate cannot be the check: it reads the last input of a frozen document, which may be hours
 * old, and then sends no request at all.
 *
 * One listener per window, installed by every gated page (the panel binding, the admin guard) and by
 * `beginLeaving`, which covers a page that is not gated any more by the time it leaves.
 */
export function guardRestoredPage() {
  if (typeof window === "undefined" || pageShowTarget === window || typeof window.addEventListener !== "function") return;
  pageShowTarget = window;
  window.addEventListener("pageshow", (event) => {
    if (!(event as PageTransitionEvent).persisted) return;
    // The reload below is the page's own, like a logout's: the page is ending first, so a leave guard (useLeaveGuard, armed while recovery
    // codes are on screen) steps aside instead of answering it with a prompt. A person who pressed Stay would keep a live document with the
    // codes in it, in a window that someone else has just opened with Back (gate-r11-4).
    leaving = true;
    hideDocument(window.document);
    window.location.reload();
  });
}

/**
 * Takes the whole document out of the rendering until the reload replaces it. Not `visibility: hidden` on <html>: that is inherited, and any
 * descendant that says `visibility: visible` (the sidebar's labels and chips do) draws itself again, and can be clicked, on a page that is
 * meant to be gone. `display: none` leaves no box to draw, and `important` on the element's own style beats every stylesheet rule.
 */
export function hideDocument(doc: Pick<Document, "documentElement"> | undefined) {
  try {
    const style = doc?.documentElement.style;
    style?.setProperty("display", "none", "important");
    style?.setProperty("visibility", "hidden", "important");
  } catch {
    // No document to hide (a test double): the reload is the part that matters.
  }
}

function beginLeaving() {
  // No timer: a full load of the login page can take longer than any fixed wait, and once the flag
  // dropped, a focus or a re-render would ask /me into the empty cache and start a second,
  // different redirect. The flag lasts until the page unloads and has no reset: a restored page is
  // reloaded (guardRestoredPage), so nothing may start meanwhile.
  leaving = true;
  guardRestoredPage();
  // Every way the session ends passes here, and the page that was open keeps whatever it painted until the next document commits: recovery
  // codes or a TOTP secret in a wizard step, which are state in a component and which nothing re-renders after queryClient.clear(). On a slow
  // link that is seconds, and for good when the person stops the load. The browser also captures the outgoing page as it is (the swipe-back
  // preview of Chrome on Android and Safari on iOS, Safari's bfcache), and hideDocument on pageshow is too late for that. So the page is taken
  // out of the rendering here, before the navigation starts (gate-r13-10). A blank page that stays after a stopped load is the safe outcome.
  hideDocument(typeof window === "undefined" ? undefined : window.document);
}

/** Only for tests between cases: a real page never goes back to "not leaving" (see beginLeaving). */
export function clearLeaving() {
  leaving = false;
}

export type LogoutOptions = {
  /**
   * Tell the other tabs to leave too. Off unless it says `true`: a "logout" message takes every live tab
   * down, so only a logout the server answered may post it, and that is `logoutAndLeave` alone
   * (wp4-r16-2). A caller that forgets the option fails closed. Admin has no channel (spec 13).
   */
  broadcast?: boolean;
  next?: string;
  /** The login page shows its "session ended" notice (spec 11.4). */
  ended?: boolean;
};

/**
 * Spec 14.4: stop what is in flight, clear the query cache, tell the other tabs, then a
 * full load of the login page, which wipes memory. Used after \`POST /auth/logout\` and
 * alone after "Log out all". Nothing is broadcast unless `broadcast: true` is passed. The cancel comes first: once the cache is empty there is
 * nothing left to cancel, and a \`/me\` that was already on its way would land in the new one.
 */
export function logoutLocal({queryClient, locale}: SessionContext, options: LogoutOptions = {}) {
  // A secret that the person copied on the way is not left for the next one at this PC (gate-r5-8).
  void wipeCopiedSecret();
  void queryClient.cancelQueries();
  queryClient.clear();
  resetLocaleSync();
  beginLeaving();
  if (options.broadcast === true) post("logout");
  window.location.assign(loginUrl(locale, {next: options.next, ended: options.ended}));
}

/**
 * The signed-in identity of this tab changed under it (another tab signed in as someone else:
 * the cookies are shared by every tab). Every cached row belongs to the previous identity, and
 * the tab has no way to tell which, so nothing is kept: cancel, clear, and a full load of the
 * page that is open, which starts the new identity from an empty memory. No broadcast: the tab
 * that signed in is the other one, and the rest learn it the same way this one did.
 */
export function reloadForNewIdentity({queryClient}: Pick<SessionContext, "queryClient">) {
  if (leaving) return;
  void wipeCopiedSecret();
  void queryClient.cancelQueries();
  queryClient.clear();
  // The new user's saved language is applied once, again.
  resetLocaleSync();
  beginLeaving();
  window.location.reload();
}

/**
 * Spec 14.4. Watches one "who am I" query (/me) and reloads the tab when an answer names a
 * different identity from the one this tab already had. It is the one rule behind every way
 * the identity can change here: a login message, a focus refetch, a poll, a browser with no
 * BroadcastChannel. The first answer only records the identity. Returns what stops it.
 */
export function watchIdentity<T>(
  queryClient: QueryClient,
  key: readonly unknown[],
  identityOf: (data: T) => string,
): () => void {
  const wanted = hashKey(key);
  const cached = queryClient.getQueryData<T>(key);
  let known = cached === undefined ? undefined : identityOf(cached);
  return queryClient.getQueryCache().subscribe((event) => {
    if (event.type !== "updated" || event.action.type !== "success" || hashKey(event.query.queryKey) !== wanted) return;
    const data = event.query.state.data as T | undefined;
    if (data === undefined) return;
    const now = identityOf(data);
    if (known === undefined) known = now;
    else if (now !== known) reloadForNewIdentity({queryClient});
  });
}

export type LogoutCalls = {
  logout: () => Promise<unknown>;
  /** Panel only. Admin has no refresh cookie, so its logout never needs it. */
  refresh?: () => Promise<unknown>;
  /**
   * What a refused refresh (401) means. Absent: the server has just cleared both cookies, and ending
   * this browser's login was all the call was for, so the tab leaves. For a call that ends MORE than
   * this browser (Log out all), leaving would claim a success that did not happen: its code goes here,
   * and the call fails with it, nothing cleared.
   */
  incompleteWhenRefreshRefused?: ErrorCode;
};

/** How many times a refresh that brought a live session back may be followed by a logout that still met a dead one. */
const LOGOUT_REFRESH_ROUNDS = 2;

/**
 * POST /auth/logout or POST /auth/logout-all (the call is `calls.logout`), then logoutLocal(). Any failure but a dead session is thrown and
 * nothing is cleared, since a logout that did not reach the server must not look like one.
 *
 * A dead SESSION cookie is not a dead login: the 30-day refresh cookie of Remember me can
 * outlive it, and the server answers that 401 without clearing anything (the gate refuses
 * before the handler runs). Leaving then would hand the account to the next visitor, whose
 * first request refreshes it back. So the client does what the next visitor would do:
 * refresh, which either answers 401 and clears both cookies, or answers 204 and gives a
 * live session that the next logout can end.
 *
 * A 204 can also be the concurrent-tab grace of AUTH 3.4, with no Set-Cookie: the new session
 * cookie is another tab's to receive, so the logout that follows can still carry the dead one
 * and answer session_expired again although a refresh cookie is alive. That is not "the session
 * has ended", so refresh and logout are tried once more; if the logout still does not end,
 * the error says it did not finish ("unknown", try again) and nothing is cleared.
 */
export async function logoutAndLeave(context: SessionContext, calls: LogoutCalls, options: LogoutOptions = {}) {
  for (let round = 0; ; round++) {
    try {
      await calls.logout();
      break;
    } catch (error) {
      if (!hasCode(error, "session_expired")) throw error;
      // Admin has no refresh cookie behind a dead session.
      if (!calls.refresh) break;
      if (round === LOGOUT_REFRESH_ROUNDS) throw new ApiError(401, "unknown");
      try {
        await calls.refresh();
      } catch (refreshError) {
        // 401: the server has just cleared both cookies, so there is nothing left to end.
        if (!hasCode(refreshError, "session_expired")) throw refreshError;
        if (calls.incompleteWhenRefreshRefused) throw new ApiError(401, calls.incompleteWhenRefreshRefused);
        break;
      }
    }
  }
  // The server answered a logout, so this is the one leave that tells the other tabs. Admin passes false.
  logoutLocal(context, {...options, broadcast: options.broadcast ?? true});
}

type Binding = {
  /** Runs when the session is over: the refresh answered 401 (spec 14.4). It clears and leaves. */
  onEnded: () => void;
};

let binding: Binding | undefined;

/** The shell registers what a refused refresh does. Returns the function that removes it. */
export function bindSession(next: Binding): () => void {
  binding = next;
  return () => {
    if (binding === next) binding = undefined;
  };
}

/**
 * Called by the refresh middleware when \`/auth/refresh\` answers 401. One
 * navigation, however many requests were waiting. Without a binding (a login page)
 * nothing leaves: the caller still gets \`session_expired\`.
 */
export function handleSessionEnded() {
  if (leaving || !binding) return;
  // The decision "this page will not leave" comes before anything that cannot be undone. beginLeaving() hides the document and sets a flag
  // with no reset, so on a login page that the router has just committed (the binding of the page that was left is not unbound yet) a
  // late refused refresh would leave the login page blank for good, with /me disabled (gate-r17-4). The admin guard asks first, too.
  if (isOnLoginPath()) return;
  beginLeaving();
  post("logout");
  binding.onEnded();
}

export type SessionStatus = "loading" | "ready" | "restricted" | "suspended" | "anonymous" | "error";

export type SessionState = {status: SessionStatus; me: Me | undefined};

type QueryLike = {data: Me | undefined; error: unknown; isPending: boolean};

/**
 * Reads the `/me` query as a status. `Me` that is already known stays authoritative
 * when a refetch fails: a 503 or a dropped connection is not a logout. Only
 * `session_expired` (after the client's one refresh) and a tenant being deleted end the session.
 * `suspended` comes before `restricted`: a suspended tenant can reach nothing else.
 */
export function deriveSession({data, error, isPending}: QueryLike): SessionState {
  if (hasCode(error, "session_expired")) return {status: "anonymous", me: undefined};
  if (data) {
    if (data.tenant.status === "deleting") return {status: "anonymous", me: undefined};
    if (data.tenant.status === "suspended") return {status: "suspended", me: data};
    if (data.user.must_reset) return {status: "restricted", me: data};
    return {status: "ready", me: data};
  }
  if (error) return {status: "error", me: undefined};
  return {status: isPending ? "loading" : "error", me: undefined};
}

/**
 * True from the moment this tab started leaving the session (a refused refresh, a
 * message from another tab, an explicit logout) until the page unloads. Everything that
 * could start a second navigation or a request into the cleared cache looks at it: the
 * gate, the binding, and `/me`, whose fresh query would otherwise answer 401, ask for a
 * refresh, and replace a plain login redirect with one that carries `next`.
 */
export function isSessionEnding(): boolean {
  return leaving;
}
