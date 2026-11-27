import {queryOptions, useQuery, useQueryClient, type QueryClient} from "@tanstack/react-query";
import {useCallback, useEffect, useRef} from "react";

import {holdSignedInSurface, refetchWhenPresent} from "../activity.ts";
import {api} from "../client.ts";
import {required} from "../core.ts";
import {shouldRetry} from "../queryDefaults.ts";
import {runSessionEnd} from "../sessionEnd.ts";
import {
  bindSession,
  deriveSession,
  guardRestoredPage,
  isOnLoginPath,
  isSessionEnding,
  logoutAndLeave,
  logoutLocal,
  parseSessionMessage,
  resetLocaleSync,
  sessionChannel,
  watchIdentity,
  type Me,
  type SessionState,
} from "../session.ts";

// Spec 14.4 and 14.5. `GET /me` is the one place the session is read: the proxy
// cannot tell whether a cookie is live, so `/me` decides.

export const meKeys = {all: ["me"] as const};

/** Who a Me is: the user and the tenant. Either changing means another account (spec 14.4). */
export const meIdentity = (me: Me) => `${me.user.id}|${me.tenant.id}`;

export const meQueryOptions = () =>
  queryOptions({
    queryKey: meKeys.all,
    queryFn: async ({signal}) => required(await api.GET("/me", {signal})),
    // Revocation should show: a tab that comes back to the front asks again. Only while a person is
    // there: the first input after a pause refetches it anyway (activity.ts), and a focus with nobody
    // at the page must not slide the idle limit.
    refetchOnWindowFocus: refetchWhenPresent,
    staleTime: 10_000,
    retry: shouldRetry,
    // Once this tab is leaving, a fresh query (the host of a mutation re-renders after `clear()`)
    // must not ask: the cookies are gone, so it would answer 401 and start a second, different leave.
    enabled: () => !isSessionEnding(),
  });

export function useMe() {
  return useQuery(meQueryOptions());
}

export type Session = SessionState & {
  error: unknown;
  /** Asks `/me` again, for the Retry of the `error` status. */
  retry: () => Promise<unknown>;
};

/** `{status, me}` of spec 14.4, plus the `error` status for a `/me` that failed without ending the session. */
export function useSession(): Session {
  const {data, error, isPending, refetch} = useQuery(meQueryOptions());
  const state = deriveSession({data, error, isPending});
  return {...state, error, retry: () => refetch()};
}

export type SessionBindingOptions = {
  locale: string;
  /** A validated path without locale, or none. Read when the session ends, not when this renders. */
  currentNext: () => string | undefined;
};

/**
 * The work of \`useSessionBinding\`, without React so that it can be tested: it tells the
 * client what "the session is over" does (a refused refresh clears the cache and loads the
 * login page, with \`next\`), and it obeys the other tabs on \`BroadcastChannel\`: \`logout\`
 * does the same here, without calling out again, and login refetches /me. A
 * /me that names another user or tenant than this tab had (that refetch, a focus, a browser with
 * no channel) clears the cache and reloads the page, since every other cached row is the previous
 * account's (watchIdentity). Returns what undoes it.
 */
export function startSessionBinding(
  queryClient: QueryClient,
  {locale, currentNext}: SessionBindingOptions,
  channel: Pick<BroadcastChannel, "addEventListener" | "removeEventListener"> | null = sessionChannel(),
): () => void {
  const unbind = bindSession({
    onEnded: () => {
      if (!isOnLoginPath()) logoutLocal({queryClient, locale}, {broadcast: false, next: currentNext()});
    },
  });

  const unwatch = watchIdentity<Me>(queryClient, meKeys.all, meIdentity);
  // Every gated page, not only one that is leaving (wp4-r5-7).
  guardRestoredPage();
  // Every signed-in page mounts this, so it is what the idle cover (activity.ts) looks for.
  const releaseSurface = holdSignedInSurface();

  const onMessage = (event: Event) => {
    const message = parseSessionMessage((event as MessageEvent).data);
    if (message === "login") {
      void queryClient.invalidateQueries({queryKey: meKeys.all});
    } else if (message === "logout" && !isOnLoginPath()) {
      logoutLocal({queryClient, locale}, {broadcast: false});
    }
  };
  channel?.addEventListener("message", onMessage);
  return () => {
    unbind();
    unwatch();
    releaseSurface();
    channel?.removeEventListener("message", onMessage);
  };
}

/**
 * What a visitor without a session must not carry onto the login pages (wp4-r14-1). A session can end
 * with no `logoutLocal` (the cookies expire and the proxy sends a soft navigation here), and this tab's
 * one QueryClient survives that: the previous account's /me, notifications, announcements, session and
 * passkey lists would still be in it when the next person signs in, and the new shell would show them
 * until its refetch lands. So everything nobody observes is dropped and what is still loading is
 * cancelled. A query the login page itself observes (public config) is kept: it holds no account data
 * and removing it under its observer would only make it ask again. The saved-language flag goes too
 * (wp4-r7-2): the same missing `logoutLocal` would otherwise leave it set, and the next sign-in would
 * never apply the saved language.
 */
export function resetLoginSession(queryClient: QueryClient): void {
  void queryClient.cancelQueries({type: "inactive"});
  queryClient.removeQueries({type: "inactive"});
  runSessionEnd();
  resetLocaleSync();
}

/**
 * Mounted once by the layout of the pages a visitor without a session sees (login, register, invite,
 * forgot password), on mount, so that no sign-in path can forget it. `signedIn` is for the pages of
 * that layout a signed-in user also lands on (change password, suspended): their /me is the live one
 * and must stay, so only the language flag is touched there.
 *
 * It also guards the page against a restore from the back/forward cache (gate-r1-19). These pages hold one-time
 * values in memory: the reset ticket of Forgot Password step 3 (a credential for five minutes), a typed password
 * behind a reveal toggle, an OTP challenge. Safari brings a page back with that state, so the next person on a
 * shared device who presses Back would find it. Every gated page already reloads on a restore; these pages did not.
 */
export function useLoginSessionReset({signedIn = false}: {signedIn?: boolean} = {}) {
  const queryClient = useQueryClient();
  // The page at mount decides. A visitor who goes on from login to change-password stays in the same
  // layout, and that must not clear the /me the page has just fetched.
  const signedInAtMount = useRef(signedIn);
  useEffect(() => {
    guardRestoredPage();
    if (signedInAtMount.current) resetLocaleSync();
    else resetLoginSession(queryClient);
  }, [queryClient]);
}

/** Mounted once by the shell (panel only: admin has no refresh and no channel, spec 13). */
export function useSessionBinding(options: SessionBindingOptions) {
  const queryClient = useQueryClient();
  const {locale} = options;
  const nextRef = useRef(options.currentNext);
  // Read when the session ends, so it is the latest one; written in an effect, not during render.
  useEffect(() => {
    nextRef.current = options.currentNext;
  });

  useEffect(() => startSessionBinding(queryClient, {locale, currentNext: () => nextRef.current()}), [queryClient, locale]);
}

/**
 * \`POST /auth/logout\`, then \`logoutLocal()\` (spec 14.4), by \`logoutAndLeave\`: a session that
 * is already gone still leaves, after the refresh cookie behind it has been ended too.
 */
export function useLogout(locale: string) {
  const queryClient = useQueryClient();
  return useCallback(
    () =>
      logoutAndLeave(
        {queryClient, locale},
        {logout: () => api.POST("/auth/logout"), refresh: () => api.POST("/auth/refresh")},
      ),
    [queryClient, locale],
  );
}
