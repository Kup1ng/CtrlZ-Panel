import {holdSignedInSurface, refetchWhenPresent, type CoverInfo} from "../activity.ts";
import {queryOptions, useQuery, useQueryClient, type QueryClient} from "@tanstack/react-query";
import {useCallback, useEffect, useRef} from "react";

import {required} from "../core.ts";
import {hasCode} from "../errors.ts";
import type {components} from "../generated/admin";
import {shouldRetry} from "../queryDefaults.ts";
import {guardRestoredPage, isOnLoginPath, isSessionEnding, logoutAndLeave, logoutLocal, watchIdentity, type SessionContext} from "../session.ts";
import {adminApi} from "./client.ts";
import {recordServerClock} from "./clockSkew.ts";

// Spec 11 and 14.2. The admin session. It has no refresh and no cross-tab
// channel (spec 13): idle is 15 minutes (AUTH 3.3), and on 401 the app goes to
// /login?ended=1, where the login page shows its "session ended" notice (11.4).
// The page hooks of the admin app (users, invites, sms, settings, audit, alerts)
// are WP10's and live in `admin/hooks/`.

export type AdminMe = components["schemas"]["AdminMe"];

export const adminMeKeys = {all: ["admin", "me"] as const};

// `api` is a seam for the clock test, which gives it a client over a fake server; the app uses the admin client.
export const adminMeQueryOptions = (api: Pick<typeof adminApi, "GET"> = adminApi) =>
  queryOptions({
    queryKey: adminMeKeys.all,
    queryFn: async ({client, signal}) => {
      const sentAt = Date.now();
      const result = await api.GET("/me", {signal});
      // The `Date` of every /me answer is compared with the browser clock (spec 7.10, T-088), not only the first.
      recordServerClock(client, result.response, sentAt, Date.now());
      return required(result);
    },
    // Only while a person is there (activity.ts), like the panel's /me.
    refetchOnWindowFocus: refetchWhenPresent,
    staleTime: 10_000,
    retry: shouldRetry,
    enabled: () => !isSessionEnding(),
  });

export type AdminGuardOptions = {
  locale: string;
  /** The page the admin was on, read when the session ends so it is the latest one. */
  currentNext: () => string | undefined;
};

/**
 * Another admin signing in from another tab changes the shared cookie under this one. A /me
 * that names a different admin clears the cache and reloads (watchIdentity), as the panel does.
 * No channel is needed (spec 13): the next focus refetch finds it.
 *
 * Mounted by AdminGate and by SessionBinding (a signed-in page outside the shell). See startAdminGuard.
 */
export function useAdminIdentityGuard(options: AdminGuardOptions) {
  const queryClient = useQueryClient();
  const {locale} = options;
  const nextRef = useRef(options.currentNext);
  // Written in an effect, not during render, as useSessionBinding does.
  useEffect(() => {
    nextRef.current = options.currentNext;
  });
  useEffect(() => startAdminGuard(queryClient, {locale, currentNext: () => nextRef.current()}), [queryClient, locale]);
}

/**
 * The work of `useAdminIdentityGuard`, without React so it can be tested. Returns what stops it.
 *
 * Three things bind an admin page to the session, whether or not SessionGate is mounted (/setup is
 * outside it, and shows a one-time password, the TOTP secret and the recovery codes):
 *  - a restored back/forward-cache page is reloaded (wp4-r5-7),
 *  - a /me that names another admin clears the cache and reloads (watchIdentity), and
 *  - an admin call that answers 401 `session_expired` leaves for /login?ended=1 (wp4-r6-4). Admin has
 *    no refresh (spec 13), so unlike the panel there is nothing to try first, and no middleware to hang
 *    it on: the one place every admin query and mutation passes is the cache, so it listens there.
 */
export function startAdminGuard(queryClient: QueryClient, {locale, currentNext}: AdminGuardOptions): () => void {
  guardRestoredPage();
  // The idle cover hides the page but leaves the session alive, and a Continue press or a reload would
  // bring a live admin session back and renew it. Admin has no Remember me and no refresh (spec 13) and
  // R44 ends the session at 15 minutes idle, so the client ends it itself at the moment it covers the
  // page: failing closed at exactly the policy limit (wp4-r8-4).
  // Not when another admin tab is still being used: the cookie is shared by every tab and the server slides
  // its idle limit on that tab's requests, so ending it here would log the admin out of the page they are
  // working in (wp4-r9-3). This tab is covered all the same, and Continue brings it back.
  const releaseSurface = holdSignedInSurface((info) => endAdminSessionOnCover({queryClient, locale}, currentNext(), info));
  const unwatch = watchIdentity<AdminMe>(queryClient, adminMeKeys.all, (me) => me.username);

  const onError = (error: unknown) => {
    if (!hasCode(error, "session_expired") || isOnLoginPath() || isSessionEnding()) return;
    leaveUnauthorizedAdminSession({queryClient, locale}, currentNext());
  };
  const onEvent = (event: {type: string; action?: {type: string; error?: unknown}}) => {
    if (event.type !== "updated" || !event.action) return;
    if (event.action.type === "success") seenSession.add(queryClient);
    else if (event.action.type === "error") onError(event.action.error);
  };
  const offQueries = queryClient.getQueryCache().subscribe(onEvent);
  const offMutations = queryClient.getMutationCache().subscribe(onEvent);

  return () => {
    offQueries();
    offMutations();
    unwatch();
    releaseSurface();
  };
}

/**
 * What the admin idle cover does: `POST /auth/logout` with `keepalive` (the request outlives the
 * page, which is about to be replaced), and a full load of /login?ended=1 whatever the answer. A
 * failed logout (offline) still leaves: the tab never offers a way back into the console, and the
 * server's own idle limit has all but run out. When another tab has had input within the limit
 * (`info.sessionLive`) nothing is sent and nothing is left: the session is in use there.
 */
export function endAdminSessionOnCover(context: SessionContext, next: string | undefined, info: CoverInfo = {sessionLive: false}) {
  if (info.sessionLive || isOnLoginPath() || isSessionEnding()) return;
  void Promise.resolve(adminApi.POST("/auth/logout", {keepalive: true})).catch(() => undefined);
  leaveEndedAdminSession(context, next);
}

export type AdminSessionStatus = "loading" | "ready" | "setup" | "anonymous" | "error";

export type AdminSessionState = {status: AdminSessionStatus; me: AdminMe | undefined};

/**
 * `setup` is a first admin with a one-time password or no authenticator yet: the
 * shell does not render and `/setup` does (spec 11.2, T-323). Only `session_expired` ends the session.
 */
export function deriveAdminSession(q: {data: AdminMe | undefined; error: unknown; isPending: boolean}): AdminSessionState {
  if (hasCode(q.error, "session_expired")) return {status: "anonymous", me: undefined};
  if (q.data) {
    return {status: q.data.must_change_password || !q.data.totp_enrolled ? "setup" : "ready", me: q.data};
  }
  if (q.error) return {status: "error", me: undefined};
  return {status: q.isPending ? "loading" : "error", me: undefined};
}

export function useAdminSession(): AdminSessionState & {error: unknown; retry: () => Promise<unknown>} {
  const {data, error, isPending, refetch} = useQuery(adminMeQueryOptions());
  return {...deriveAdminSession({data, error, isPending}), error, retry: () => refetch()};
}

/**
 * `POST /auth/logout`, then the local part. A session that is already gone still leaves.
 * Admin has no refresh cookie, so there is nothing behind a dead session to end, and no
 * channel (spec 13): other admin tabs find out when `/me` is next refetched.
 */
export function useAdminLogout(locale: string) {
  const queryClient = useQueryClient();
  return useCallback(
    () => logoutAndLeave({queryClient, locale}, {logout: () => adminApi.POST("/auth/logout")}, {broadcast: false}),
    [queryClient, locale],
  );
}

/**
 * `/me` answered 401: the admin session ended by itself (idle 15 minutes, or revoked). Leave
 * for the login page with the marker its "session ended" notice reads (`?ended=1`, spec 11.4).
 * No broadcast: admin has no channel (spec 13).
 */
export function leaveEndedAdminSession(context: SessionContext, next: string | undefined) {
  logoutLocal(context, {broadcast: false, ended: true, next});
}

// Clients in which an admin call has succeeded: the page has had a live session of its own.
const seenSession = new WeakSet<QueryClient>();

/**
 * A 401 `session_expired` that came from a call of the page (the guard's cache watch, the shell's gate). The login page's "session ended"
 * notice is true only for a page that had a session: the first answer of a page load that is already a 401 means no cookie came, or none that
 * the server knows, as for a link from another site (the admin cookie is Strict, so such a navigation carries none, and the proxy serves the
 * page for it, spec 15.4) and for a browser that never signed in. That arrival leaves with `next` and without the marker (gate-r33-11).
 */
export function leaveUnauthorizedAdminSession(context: SessionContext, next: string | undefined) {
  logoutLocal(context, {broadcast: false, ended: seenSession.has(context.queryClient), next});
}
