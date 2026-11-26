import {queryOptions, useMutation, useQuery, useQueryClient, type QueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import {logoutAndLeave} from "../session.ts";

// The Account page's session list (spec 12.4) and Log out all.

export const sessionKeys = {list: ["account", "sessions"] as const};

export const sessionsQueryOptions = () =>
  queryOptions({
    queryKey: sessionKeys.list,
    queryFn: async ({signal}) => required(await api.GET("/account/sessions", {signal})).sessions,
  });

export function useSessions() {
  return useQuery(sessionsQueryOptions());
}

/** `DELETE /account/sessions/{id}`. A newer session needs a live reauth: `reauth_required` is the caller's to handle. */
export function useEndSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.DELETE("/account/sessions/{id}", {params: {path: {id}}});
    },
    onSuccess: () => queryClient.invalidateQueries({queryKey: sessionKeys.list}),
  });
}

/**
 * `POST /auth/logout-all`, then `logoutLocal()` and nothing else: the server has
 * already ended this session too, so a second logout call would only fail (spec 12.4).
 * `logoutLocal` stops what is in flight before it clears the cache, and marks the tab as
 * leaving, so the host component's re-render cannot start a `/me` that would end in a
 * second, different redirect.
 *
 * It runs through the same loop as Log out (`logoutAndLeave`), because `/auth/*` has no refresh
 * middleware and a dead session cookie under a live Remember me one answers 401 before the handler
 * runs: nothing would be ended, and the page would say "your session has ended" while every other
 * session and the 30-day refresh cookie lived on. The loop refreshes and asks again. The one
 * difference is a refused refresh: the server then clears this browser's cookies, but the other
 * sessions were not ended, so it fails with `logout_all_incomplete` instead of leaving as if it
 * had worked. Nothing local is cleared, and the next request finds the session gone as usual.
 */
export function logoutAllMutationOptions(queryClient: QueryClient, locale: string) {
  return {
    mutationFn: () =>
      logoutAndLeave(
        {queryClient, locale},
        {
          logout: () => api.POST("/auth/logout-all"),
          refresh: () => api.POST("/auth/refresh"),
          incompleteWhenRefreshRefused: "logout_all_incomplete",
        },
      ),
  };
}

export function useLogoutAll(locale: string) {
  const queryClient = useQueryClient();
  return useMutation(logoutAllMutationOptions(queryClient, locale));
}
