import {QueryClient} from "@tanstack/react-query";

import {refetchWhenPresent} from "./activity.ts";
import {isApiError} from "./errors.ts";

/**
 * The retry rule of spec 14.4: a network error or a 503, twice at most, never a 4xx.
 * A fetch that never reached the server throws a `TypeError` with no status.
 */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= 2) return false;
  if (isApiError(error)) return error.status === 503;
  return error instanceof TypeError;
}

/**
 * The default options of the app's one QueryClient (AppProviders). Memory only, no persister.
 * `refetchOnWindowFocus` is off here and `/me` turns it on for itself, so revocation shows.
 * `refetchOnReconnect` is gated by presence: a network that drops and comes back with nobody at the
 * page must not fetch with the session cookie, because every authenticated request slides the idle
 * limit (AUTH 3.3). A query that sets its own value must use `refetchWhenPresent` too.
 */
export const queryDefaults = {
  retry: shouldRetry,
  staleTime: 30_000,
  refetchOnWindowFocus: false,
  refetchOnReconnect: refetchWhenPresent,
} as const;

/**
 * The default options of every mutation. A mutation keeps its `variables` and its answer in the
 * MutationCache for `gcTime` after the last component that observed it unmounts, and the browser
 * default is 5 minutes. The writes of the screens carry one-time secrets: the password of a login or
 * a reauth, a TOTP secret and its recovery codes, a console one-time password, a reset ticket
 * (spec 14.4). Closing the dialog removes them from the DOM but not from memory, where a devtools
 * panel or a heap snapshot of a shared PC finds them while the session is still live. With 0 the
 * state goes as soon as the last observer unmounts, for every screen at once (wp4-r7-3).
 * A screen must also never put a secret in a query key or in the data of a query: a query is kept
 * in the cache, and its key is readable there.
 */
export const mutationDefaults = {
  gcTime: 0,
} as const;

/** The app's one QueryClient (AppProviders). Here, not there, so that a test builds the very client the app runs. */
export function makeQueryClient(): QueryClient {
  return new QueryClient({defaultOptions: {queries: {...queryDefaults}, mutations: {...mutationDefaults}}});
}
