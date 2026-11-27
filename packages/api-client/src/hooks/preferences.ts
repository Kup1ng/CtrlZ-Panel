import {useMutation, useQueryClient, type QueryClient} from "@tanstack/react-query";
import {useCallback} from "react";

import {api} from "../client.ts";
import {required} from "../core.ts";
import {ApiError} from "../errors.ts";
import type {components} from "../generated/panel";
import type {Me} from "../session.ts";
import {meKeys, useMe} from "./me.ts";

// Spec 8.12 and AUTH 14.2. There is no GET for preferences: they are part of `Me`,
// so reading them is a `select` on `/me` and writing one puts the answer (a whole
// `Me`) back in the same cache entry.

export type PreferencesRequest = components["schemas"]["PreferencesRequest"];
export type OnboardingState = components["schemas"]["OnboardingState"];

/** One PATCH gets this long. A request that never settles must not hold back every later write of the tab (wp4-r10-3). */
export const PREFERENCE_TIMEOUT_MS = 10_000;

/**
 * After a timeout, `/me` is read again this much later. Aborting a fetch does not recall a request the
 * server already has, or one still on its way over a slow link, so the write that timed out can be applied
 * AFTER the one that followed it (wp4-r11-1). The order of the queue is then no longer the order the server
 * applied the writes in, and the cache holds what the client believes, not what is stored. The read puts
 * the cache, and with it the page and the onboarding card, back in step with the server. The wait gives a
 * request that is merely slow time to land first. A request slower than this still wins the race, and the
 * next `/me` (a load, a focus after a pause) corrects it.
 */
export const PREFERENCE_RECONCILE_MS = 15_000;

export type PreferenceWriteOptions = {
  /**
   * Send now, outside the queue, and merge only the written fields into the cached `Me`. For a write the
   * page is about to leave on: the language switch waits 1.5 s for it and then reloads, so a slow earlier
   * write must not hold it back. The reload makes the order of answers moot.
   */
  immediate?: boolean;
  timeoutMs?: number;
  reconcileMs?: number;
};

/** A function is called when the write's turn comes, so the body is built from the newest cache (wp4-r10-3). */
export type PreferencesBody = PreferencesRequest | (() => PreferencesRequest);

/**
 * `PATCH /account/preferences`, and the `Me` it answers with goes into the cache.
 *
 * A `GET /me` that was already on its way (the focus refetch, a login message) was answered before the
 * PATCH took effect, so if it landed after the write it would put the old theme, language or onboarding
 * state back, and the effect that adopts the server's theme would flip the page with it (wp4-r5-1).
 * It is cancelled first, as the notification mutations do for their own key.
 */
export function updatePreferences(queryClient: QueryClient, body: PreferencesBody, options: PreferenceWriteOptions = {}): Promise<Me> {
  if (options.immediate) return send(queryClient, body, options, true);
  // One write at a time per client (wp4-r9-2). Each answer is a whole `Me`, so the answer of the write
  // the server applied FIRST carries the old value of every field the later write changed. If two writes
  // are in flight (a theme switch and the onboarding dismissal, or the same field twice) and their
  // answers come back in the other order, the older Me would be the last one put in the cache. Sent one
  // after the other, each answer includes all the writes before it, whatever the network does. A failed
  // or timed-out write does not hold up the next one.
  const run = (writeQueues.get(queryClient) ?? Promise.resolve()).then(() => send(queryClient, body, options, false));
  writeQueues.set(
    queryClient,
    run.then(
      () => undefined,
      () => undefined,
    ),
  );
  return run;
}

const writeQueues = new WeakMap<QueryClient, Promise<void>>();

async function send(queryClient: QueryClient, body: PreferencesBody, options: PreferenceWriteOptions, merge: boolean): Promise<Me> {
  const request = typeof body === "function" ? body() : body;
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // Both the signal (the browser drops the request) and the race (a fetch that ignores the signal still
  // frees the queue).
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      // The server may still apply it, after later writes: read the truth back (see PREFERENCE_RECONCILE_MS).
      setTimeout(() => void queryClient.invalidateQueries({queryKey: meKeys.all}), options.reconcileMs ?? PREFERENCE_RECONCILE_MS);
      reject(new ApiError(504, "unknown"));
    }, options.timeoutMs ?? PREFERENCE_TIMEOUT_MS);
  });
  const patch = api.PATCH("/account/preferences", {body: request, signal: controller.signal});
  patch.catch(() => undefined);
  let me: Me;
  try {
    me = required(await Promise.race([patch, timeout]));
  } finally {
    clearTimeout(timer);
  }
  await queryClient.cancelQueries({queryKey: meKeys.all});
  if (merge) {
    // Only what this write changed: the answer may predate the writes still in flight.
    queryClient.setQueryData<Me>(meKeys.all, (prev) => {
      if (!prev) return me;
      const written = Object.fromEntries(Object.keys(request).map((key) => [key, me.user[key as keyof Me["user"]]]));
      return {...prev, user: {...prev.user, ...written}};
    });
  } else {
    queryClient.setQueryData(meKeys.all, me);
  }
  return me;
}

export function useUpdatePreferences() {
  const queryClient = useQueryClient();
  return useMutation({mutationFn: (body: PreferencesRequest) => updatePreferences(queryClient, body)});}

/** `dismissed_at` is a timestamp the server never sees as null: the schema holds scalars only, so absent means "not yet". */
export function isOnboardingDismissed(state: OnboardingState | undefined): boolean {
  const at = state?.dismissed_at;
  return typeof at === "string" && at !== "";
}

/**
 * The whole object the next PATCH sends, since `onboarding_state` replaces the
 * stored value (spec 8.12). Keys that are already there stay.
 */
export function dismissedOnboardingState(state: OnboardingState | undefined, now: Date): OnboardingState {
  return {...state, v: 1, dismissed_at: now.toISOString()};
}

/**
 * `PATCH /account/preferences {onboarding_state}` with `dismissed_at` set, built from the state the
 * cache holds now. Rejects with the API's error and leaves the cache as it was, so a failed
 * dismissal leaves the card in place: the caller says why (spec 10.1).
 */
export async function dismissOnboarding(queryClient: QueryClient, now: Date = new Date()): Promise<Me> {
  // `onboarding_state` replaces the stored value, so the body is built when the write's turn comes, from
  // the newest cache, not now: an onboarding write queued ahead of this one must not be overwritten by
  // an older snapshot (wp4-r10-3).
  return updatePreferences(queryClient, () => ({
    onboarding_state: dismissedOnboardingState(queryClient.getQueryData<Me>(meKeys.all)?.user.onboarding_state, now),
  }));
}

/**
 * The first-run checklist's state (spec 8.12). `hintsEnabled` off hides the card
 * without dismissing it. Before `/me` has answered the card stays hidden, so it
 * does not flash in and out.
 */
export function useOnboarding() {
  const {data: me} = useMe();
  const queryClient = useQueryClient();
  const known = me !== undefined;
  const state = me?.user.onboarding_state;

  /** Rejects when the write fails. The card catches it and shows the error. */
  const dismiss = useCallback(async () => {
    await dismissOnboarding(queryClient);
  }, [queryClient]);

  return {
    hintsEnabled: known && me.user.onboarding_hints.enabled,
    dismissed: !known || isOnboardingDismissed(state),
    dismiss,
  };
}

/** The one-time warning of the first Redirect a person chooses (spec p2 9.6, T-197) is remembered in `onboarding_state`, under this key. */
export const REDIRECT_WARNED_KEY = "redirect_warned_at";

export function isRedirectWarned(state: OnboardingState | undefined): boolean {
  const at = state?.[REDIRECT_WARNED_KEY];
  return typeof at === "string" && at !== "";
}

/**
 * Whether the first-Redirect warning has been seen, and the write that remembers it. Before `/me` has answered it counts as seen, so the
 * warning is not shown for a moment and then taken back. The write sends the whole object, built from the newest cache (it replaces).
 */
export function useRedirectWarning() {
  const {data: me} = useMe();
  const queryClient = useQueryClient();
  const seen = me === undefined || isRedirectWarned(me.user.onboarding_state);
  const markSeen = useCallback(async () => {
    await updatePreferences(queryClient, () => ({
      onboarding_state: {...queryClient.getQueryData<Me>(meKeys.all)?.user.onboarding_state, [REDIRECT_WARNED_KEY]: new Date().toISOString()},
    }));
  }, [queryClient]);
  return {seen, markSeen};
}
