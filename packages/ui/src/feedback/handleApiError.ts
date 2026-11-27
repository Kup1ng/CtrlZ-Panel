"use client";

import {hasCode, isApiError, type ErrorCode} from "@ctrlz/api-client/errors.ts";
import {leaveEndedAdminSession} from "@ctrlz/api-client/admin/session.ts";
import {isOnLoginPath, isSessionEnding, logoutLocal, type SessionContext} from "@ctrlz/api-client/session.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import type {AppId} from "@ctrlz/i18n/namespaces.ts";
import {useQueryClient} from "@tanstack/react-query";
import {useLocale} from "next-intl";
import {useCallback} from "react";

import {useApp} from "../providers/appContext.tsx";
import {currentNext} from "../shell/currentNext.ts";

// Spec 14.3, the table "Global handling". Some errors are not the screen's to show: the session is
// over, the password must change, the account is suspended, a fresh proof is needed. The screen
// asks this module first, and shows inline only what it returns as not handled.
//
//   session_expired            the refresh already failed (14.4), so the session is over: leave
//   password_change_required   /change-password
//   account_suspended          /suspended
//   setup_required (admin)     /setup
//   reauth_required (panel)    the reauth dialog, then the call once more
//   totp_fresh_required (admin) the fresh-TOTP dialog, then the call once more
//   not_found                  the section's own empty or 404 state, if it gave one
//   anything else              not handled: the caller shows it inline
//
// The dialogs themselves are other work packages' (WP8 reauth, WP10 fresh TOTP); this module takes
// them as functions, so it has no UI and no way to open the wrong one. "Once more" is exactly
// once: a call that fails again is shown, never looped.

export type ApiErrorOutcome =
  | {kind: "session_ended"}
  | {kind: "navigate"; to: "/change-password" | "/suspended" | "/setup"}
  | {kind: "reauth"}
  | {kind: "fresh_totp"}
  | {kind: "not_found"}
  | {kind: "inline"};

/** What the table says to do with an error. Pure: no navigation, no dialog. */
export function classifyApiError(error: unknown, app: AppId): ApiErrorOutcome {
  if (!isApiError(error)) return {kind: "inline"};
  const code: ErrorCode = error.code;
  switch (code) {
    case "session_expired":
      return {kind: "session_ended"};
    case "password_change_required":
      return {kind: "navigate", to: "/change-password"};
    case "account_suspended":
      return {kind: "navigate", to: "/suspended"};
    case "setup_required":
      return app === "admin" ? {kind: "navigate", to: "/setup"} : {kind: "inline"};
    case "reauth_required":
      return app === "panel" ? {kind: "reauth"} : {kind: "inline"};
    case "totp_fresh_required":
      return app === "admin" ? {kind: "fresh_totp"} : {kind: "inline"};
    case "not_found":
      return {kind: "not_found"};
    default:
      return {kind: "inline"};
  }
}

export type ApiErrorActions = {
  app: AppId;
  /** Locale-aware `router.replace`. */
  navigate(to: "/change-password" | "/suspended" | "/setup"): void;
  /**
   * The session is over: clear and leave. Returns `true` when the page is leaving (this call started it,
   * or it was already under way), `false` when nothing was done, so the caller shows the error itself.
   */
  endSession(): boolean;
  /** Opens the reauth dialog. Resolves `true` when the user proved themselves, `false` when they gave up. */
  reauth?(): Promise<boolean>;
  /** Opens the fresh-TOTP dialog. Same contract. */
  freshTotp?(): Promise<boolean>;
  /** The section shows its own empty or 404 state for a missing row. */
  onNotFound?(): void;
};

// An error the module already acted on, so a screen that awaits the call knows not to show it too.
const handled = new WeakSet<object>();

/** True for an error `handleApiError` or `callWithRecovery` already dealt with. */
export function isHandledError(error: unknown): boolean {
  return typeof error === "object" && error !== null && handled.has(error);
}

/**
 * Acts on the global part of the table. Returns `true` when the error was handled and the caller
 * shows nothing, `false` when it is the caller's to show inline. `reauth` and `fresh_totp` are
 * left to `callWithRecovery`, because only it can repeat the call, so here they read as not handled.
 */
export function handleApiError(error: unknown, actions: ApiErrorActions): boolean {
  const outcome = classifyApiError(error, actions.app);
  switch (outcome.kind) {
    case "session_ended":
      // A call that did nothing must not mark the error handled: the screen would show nothing at all.
      if (!actions.endSession()) return false;
      break;
    case "navigate":
      actions.navigate(outcome.to);
      break;
    case "not_found":
      if (!actions.onNotFound) return false;
      actions.onNotFound();
      break;
    default:
      return false;
  }
  if (typeof error === "object" && error !== null) handled.add(error);
  return true;
}

/**
 * Runs `call`. A `reauth_required` (panel) or `totp_fresh_required` (admin) opens the matching dialog
 * and repeats `call` once if the user confirmed; the other global errors are acted on. Whatever is
 * still thrown is the original error, or the one from the repeat, so the caller can show it inline
 * unless `isHandledError` says it was dealt with.
 */
export async function callWithRecovery<T>(call: () => Promise<T>, actions: ApiErrorActions): Promise<T> {
  try {
    return await call();
  } catch (first) {
    const outcome = classifyApiError(first, actions.app);
    const ask = outcome.kind === "reauth" ? actions.reauth : outcome.kind === "fresh_totp" ? actions.freshTotp : undefined;
    if (!ask) {
      handleApiError(first, actions);
      throw first;
    }
    let confirmed = false;
    try {
      confirmed = await ask();
    } catch {
      confirmed = false;
    }
    if (!confirmed) throw first;
    try {
      return await call();
    } catch (second) {
      // The repeat may meet a dead session or a suspension; it must not ask for the same proof again.
      if (!hasCode(second, "reauth_required", "totp_fresh_required")) handleApiError(second, actions);
      throw second;
    }
  }
}

/**
 * What "the session is over" does for a call made outside a TanStack query or mutation, which the
 * admin guard's cache listener never sees (wp7-r1-1). It does not lean on the panel's `SessionBinding`
 * (`handleSessionEnded` is a no-op without one), so it ends the session the same way in both apps and
 * on every page: the panel clears and leaves like its binding does, the admin leaves with the
 * `?ended=1` marker. On the login page there is nowhere to go, so it reports `false` and the screen
 * shows the error.
 */
export function endSessionFor(app: AppId, context: SessionContext): boolean {
  if (isSessionEnding()) return true;
  if (isOnLoginPath()) return false;
  if (app === "admin") leaveEndedAdminSession(context, currentNext(app));
  // No broadcast: a screen that saw `session_expired` has no proof the session ended (wp4-r15-1), and a
  // "logout" message would end the live tabs too. Only a logout the server answered posts it.
  else logoutLocal(context, {broadcast: false, next: currentNext(app)});
  return true;
}

/** The actions bound to the router and the session of this app. `reauth` and `freshTotp` come from the screen. */
export function useApiErrorActions(extra: Pick<ApiErrorActions, "reauth" | "freshTotp" | "onNotFound"> = {}): ApiErrorActions {
  const app = useApp();
  const router = useRouter();
  const queryClient = useQueryClient();
  const locale = useLocale();
  const navigate = useCallback((to: "/change-password" | "/suspended" | "/setup") => router.replace(to), [router]);
  const endSession = useCallback(() => endSessionFor(app, {queryClient, locale}), [app, queryClient, locale]);
  return {app, navigate, endSession, ...extra};
}
