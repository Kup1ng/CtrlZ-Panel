import {hasCode} from "@ctrlz/api-client/errors.ts";
import {isWebAuthnCancel} from "@ctrlz/api-client/webauthn.ts";

import type {LoginMethod, LoginResult} from "./authApi.ts";

// The state machine of the login page (spec 10.2) without React, so each row of the two outcome tables
// is a plain test. Tickets and challenges live here and nowhere else: not in the URL, not in storage.
// The URL mirrors only `?step=`, and only for the two steps a reload can honestly show.

export type LoginStep = "password" | "otp-phone" | "otp-code" | "2fa" | "passkey";

/** The steps a reload may land on. Every other step needs a ticket or a challenge that a reload loses. */
export const RELOADABLE_STEPS = ["password", "otp-phone"] as const satisfies readonly LoginStep[];

export function stepFromParam(param: string | null | undefined, smsAvailable: boolean): LoginStep {
  return param === "otp-phone" && smsAvailable ? "otp-phone" : "password";
}

export type LoginState = {
  step: LoginStep;
  phone: string;
  remember: boolean;
  /** The OTP being waited for, with the moment the "resend" button wakes. */
  challenge: {id: string; readyAt: number} | null;
  /** The mfa ticket, with the moment it ends. */
  ticket: {value: string; endsAt: number; methods: readonly LoginMethod[]} | null;
  /** `passkey_unavailable` removes the passkey button for the rest of the visit. */
  passkeyGone: boolean;
  /** An error the step we returned to still has to show (`otp_expired`, `ticket_invalid`). */
  notice: unknown;
  /**
   * The step on screen was reached by going back, so the step it replaced (and the focus in it) is gone and the
   * focus would fall to the page. The step puts it on its first field (wp8-r1-4). False for the first
   * visit and for a tab switch, where the focus is on the tab and must stay there.
   */
  returned: boolean;
  /**
   * The sign-in was refused with `account_suspended`. No session exists then (AUTH 5.7: the password path
   * answers 403 and creates none), so /suspended, which asks /me, would find nothing and fall back to this
   * page with no explanation. The page says it where it is (wp8-r2-1).
   */
  suspended: boolean;
};

export const initialLoginState = (step: LoginStep = "password"): LoginState => ({
  step,
  phone: "",
  remember: false,
  challenge: null,
  ticket: null,
  passkeyGone: false,
  notice: null,
  returned: false,
  suspended: false,
});

export type LoginEvent =
  | {type: "phone"; value: string}
  | {type: "remember"; value: boolean}
  /** The visitor edited a field or sent a request: the notice of the step we came back to has been read. */
  | {type: "clearNotice"}
  | {type: "tab"; step: "password" | "otp-phone"}
  | {type: "otpSent"; id: string; readyAt: number}
  | {type: "mfa"; ticket: string; endsAt: number; methods: readonly LoginMethod[]}
  | {type: "passkey"}
  | {type: "back"; to: "password" | "otp-phone"; notice?: unknown}
  | {type: "passkeyGone"}
  | {type: "suspended"};

export function loginReducer(state: LoginState, event: LoginEvent): LoginState {
  switch (event.type) {
    case "phone":
      return {...state, phone: event.value, notice: null};
    case "clearNotice":
      return state.notice === null ? state : {...state, notice: null};
    case "remember":
      return {...state, remember: event.value};
    case "tab":
      return {...state, step: event.step, notice: null, returned: false, suspended: false};
    case "otpSent":
      return {...state, step: "otp-code", challenge: {id: event.id, readyAt: event.readyAt}, notice: null, returned: false};
    case "mfa":
      return {...state, step: "2fa", ticket: {value: event.ticket, endsAt: event.endsAt, methods: event.methods}, notice: null, returned: false};
    case "passkey":
      return {...state, step: "passkey", ticket: null, notice: null, returned: false};
    case "back":
      // The challenge and the ticket are dropped with the step that held them; the phone stays, so the
      // visitor does not type it again (spec 10.2, `otp_expired`).
      return {...state, step: event.to, challenge: null, ticket: null, notice: event.notice ?? null, returned: true, suspended: false};
    case "suspended":
      return {...state, step: "password", challenge: null, ticket: null, notice: null, returned: false, suspended: true};
    case "passkeyGone":
      return state.step === "passkey"
        ? {...state, passkeyGone: true, step: "password", returned: true}
        : {...state, passkeyGone: true};
  }
}

/** What a `LoginResult` means for the page (the first three rows of the outcome table in 10.2). */
export type ResultOutcome =
  | {kind: "authenticated"}
  | {kind: "mfa"; ticket: string; expiresInS: number | undefined; methods: readonly LoginMethod[]}
  | {kind: "passkey"}
  | {kind: "unreadable"};

export function resultOutcome(result: LoginResult): ResultOutcome {
  switch (result.status) {
    case "authenticated":
      return {kind: "authenticated"};
    case "passkey_required":
      return {kind: "passkey"};
    case "mfa_required":
      // Without a ticket there is nothing to continue with. The server never does this; a broken one must
      // not leave the visitor on a blank step.
      return result.ticket
        ? {kind: "mfa", ticket: result.ticket, expiresInS: result.ticket_expires_in_s, methods: result.methods ?? ["totp"]}
        : {kind: "unreadable"};
    default:
      return {kind: "unreadable"};
  }
}

/** What a failed call does to the page: the error rows of the outcome table in 10.2. */
export type ErrorOutcome =
  /** `FormError`, the generic case, and the case with a wait or a request id. */
  | {kind: "form"}
  /** `invalid_credentials`: one neutral message, the password cleared, the focus on the password. */
  | {kind: "invalidCredentials"}
  /** `otp_invalid`, `totp_invalid`, `totp_step_reused`: under the code, slots cleared, focus on the first. */
  | {kind: "code"}
  /** `otp_expired`, `otp_locked`, `ticket_invalid`: back to a step that can start again, with the message. */
  | {kind: "back"; to: "password" | "otp-phone"}
  /** `account_suspended` from any step: the page explains it in place (no session exists to show /suspended with). */
  | {kind: "suspended"}
  /** The user closed the browser's prompt: nothing to say. */
  | {kind: "silent"}
  /** `passkey_unavailable`: the passkey button is removed. */
  | {kind: "passkeyGone"};

export function loginErrorOutcome(step: LoginStep, error: unknown): ErrorOutcome {
  if (step === "passkey" && isWebAuthnCancel(error)) return {kind: "silent"};
  if (hasCode(error, "account_suspended")) return {kind: "suspended"};
  if (hasCode(error, "passkey_unavailable")) return {kind: "passkeyGone"};
  switch (step) {
    case "password":
      return hasCode(error, "invalid_credentials") ? {kind: "invalidCredentials"} : {kind: "form"};
    case "otp-code":
      if (hasCode(error, "otp_invalid")) return {kind: "code"};
      if (hasCode(error, "otp_expired", "otp_locked")) return {kind: "back", to: "otp-phone"};
      return {kind: "form"};
    case "2fa":
      if (hasCode(error, "totp_invalid", "totp_step_reused")) return {kind: "code"};
      if (hasCode(error, "ticket_invalid")) return {kind: "back", to: "password"};
      return {kind: "form"};
    case "passkey":
      // The ceremony ticket of finish ends the same way as the second-factor ticket (10.2 lists ticket_invalid for
      // every step): a spent or expired one cannot be retried, so the visitor starts again from the password.
      if (hasCode(error, "ticket_invalid")) return {kind: "back", to: "password"};
      return {kind: "form"};
    default:
      return {kind: "form"};
  }
}
