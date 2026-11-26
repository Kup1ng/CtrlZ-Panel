import {api} from "@ctrlz/api-client/client.ts";
import {required} from "@ctrlz/api-client/core.ts";
import {ApiError} from "@ctrlz/api-client/errors.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

import {stripInvisible} from "../forms/invisible.ts";

// The routes of the user auth screens (AUTH 14.2), one function each, so a screen reads as a story and a
// unit test can see which body it sends. Every non-2xx is thrown as an ApiError by the client's error
// middleware (spec 14.3). Tickets and passwords pass through these arguments only: nothing here stores
// them, and nothing puts them in a URL, a query key or a log. The WebAuthn ceremonies are the client's
// own (`passkeyLogin`, `passkeyResetProof` in @ctrlz/api-client/webauthn.ts).

export type Locale = "fa" | "en";

// Every code the user typed goes out as ASCII digits (spec 10.3): the field shows Persian digits as they were
// typed, and the one place that turns them into what the server reads is here, so no screen can forget it.
const ascii = toAsciiDigits;

// A phone number goes out without invisible format characters: the API schema refuses them with a bare 400 (wp8-r10-1).
// The phone fields strip them as they are typed; this is the one place that no screen can forget.
const withPhone = <T extends object>(body: T): T => ("phone" in body && typeof body.phone === "string" ? {...body, phone: stripInvisible(body.phone)} : body);

export const authApi = {
  async loginPassword(body: {phone: string; password: string; remember_me: boolean}, signal?: AbortSignal) {
    return required(await api.POST("/auth/login/password", {body: withPhone(body), signal}));
  },

  async requestOtp(
    body: {purpose: "login" | "signup" | "reset"; phone: string; locale: Locale} | {purpose: "invite"; invite_token: string; locale: Locale},
    signal?: AbortSignal,
  ) {
    return required(await api.POST("/auth/otp/request", {body: withPhone(body), signal}));
  },

  async loginOtp(body: {phone: string; challenge_id: string; code: string; remember_me: boolean}, signal?: AbortSignal) {
    return required(await api.POST("/auth/login/otp", {body: {...withPhone(body), code: ascii(body.code)}, signal}));
  },

  /** Exactly one of `totp_code` and `recovery_code`. */
  async loginTotp(body: {ticket: string; totp_code: string} | {ticket: string; recovery_code: string}, signal?: AbortSignal) {
    const clean = "totp_code" in body ? {...body, totp_code: ascii(body.totp_code)} : {...body, recovery_code: ascii(body.recovery_code)};
    return required(await api.POST("/auth/login/totp", {body: clean, signal}));
  },

  /**
   * Best effort: ends the session that a sign-in call opened after the page that asked for it had gone (the visitor
   * left by a link, the language menu or Back while the call ran). The page cannot show that session, so the browser
   * must not keep it. `keepalive` lets the request outlive the page. A failure is swallowed: nothing more can be done.
   */
  async dropSession() {
    try {
      await api.POST("/auth/logout", {keepalive: true});
    } catch {
      // Offline or already gone: the session ends by its own time.
    }
  },

  /**
   * Whether the session a sign-in opened works: `dead` only on a 401 from /me (after the client's own recovery), `live`
   * on a 200, and `unknown` for everything else (429, 5xx, offline), which says nothing about the session and must
   * not be read as its end (wp8-r12-1).
   */
  async sessionState(): Promise<"live" | "dead" | "unknown"> {
    try {
      required(await api.GET("/me"));
      return "live";
    } catch (error) {
      return error instanceof ApiError && error.status === 401 ? "dead" : "unknown";
    }
  },

  async register(
    body:
      | {phone: string; challenge_id: string; code: string; password?: string; locale: Locale}
      | {invite_token: string; challenge_id: string; code: string; password?: string; locale: Locale},
    signal?: AbortSignal,
  ) {
    return required(await api.POST("/auth/register", {body: {...withPhone(body), code: ascii(body.code)}, signal}));
  },

  async lookupInvite(token: string, signal?: AbortSignal) {
    return required(await api.POST("/auth/invites/lookup", {body: {token}, signal}));
  },

  async resetVerify(body: {phone: string; challenge_id: string; code: string}, signal?: AbortSignal) {
    return required(await api.POST("/auth/password/reset/verify", {body: {...withPhone(body), code: ascii(body.code)}, signal}));
  },

  /** 204. `defer_enforce` is the "I lost my passkey" path (AUTH 4.4). */
  async resetComplete(
    body: {ticket: string; new_password: string; totp_code?: string; recovery_code?: string; defer_enforce?: boolean},
    signal?: AbortSignal,
  ) {
    const clean = {
      ...body,
      ...(body.totp_code === undefined ? {} : {totp_code: ascii(body.totp_code)}),
      ...(body.recovery_code === undefined ? {} : {recovery_code: ascii(body.recovery_code)}),
    };
    await api.POST("/auth/password/reset/complete", {body: clean, signal});
  },

  /**
   * 204, and a ten minute reauth window (AUTH 3.5). `/auth/reauth` is `session-setup`, so a restricted session can
   * use it; the forced password change needs it when the session was opened by an SMS code or a passkey
   * (wp8-r1-3). Only what a restricted account can send: its password, and its authenticator code or a recovery code (wp8-r12-2).
   */
  async reauth(body: {password: string; totp_code?: string; recovery_code?: string}, signal?: AbortSignal) {
    const clean = {
      ...body,
      ...(body.totp_code === undefined ? {} : {totp_code: ascii(body.totp_code)}),
      ...(body.recovery_code === undefined ? {} : {recovery_code: ascii(body.recovery_code)}),
    };
    await api.POST("/auth/reauth", {body: clean, signal});
  },

  /** 204. The restricted session of 10.7: `totp_code` only for an account with an authenticator. */
  async changePassword(body: {new_password: string; totp_code?: string}, signal?: AbortSignal) {
    const clean = body.totp_code === undefined ? body : {...body, totp_code: ascii(body.totp_code)};
    await api.POST("/account/password", {body: clean, signal});
  },
};

// The answers, as the generated client types them, so a schema change shows here and nowhere is retyped.
export type LoginResult = Awaited<ReturnType<typeof authApi.loginPassword>>;
export type OtpIssued = Awaited<ReturnType<typeof authApi.requestOtp>>;
export type ResetVerified = Awaited<ReturnType<typeof authApi.resetVerify>>;
export type InviteInfo = Awaited<ReturnType<typeof authApi.lookupInvite>>;
export type LoginMethod = NonNullable<LoginResult["methods"]>[number];
