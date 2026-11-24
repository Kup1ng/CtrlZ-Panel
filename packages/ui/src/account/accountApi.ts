import {api} from "@ctrlz/api-client/client.ts";
import {required} from "@ctrlz/api-client/core.ts";
import {meKeys} from "@ctrlz/api-client/hooks/me.ts";
import {passkeyKeys} from "@ctrlz/api-client/hooks/passkeys.ts";
import {sessionKeys} from "@ctrlz/api-client/hooks/sessions.ts";
import {isApiError} from "@ctrlz/api-client/errors.ts";
import type {Me} from "@ctrlz/api-client/session.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";
import {stripInvisible} from "../forms/invisible.ts";
import type {QueryClient} from "@tanstack/react-query";

// The routes of the Account page (spec 12, AUTH 14.2), one function each, so a row reads as a story and a
// test can see which body it sends. Every non-2xx is thrown as an ApiError by the client's error
// middleware. Nothing here keeps a secret: the TOTP secret, the recovery codes and the passwords pass
// through arguments and results only, and the dialogs that hold them hold them in state, never in a
// query cache or a URL. The passkey, session and preference routes have hooks in packages/api-client.

export const accountApi = {
  /** `POST /account/phone/change`. Both numbers get a code. The number goes out without invisible characters (wp8-r10-1). */
  async startPhoneChange(newPhone: string, locale: "fa" | "en", signal?: AbortSignal) {
    return required(await api.POST("/account/phone/change", {body: {new_phone: stripInvisible(newPhone), locale}, signal}));
  },

  /** 204. The session is rotated, the others end (AUTH 3.7). */
  async confirmPhoneChange(id: string, body: {old_code: string; new_code: string}, signal?: AbortSignal) {
    await api.POST("/account/phone/change/{id}/confirm", {
      params: {path: {id}},
      body: {old_code: toAsciiDigits(body.old_code), new_code: toAsciiDigits(body.new_code)},
      signal,
    });
  },

  /** 204. The first password of an SMS-only account uses the same route. */
  async changePassword(newPassword: string, signal?: AbortSignal) {
    await api.POST("/account/password", {body: {new_password: newPassword}, signal});
  },

  /** A pending secret lives 15 minutes (AUTH 6.4). Resolves to the secret and the otpauth URI, shown once. */
  async totpSetup(signal?: AbortSignal) {
    return required(await api.POST("/account/totp/setup", {body: {}, signal}));
  },

  /** `saved` is the tick of "I saved the key", which the server insists on. Resolves to the recovery codes, shown once. */
  async totpConfirm(code: string, signal?: AbortSignal) {
    return required(await api.POST("/account/totp/confirm", {body: {code: toAsciiDigits(code), saved: true}, signal}));
  },

  async totpDisable(signal?: AbortSignal) {
    return required(await api.POST("/account/totp/disable", {body: {}, signal}));
  },

  /** Replaces all the codes at once. */
  async regenerateRecoveryCodes(signal?: AbortSignal) {
    return required(await api.POST("/account/totp/recovery-codes", {body: {}, signal}));
  },

  async setHomeCountries(countries: string[], signal?: AbortSignal) {
    return required(await api.PUT("/account/home-countries", {body: {countries}, signal}));
  },
};

export type TotpSetup = Awaited<ReturnType<typeof accountApi.totpSetup>>;

/**
 * What a change of the account's security leaves stale: `/me` (has_password, totp_enabled, the passkey
 * count, the review mark), the session list (other sessions ended) and the passkey list (a phone change
 * may leave them for review). Pure, so a test can see which keys it drops.
 */
export function refreshAccount(queryClient: QueryClient) {
  return Promise.all([
    queryClient.invalidateQueries({queryKey: meKeys.all}),
    queryClient.invalidateQueries({queryKey: sessionKeys.list}),
    queryClient.invalidateQueries({queryKey: passkeyKeys.list}),
  ]);
}

/** `PUT /account/home-countries` answers only the list, so the cached `Me` takes it in place. */
export function putHomeCountries(queryClient: QueryClient, countries: string[]) {
  queryClient.setQueryData<Me>(meKeys.all, (prev) => (prev ? {...prev, tenant: {...prev.tenant, home_countries: countries}} : prev));
}

/**
 * A call that returns a one-time secret failed in a way that does not say whether the server did the work: no answer
 * at all (a dropped link, an abort) or a 5xx that a proxy may have made after the server committed. The 503s named
 * `server_busy` and `service_unavailable` are the server's own "not done". The caller refetches `/me` and tells the
 * person the codes may exist (wp9-r2-7).
 */
export function answerMayBeLost(error: unknown): boolean {
  if (!isApiError(error)) return true;
  return error.status >= 500 && error.code !== "server_busy" && error.code !== "service_unavailable";
}
