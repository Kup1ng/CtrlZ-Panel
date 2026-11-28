import {api} from "@ctrlz/api-client/client.ts";
import {required} from "@ctrlz/api-client/core.ts";
import {passkeyReauth} from "@ctrlz/api-client/webauthn.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

// The reauth routes of AUTH 3.5, one function each. `POST /auth/reauth` answers 204 with fresh cookies
// and opens a ten minute window that the server tracks; nothing here remembers it (spec 12.1). The codes
// leave as ASCII digits whatever the user typed, as in authApi.ts.

export type ReauthProof =
  | {password: string; totp_code?: string; recovery_code?: string}
  | {totp_code: string}
  | {recovery_code: string}
  | {otp_challenge_id: string; otp_code: string};

export const reauthApi = {
  async prove(proof: ReauthProof, signal?: AbortSignal) {
    const body = {...proof};
    if ("totp_code" in body && body.totp_code !== undefined) body.totp_code = toAsciiDigits(body.totp_code);
    if ("recovery_code" in body && body.recovery_code !== undefined) body.recovery_code = toAsciiDigits(body.recovery_code);
    if ("otp_code" in body) body.otp_code = toAsciiDigits(body.otp_code);
    await api.POST("/auth/reauth", {body, signal});
  },

  /** `POST /auth/reauth/otp/request`: no body, no phone. The code goes to the session's own number. */
  async requestOtp(signal?: AbortSignal) {
    return required(await api.POST("/auth/reauth/otp/request", {signal}));
  },

  /** Begin, the browser's prompt and finish, as one call. */
  passkey(signal?: AbortSignal) {
    return passkeyReauth({signal});
  },
};

export type ReauthOtpIssued = Awaited<ReturnType<typeof reauthApi.requestOtp>>;
