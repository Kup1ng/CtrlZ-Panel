import {beforeEach, describe, expect, it, vi} from "vitest";

const calls: {path: string; body?: Record<string, unknown>}[] = [];
vi.mock("@ctrlz/api-client/client.ts", () => ({
  api: {
    POST: async (route: string, init?: {body?: Record<string, unknown>}) => {
      calls.push({path: route, body: init?.body});
      return {data: {challenge_id: "c", expires_in_s: 300, resend_after_s: 60}, response: {status: 204}};
    },
  },
}));
vi.mock("@ctrlz/api-client/core.ts", async (original) => ({...(await original<object>()), required: (result: {data: unknown}) => result.data}));
vi.mock("@ctrlz/api-client/webauthn.ts", () => ({passkeyReauth: async () => undefined}));

import {reauthApi} from "./reauthApi.ts";
import {canReauthWithPasskey, reauthKind} from "./reauthKind.ts";

beforeEach(() => {
  calls.length = 0;
});

const me = (has_password: boolean, totp_enabled: boolean, security: {passkeys?: number; passkey_review_required?: boolean} = {}) => ({
  user: {has_password},
  security: {totp_enabled, passkeys: 0, passkey_review_required: false, ...security},
}) as never;

// Spec 12.1, the table: which fields a reauth draws follows what the account has (AUTH 3.5).
describe("reauthKind", () => {
  it.each([
    [true, false, "password"],
    [true, true, "password_totp"],
    [false, true, "totp"],
    [false, false, "otp"],
  ] as const)("password %s and authenticator %s asks for %s", (password, totp, kind) => {
    expect(reauthKind(me(password, totp))).toBe(kind);
  });
});

describe("canReauthWithPasskey", () => {
  it("needs a live passkey and the operator's switch", () => {
    expect(canReauthWithPasskey(me(true, false, {passkeys: 1}), true)).toBe(true);
    expect(canReauthWithPasskey(me(true, false, {passkeys: 0}), true)).toBe(false);
    expect(canReauthWithPasskey(me(true, false, {passkeys: 1}), false)).toBe(false);
  });

  it("is refused while a review is pending (AUTH 7.7), so the review cannot be cleared by the thing under review", () => {
    expect(canReauthWithPasskey(me(true, false, {passkeys: 2, passkey_review_required: true}), true)).toBe(false);
  });
});

describe("reauthApi", () => {
  it("turns Persian digits of the authenticator, recovery and SMS codes into ASCII", async () => {
    await reauthApi.prove({password: "p", totp_code: "۱۲۳۴۵۶"});
    await reauthApi.prove({recovery_code: "ABCD۱۲۳۴EFGH5678"});
    await reauthApi.prove({otp_challenge_id: "c", otp_code: "٦٥٤٣٢١"});
    expect(calls.map((c) => c.body)).toEqual([
      {password: "p", totp_code: "123456"},
      {recovery_code: "ABCD1234EFGH5678"},
      {otp_challenge_id: "c", otp_code: "654321"},
    ]);
    expect(calls.every((c) => c.path === "/auth/reauth")).toBe(true);
  });

  it("asks for an SMS code with no body: the number is the session's own", async () => {
    await reauthApi.requestOtp();
    expect(calls).toEqual([{path: "/auth/reauth/otp/request", body: undefined}]);
  });
});
