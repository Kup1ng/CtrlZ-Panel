import {ApiError} from "@ctrlz/api-client/errors.ts";
import {beforeEach, describe, expect, it, vi} from "vitest";

const calls: {path: string; body?: Record<string, unknown>}[] = [];
let getAnswer: () => Promise<{data: unknown}> = async () => ({data: {}});
vi.mock("@ctrlz/api-client/client.ts", () => ({
  api: {
    GET: async (route: string) => {
      calls.push({path: route});
      return getAnswer();
    },
    POST: async (route: string, init: {body: Record<string, unknown>}) => {
      calls.push({path: route, body: init.body});
      return {data: {}, response: {status: 204}};
    },
  },
}));
vi.mock("@ctrlz/api-client/core.ts", () => ({required: (result: {data: unknown}) => result.data}));

import {authApi} from "./authApi.ts";

beforeEach(() => {
  calls.length = 0;
});

// wp8-r12-1, r12-3: the stall bound of useCompleteSignIn may call a session ended only on a 401 from /me. A 200 is
// live, and an answer that says nothing about the session (429, 5xx, a dropped connection) is not its end.
describe("authApi.sessionState", () => {
  it("is live on a 200", async () => {
    getAnswer = async () => ({data: {user: {}}});
    expect(await authApi.sessionState()).toBe("live");
    expect(calls).toEqual([{path: "/me"}]);
  });

  it("is dead on a 401 only", async () => {
    getAnswer = async () => Promise.reject(new ApiError(401, "session_expired"));
    expect(await authApi.sessionState()).toBe("dead");
  });

  it("says unknown for a 429, a 5xx and a network failure", async () => {
    for (const error of [new ApiError(429, "rate_limited"), new ApiError(503, "service_unavailable"), new TypeError("Failed to fetch")]) {
      getAnswer = async () => Promise.reject(error);
      expect(await authApi.sessionState()).toBe("unknown");
    }
  });
});

// wp8-r12-2: /auth/reauth takes the authenticator code or a recovery code, as ASCII.
describe("authApi.reauth", () => {
  it("sends a recovery code in place of the authenticator code", async () => {
    await authApi.reauth({password: "p", recovery_code: "ABCDEFGH23456789"});
    expect(calls[0]).toEqual({path: "/auth/reauth", body: {password: "p", recovery_code: "ABCDEFGH23456789"}});
  });

  it("turns Persian digits of either code into ASCII", async () => {
    await authApi.reauth({password: "p", totp_code: "۱۲۳۴۵۶"});
    await authApi.reauth({password: "p", recovery_code: "ABCD۱۲۳۴EFGH5678"});
    expect(calls[0]?.body).toEqual({password: "p", totp_code: "123456"});
    expect(calls[1]?.body).toEqual({password: "p", recovery_code: "ABCD1234EFGH5678"});
  });

  it("sends only the password when there is no code", async () => {
    await authApi.reauth({password: "p"});
    expect(calls[0]?.body).toEqual({password: "p"});
  });
});

// wp8-r17-1: every code a visitor typed goes out as ASCII digits (spec 10.3, 17.3). Each route that carries one is
// pinned here, so deleting the conversion from any single branch fails a test.
describe("authApi sends typed codes as ASCII digits", () => {
  it("loginOtp, register and resetVerify convert the SMS code", async () => {
    await authApi.loginOtp({phone: "09120000000", challenge_id: "c", code: "۱۲۳۴۵۶", remember_me: false});
    await authApi.register({phone: "09120000000", challenge_id: "c", code: "۱۲۳۴۵۶", locale: "fa"});
    await authApi.register({invite_token: "t", challenge_id: "c", code: "۱۲۳۴۵۶", locale: "fa"});
    await authApi.resetVerify({phone: "09120000000", challenge_id: "c", code: "۱۲۳۴۵۶"});
    expect(calls.map((call) => call.body?.code)).toEqual(["123456", "123456", "123456", "123456"]);
  });

  it("loginTotp converts the authenticator code and a recovery code", async () => {
    await authApi.loginTotp({ticket: "t", totp_code: "۱۲۳۴۵۶"});
    await authApi.loginTotp({ticket: "t", recovery_code: "ABCD۱۲۳۴EFGH۵۶۷۸"});
    expect(calls[0]).toEqual({path: "/auth/login/totp", body: {ticket: "t", totp_code: "123456"}});
    expect(calls[1]).toEqual({path: "/auth/login/totp", body: {ticket: "t", recovery_code: "ABCD1234EFGH5678"}});
  });

  it("resetComplete converts the authenticator code and a recovery code, and leaves the rest alone", async () => {
    await authApi.resetComplete({ticket: "t", new_password: "pässword-۱۲۳", totp_code: "۱۲۳۴۵۶"});
    await authApi.resetComplete({ticket: "t", new_password: "x", recovery_code: "ABCD۱۲۳۴EFGH۵۶۷۸", defer_enforce: true});
    await authApi.resetComplete({ticket: "t", new_password: "x"});
    expect(calls[0]?.body).toEqual({ticket: "t", new_password: "pässword-۱۲۳", totp_code: "123456"});
    expect(calls[1]?.body).toEqual({ticket: "t", new_password: "x", recovery_code: "ABCD1234EFGH5678", defer_enforce: true});
    expect(calls[2]?.body).toEqual({ticket: "t", new_password: "x"});
  });

  it("changePassword converts the authenticator code", async () => {
    await authApi.changePassword({new_password: "x", totp_code: "۱۲۳۴۵۶"});
    expect(calls[0]?.body).toEqual({new_password: "x", totp_code: "123456"});
  });
});
