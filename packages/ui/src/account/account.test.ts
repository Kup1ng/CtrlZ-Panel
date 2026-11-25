import {meKeys} from "@ctrlz/api-client/hooks/me.ts";
import {passkeyKeys} from "@ctrlz/api-client/hooks/passkeys.ts";
import {sessionKeys} from "@ctrlz/api-client/hooks/sessions.ts";
import {QueryClient} from "@tanstack/react-query";
import {beforeEach, describe, expect, it, vi} from "vitest";

const calls: {method: string; path: string; body?: Record<string, unknown>; params?: unknown}[] = [];
vi.mock("@ctrlz/api-client/client.ts", () => {
  const answer = (method: string) => async (path: string, init?: {body?: Record<string, unknown>; params?: unknown}) => {
    calls.push({method, path, body: init?.body, params: init?.params});
    return {data: {secret: "S", otpauth_uri: "u", countries: init?.body?.countries, request_id: "r", ended_sessions: 0, recovery_codes: []}};
  };
  return {api: {POST: answer("POST"), PUT: answer("PUT"), GET: answer("GET"), PATCH: answer("PATCH"), DELETE: answer("DELETE")}};
});
vi.mock("@ctrlz/api-client/core.ts", async (original) => ({...(await original<object>()), required: (result: {data: unknown}) => result.data}));

import {ApiError} from "@ctrlz/api-client/errors.ts";
import {accountApi, answerMayBeLost, putHomeCountries, refreshAccount} from "./accountApi.ts";
import {matchesCountry, HOME_LIMIT} from "./HomeCountries.tsx";
import {groupSecret, recoveryCodesText, recoveryFileContent} from "./recoveryCodes.ts";
import {trimAgent} from "./SessionsRow.tsx";

beforeEach(() => {
  calls.length = 0;
});

describe("accountApi", () => {
  it("sends the new number without invisible characters, and the language of the page", async () => {
    await accountApi.startPhoneChange("0935‏1234567", "fa");
    expect(calls[0]).toMatchObject({path: "/account/phone/change", body: {new_phone: "09351234567", locale: "fa"}});
  });

  it("sends both phone codes as ASCII digits, to the request's own path", async () => {
    await accountApi.confirmPhoneChange("req-1", {old_code: "۱۲۳۴۵۶", new_code: "٦٥٤٣٢١"});
    expect(calls[0]).toMatchObject({path: "/account/phone/change/{id}/confirm", params: {path: {id: "req-1"}}, body: {old_code: "123456", new_code: "654321"}});
  });

  it("confirms the authenticator with the saved tick the server insists on, as ASCII", async () => {
    await accountApi.totpConfirm("۱۲۳۴۵۶");
    expect(calls[0]).toMatchObject({path: "/account/totp/confirm", body: {code: "123456", saved: true}});
  });

  it("sets the password with the new password alone: a fresh window already proved the second factor", async () => {
    await accountApi.changePassword("n");
    expect(calls[0]).toMatchObject({path: "/account/password", body: {new_password: "n"}});
  });

  it("writes the whole list of Home Countries", async () => {
    await accountApi.setHomeCountries(["IR", "DE"]);
    expect(calls[0]).toMatchObject({method: "PUT", path: "/account/home-countries", body: {countries: ["IR", "DE"]}});
  });
});

describe("what a security change leaves stale", () => {
  it("drops /me, the session list and the passkey list together", async () => {
    const client = new QueryClient();
    const spy = vi.spyOn(client, "invalidateQueries");
    await refreshAccount(client);
    expect(spy.mock.calls.map(([filter]) => filter?.queryKey)).toEqual([meKeys.all, sessionKeys.list, passkeyKeys.list]);
  });

  it("puts the saved countries into the cached /me", () => {
    const client = new QueryClient();
    client.setQueryData(meKeys.all, {user: {}, security: {}, tenant: {id: "t", status: "active", home_countries: ["IR"]}});
    putHomeCountries(client, ["IR", "DE"]);
    expect(client.getQueryData<{tenant: {home_countries: string[]}}>(meKeys.all)?.tenant.home_countries).toEqual(["IR", "DE"]);
  });

  it("leaves an empty cache empty", () => {
    const client = new QueryClient();
    putHomeCountries(client, ["IR"]);
    expect(client.getQueryData(meKeys.all)).toBeUndefined();
  });
});

describe("recovery codes", () => {
  const codes = ["AAAA-BBBB-CCCC-DDDD", "EEEE-FFFF-GGGG-HHHH"];

  it("copy as one code per line and nothing else", () => {
    expect(recoveryCodesText(codes)).toBe("AAAA-BBBB-CCCC-DDDD\nEEEE-FFFF-GGGG-HHHH");
  });

  it("download as a text file with a header, led by a byte order mark so Notepad reads Persian", () => {
    const text = recoveryFileContent("هدر", codes);
    expect(text.startsWith("﻿هدر\n\n")).toBe(true);
    for (const code of codes) expect(text).toContain(code);
  });

  it("show the secret in groups of four", () => {
    expect(groupSecret("JBSWY3DPEHPK3PXP")).toBe("JBSW Y3DP EHPK 3PXP");
  });
});

describe("sessions list", () => {
  it("trims a long user agent and leaves a short one", () => {
    expect(trimAgent("Mozilla/5.0")).toBe("Mozilla/5.0");
    const long = "x".repeat(400);
    expect(trimAgent(long).length).toBeLessThan(100);
    expect(trimAgent(long).endsWith("…")).toBe(true);
  });
});

describe("Home Countries search", () => {
  it("is three at most", () => {
    expect(HOME_LIMIT).toBe(3);
  });

  it("finds a Persian name typed with Arabic yeh and kaf, and ignores case in English", () => {
    expect(matchesCountry("ترکیه", "ترك")).toBe(true);
    expect(matchesCountry("کانادا", "كان")).toBe(true);
    expect(matchesCountry("Germany", "germ")).toBe(true);
    expect(matchesCountry("Germany", "zz")).toBe(false);
    expect(matchesCountry("Germany", "  ")).toBe(true);
  });
});

describe("answerMayBeLost", () => {
  it("is true when there was no answer or a 5xx that a proxy may have made after the server committed", () => {
    expect(answerMayBeLost(new TypeError("Failed to fetch"))).toBe(true);
    expect(answerMayBeLost(new DOMException("aborted", "AbortError"))).toBe(true);
    expect(answerMayBeLost(new ApiError(502, "unknown"))).toBe(true);
    expect(answerMayBeLost(new ApiError(504, "unknown"))).toBe(true);
    expect(answerMayBeLost(new ApiError(500, "internal"))).toBe(true);
  });

  it("is false for an answer that says nothing was done", () => {
    expect(answerMayBeLost(new ApiError(401, "totp_invalid"))).toBe(false);
    expect(answerMayBeLost(new ApiError(409, "totp_not_enabled"))).toBe(false);
    expect(answerMayBeLost(new ApiError(403, "reauth_required"))).toBe(false);
    expect(answerMayBeLost(new ApiError(503, "server_busy"))).toBe(false);
    expect(answerMayBeLost(new ApiError(503, "service_unavailable"))).toBe(false);
  });
});
