/// <reference types="node" />
import {existsSync, readdirSync, readFileSync} from "node:fs";
import path from "node:path";

import {describe, expect, it} from "vitest";

import {
  ApiError,
  apiErrorFromResponse,
  CLIENT_ONLY_CODES,
  ERROR_CODES,
  errorMessageArgs,
  errorMessageKey,
  fieldErrors,
  FIELD_ERROR_CODES,
  hasCode,
  isApiError,
} from "./errors.ts";

// Open question 9: `Error.code` is a plain string in OpenAPI, so the list in
// errors.ts is a hand copy. These tests are what keeps it honest.

const repo = path.resolve(import.meta.dirname, "../../..");
const messages = (locale: string) =>
  JSON.parse(readFileSync(path.join(repo, "packages/i18n/messages", locale, "errors.json"), "utf8")) as Record<string, unknown>;

describe("ERROR_CODES", () => {
  // No skipIf: this is the only check that sees a code no OpenAPI sentence names, so a Go file that
  // moved or was renamed must fail the run (wp4-r16-1), not skip it. Every non-test file of the package
  // is read, so a split of errors.go into several files is still found.
  const goDir = path.join(repo, "internal/httpx");

  it("is the list of codes of internal/httpx, plus unknown", () => {
    expect(existsSync(goDir), `${goDir} is gone: point this test at the new place of the codes`).toBe(true);
    const files = readdirSync(goDir).filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"));
    expect(files.length).toBeGreaterThan(0);
    const codes = files.flatMap((f) =>
      [...readFileSync(path.join(goDir, f), "utf8").matchAll(/^\s+Code\w+\s+= "([a-z_]+)"$/gm)].map((m) => m[1]!),
    );
    expect(codes.length).toBeGreaterThan(30);
    const clientOnly = new Set<string>(CLIENT_ONLY_CODES);
    expect([...ERROR_CODES].filter((c) => !clientOnly.has(c)).sort()).toEqual([...codes].sort());
  });

  it("holds every code the two OpenAPI documents name in an Errors sentence", () => {
    const named = new Set<string>();
    for (const file of ["api/openapi.yaml", "api/admin-openapi.yaml"]) {
      const text = readFileSync(path.join(repo, file), "utf8");
      // From "Errors:" to the end of the sentence: a full stop outside the backticks and at the end of a line or before a space.
      for (const m of text.matchAll(/Errors:([\s\S]*?)(?:\.\s|\.'|\.$)/gm)) {
        // Parentheses nest (main's putSmsRouting names a code inside a parenthesis inside a parenthesis): the innermost go first, until none is left.
        let sentence = m[1]!;
        for (let before = ""; before !== sentence; ) {
          before = sentence;
          sentence = sentence.replace(/\([^()]*\)/g, "");
        }
        for (const t of sentence.matchAll(/`([a-z_]+)`/g)) named.add(t[1]!);
      }
    }
    expect(named.size).toBeGreaterThan(30);
    const known = new Set<string>(ERROR_CODES);
    expect([...named].filter((c) => !known.has(c))).toEqual([]);
  });

  it("has no duplicate", () => {
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
  });

  it.each(["fa", "en"])("has a message for every code and every field code in %s", (locale) => {
    const m = messages(locale);
    for (const code of ERROR_CODES) expect(typeof m[code], code).toBe("string");
    const fields = m.fields as Record<string, unknown>;
    for (const code of FIELD_ERROR_CODES) expect(typeof fields[code], code).toBe("string");
  });

  it("keeps the message files free of keys that are not codes", () => {
    for (const locale of ["fa", "en"]) {
      const extra = Object.keys(messages(locale)).filter((k) => !(ERROR_CODES as readonly string[]).includes(k));
      // `fields`, `banners` and `idle` (the idle cover, activity.ts) are the groups of the namespace.
      expect(extra.sort(), locale).toEqual(["banners", "fields", "idle"]);
    }
  });
});

function reply(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {status, headers});
}

describe("apiErrorFromResponse", () => {
  it("reads code, request id, retry and fields from the body", async () => {
    const e = await apiErrorFromResponse(
      reply(422, {code: "password_weak", request_id: "abc-1", retry_after_s: 7, fields: [{name: "new_password", code: "too_short"}]}),
    );
    expect(e).toBeInstanceOf(ApiError);
    expect(e).toMatchObject({status: 422, code: "password_weak", requestId: "abc-1", retryAfterS: 7});
    expect(e.fields).toEqual([{name: "new_password", code: "too_short"}]);
  });

  it("makes the message the code and nothing else", async () => {
    const response = reply(401, {code: "invalid_credentials"});
    Object.defineProperty(response, "url", {value: "https://panel.example/api/v1/auth/login/password?phone=0912"});
    const e = await apiErrorFromResponse(response);
    expect(e.message).toBe("invalid_credentials");
    expect(JSON.stringify(e)).not.toContain("0912");
    expect(String(e.stack)).not.toContain("0912");
  });

  it("falls back to Retry-After when the body has no figure", async () => {
    expect((await apiErrorFromResponse(reply(429, {code: "rate_limited"}, {"Retry-After": "30"}))).retryAfterS).toBe(30);
    // The body wins when both are there.
    expect((await apiErrorFromResponse(reply(429, {code: "rate_limited", retry_after_s: 5}, {"Retry-After": "30"}))).retryAfterS).toBe(5);
    // An HTTP-date, a negative and an absurd figure are ignored.
    for (const value of ["Wed, 21 Oct 2026 07:28:00 GMT", "-3", "99999999", "1e3"]) {
      expect((await apiErrorFromResponse(reply(429, {code: "rate_limited"}, {"Retry-After": value}))).retryAfterS, value).toBeUndefined();
    }
  });

  it("turns a body that is not Error JSON into unknown and keeps the status", async () => {
    for (const body of ["<html>502 Bad Gateway</html>", "", "[]", "null", '"text"', "{}", '{"code":7}']) {
      const e = await apiErrorFromResponse(reply(502, body));
      expect(e, body).toMatchObject({status: 502, code: "unknown"});
    }
  });

  it("turns a code this client does not know into unknown", async () => {
    expect((await apiErrorFromResponse(reply(409, {code: "brand_new_code", request_id: "r1"}))).code).toBe("unknown");
    expect((await apiErrorFromResponse(reply(409, {code: "constructor"}))).code).toBe("unknown");
  });

  it("drops a request id that is not a plain token, and malformed fields", async () => {
    const e = await apiErrorFromResponse(
      reply(400, {code: "bad_request", request_id: "<script>x</script>", fields: [{name: 1, code: "x"}, "no", null, {name: "a", code: "b"}]}),
    );
    expect(e.requestId).toBeUndefined();
    expect(e.fields).toEqual([{name: "a", code: "b"}]);
  });

  it("takes the request id from X-Request-Id when the body has none", async () => {
    expect((await apiErrorFromResponse(reply(500, "oops", {"X-Request-Id": "hdr-9"}))).requestId).toBe("hdr-9");
  });

  it("leaves the response readable for the next middleware", async () => {
    const response = reply(403, {code: "csrf_rejected"});
    await apiErrorFromResponse(response);
    expect(await response.json()).toEqual({code: "csrf_rejected"});
  });
});

describe("helpers", () => {
  it("maps anything thrown to a message key and its values", () => {
    const e = new ApiError(429, "too_many_attempts", "r", 12);
    expect(errorMessageKey(e)).toBe("too_many_attempts");
    expect(errorMessageArgs(e)).toEqual({retryAfterS: 12});
    expect(errorMessageKey(new TypeError("Failed to fetch"))).toBe("unknown");
    expect(errorMessageArgs("x")).toEqual({retryAfterS: 0});
    expect(errorMessageArgs(new ApiError(500, "internal"))).toEqual({retryAfterS: 0});
  });

  it("tells ApiError by name too, for a second copy of the module", () => {
    const foreign = Object.assign(new Error("x"), {name: "ApiError", code: "not_found"});
    expect(isApiError(foreign)).toBe(true);
    expect(isApiError(new Error("x"))).toBe(false);
    expect(hasCode(new ApiError(404, "not_found"), "conflict", "not_found")).toBe(true);
    expect(hasCode(undefined, "not_found")).toBe(false);
  });

  it("maps fields to codes for a form, first one winning", () => {
    expect(fieldErrors(new ApiError(422, "password_weak", undefined, undefined, [{name: "p", code: "too_short"}, {name: "p", code: "weak"}]))).toEqual({
      p: "too_short",
    });
    expect(fieldErrors(new Error("x"))).toEqual({});
  });
});
