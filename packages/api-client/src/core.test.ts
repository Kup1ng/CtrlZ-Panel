/// <reference types="node" />
import {readFileSync} from "node:fs";
import path from "node:path";

import {describe, expect, it, vi} from "vitest";

import {createApiClient, isRecoverable} from "./core.ts";
import {ApiError, hasCode, isApiError} from "./errors.ts";
import type {paths as AdminPaths} from "./generated/admin";
import type {paths} from "./generated/panel";
import {shouldRetry} from "./queryDefaults.ts";

// Refresh per AUTH 3.4 and 3.5, errors per spec 14.3, and what "CSRF as AUTH
// requires" means for a client: nothing to send, nothing cross-origin.

const BASE = "http://panel.test/api/v1";

const json = (status: number, body?: unknown, headers: Record<string, string> = {}) =>
  new Response(body === undefined ? null : JSON.stringify(body), {status, headers: {"content-type": "application/json", ...headers}});

type Seen = {method: string; path: string; body: string; headers: Headers; request: Request};

/**
 * A fake server: `route` answers by "METHOD /path", and every request is recorded, body included.
 * Its `fetch` is a plain function that throws on any receiver, as the browser's does: a client that
 * calls it as a method of another object ("Illegal invocation") fails every test here, not only one.
 */
function server(route: (seen: Seen, n: number) => Response | Promise<Response>) {
  const seen: Seen[] = [];
  const counts = new Map<string, number>();
  const fetch = async function (this: unknown, request: Request) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
    const url = new URL(request.url);
    const entry: Seen = {
      method: request.method,
      path: url.pathname.replace("/api/v1", ""),
      body: request.body ? await request.clone().text() : "",
      headers: request.headers,
      request,
    };
    seen.push(entry);
    const key = `${entry.method} ${entry.path}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
    return route(entry, counts.get(key)!);
  };
  return {fetch, seen, times: (key: string) => counts.get(key) ?? 0};
}

const expired = () => json(401, {code: "session_expired"});

describe("errors", () => {
  it("throws an ApiError for a non-2xx and returns data for a 2xx", async () => {
    const s = server(({path}) => (path === "/me" ? json(200, {ok: 1}) : json(404, {code: "not_found", request_id: "r-1"})));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch});
    await expect(api.GET("/me")).resolves.toMatchObject({data: {ok: 1}});
    const failure = await api.GET("/account/limits").catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(ApiError);
    expect(failure).toMatchObject({status: 404, code: "not_found", requestId: "r-1"});
  });

  it("returns undefined data for a 204", async () => {
    const api = createApiClient<paths>({baseUrl: BASE, fetch: async () => new Response(null, {status: 204})});
    await expect(api.POST("/auth/logout")).resolves.toMatchObject({data: undefined});
  });

  it("does not turn a network failure into an ApiError, so the retry rule can see it", async () => {
    const api = createApiClient<paths>({baseUrl: BASE, fetch: async () => Promise.reject(new TypeError("Failed to fetch"))});
    const failure = await api.GET("/me").catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(TypeError);
    expect(isApiError(failure)).toBe(false);
    expect(shouldRetry(0, failure)).toBe(true);
  });
});

describe("path parameters (wp4-r13-1)", () => {
  // A value the URL parser would fold must never reach fetch: it changes which route is called.
  it.each(["..", ".", "", "%2e%2e", "%2E", "%252e%252e", ".%2e"])("refuses %j as a path value, with no request", async (bad) => {
    const s = server(() => json(204));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch});
    const calls = [
      api.DELETE("/account/passkeys/{id}", {params: {path: {id: bad}}}),
      api.DELETE("/account/sessions/{id}", {params: {path: {id: bad}}}),
      api.POST("/notifications/{id}/read", {params: {path: {id: bad}}}),
      api.POST("/account/phone/change/{id}/confirm", {params: {path: {id: bad}}, body: {code: "123456"}} as never),
    ];
    for (const call of calls) await expect(call).rejects.toMatchObject({name: "ApiError", status: 400, code: "bad_request"});
    expect(s.seen).toHaveLength(0);
  });

  it("refuses a dot segment in the middle of a nested admin route, and in either position", async () => {
    const s = server(() => json(204));
    const api = createApiClient<AdminPaths>({baseUrl: BASE, fetch: s.fetch, refresh: false});
    const route = "/tenants/{tenant_id}/users/{user_id}/one-time-password" as const;
    await expect(api.POST(route, {params: {path: {tenant_id: "..", user_id: "u1"}}})).rejects.toMatchObject({status: 400, code: "bad_request"});
    await expect(api.POST(route, {params: {path: {tenant_id: "t1", user_id: ""}}})).rejects.toMatchObject({status: 400, code: "bad_request"});
    expect(s.seen).toHaveLength(0);
  });

  it("still sends an ordinary id, and keeps a slash or a dot inside a value in its own segment", async () => {
    const s = server(() => json(204));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch});
    await api.DELETE("/account/passkeys/{id}", {params: {path: {id: "a/b..c.d"}}});
    await api.DELETE("/account/passkeys/{id}", {params: {path: {id: "01HX-abc_9"}}});
    expect(s.seen.map((x) => x.path)).toEqual(["/account/passkeys/a%2Fb..c.d", "/account/passkeys/01HX-abc_9"]);
  });
});

describe("what a request carries (CSRF, AUTH 3.6)", () => {
  it("is same-origin with the cookies the browser holds and nothing of its own", async () => {
    const s = server(() => json(200, {}));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch});
    await api.POST("/auth/login/password", {body: {phone: "0912", password: "x"}});
    const {request, headers} = s.seen[0]!;
    expect(request.credentials).toBe("same-origin");
    expect(request.cache).toBe("no-store");
    expect(headers.get("content-type")).toBe("application/json");
    // No token, no CSRF header, and no Origin: the browser sets that one, and the API compares it with Host.
    for (const name of ["authorization", "origin", "cookie", "x-csrf-token", "x-xsrf-token", "x-ctrlz-ticket"]) {
      expect(headers.has(name), name).toBe(false);
    }
  });

  it("reads a refused cross-origin write as csrf_rejected, and neither refreshes nor repeats it", async () => {
    const s = server(() => json(403, {code: "csrf_rejected"}));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    const e = await api.POST("/account/totp/disable", {body: {}}).catch((x: unknown) => x);
    expect(hasCode(e, "csrf_rejected")).toBe(true);
    expect(s.seen).toHaveLength(1);
  });

  it("is built on a path of this origin: the default base is /api/v1 and no client overrides it", () => {
    const read = (f: string) => readFileSync(path.join(import.meta.dirname, f), "utf8");
    expect(read("core.ts")).toContain('baseUrl = "/api/v1"');
    for (const file of ["client.ts", "admin/client.ts"]) expect(read(file), file).not.toMatch(/baseUrl|https?:\/\//);
  });
});

describe("refresh", () => {
  it("refreshes once on session_expired and repeats the request once, body included", async () => {
    const s = server(({path, body}, n) => {
      if (path === "/auth/refresh") return new Response(null, {status: 204});
      if (path === "/account/phone/change") return n === 1 ? expired() : json(202, {echo: body});
      // The probe: the session is dead, and only the dead session answers the refresh.
      return expired();
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    const result = await api.POST("/account/phone/change", {body: {new_phone: "09120000000"}});
    expect(result.data).toEqual({echo: JSON.stringify({new_phone: "09120000000"})});
    expect(s.seen.map((x) => `${x.method} ${x.path}`)).toEqual([
      "POST /account/phone/change",
      "GET /me",
      "POST /auth/refresh",
      "POST /account/phone/change",
    ]);
    expect(s.seen[1]!.request.credentials).toBe("same-origin");
    expect(s.seen[2]!.request.credentials).toBe("same-origin");
  });

  it("repeats the request after a refresh with the fetch the client was given, never as a method of another object", async () => {
    // The fake fetch of `server` throws on a receiver. This test names the rule: it is the one a browser enforces.
    let live = false;
    const s = server(({path}) => {
      if (path === "/auth/refresh") {
        live = true;
        return new Response(null, {status: 204});
      }
      return live ? json(200, {ok: path}) : expired();
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    await expect(api.PATCH("/account/preferences", {body: {theme: "dark"}})).resolves.toMatchObject({data: {ok: "/account/preferences"}});
    expect(s.times("PATCH /account/preferences")).toBe(2);
  });

  it("asks /me first, and does not refresh when the session is alive: a request that raced a rotation", async () => {
    // The first call carried the old cookie; by the time the client reacts the browser holds the new one.
    // A refresh here would answer 401 without Remember me and clear the live cookie (AUTH 3.5, 3.7).
    const s = server(({path}, n) => (path === "/account/limits" ? (n === 1 ? expired() : json(200, {ok: 1})) : json(200, {tenant: "ok"})));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    await expect(api.GET("/account/limits")).resolves.toMatchObject({data: {ok: 1}});
    expect(s.times("POST /auth/refresh")).toBe(0);
    expect(s.seen.map((x) => `${x.method} ${x.path}`)).toEqual(["GET /account/limits", "GET /me", "GET /account/limits"]);
  });

  it("does not refresh when the probe answers anything but 200 or 401: it says nothing about the session", async () => {
    // A 429 or a 503 on the probe, or a dropped connection, must not lead to the refresh: without
    // Remember me it answers 401 and clears the session cookie a rotation had just made live.
    for (const [label, answer, expected] of [
      ["429", () => json(429, {code: "rate_limited"}, {"Retry-After": "3"}), {status: 429, code: "rate_limited", retryAfterS: 3}],
      ["503", () => json(503, {code: "service_unavailable"}), {status: 503, code: "service_unavailable"}],
    ] as const) {
      const onEnded = vi.fn();
      const s = server(({path}) => (path === "/me" ? answer() : expired()));
      const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {onEnded}});
      const e = await api.GET("/account/limits").catch((x: unknown) => x);
      expect(e, label).toBeInstanceOf(ApiError);
      expect(e, label).toMatchObject(expected);
      expect(s.times("POST /auth/refresh"), label).toBe(0);
      expect(onEnded, label).not.toHaveBeenCalled();
      // The request is not repeated either.
      expect(s.times("GET /account/limits"), label).toBe(1);
    }
    const dropped = server(({path}) => (path === "/me" ? Promise.reject(new TypeError("offline")) : expired()));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: dropped.fetch, refresh: {}});
    expect(await api.GET("/account/limits").catch((x: unknown) => x)).toBeInstanceOf(TypeError);
    expect(dropped.times("POST /auth/refresh")).toBe(0);
  });

  it("recovers on the next 401 after a probe that said nothing", async () => {
    let probeAnswers = 0;
    const s = server(({path}, n) => {
      if (path === "/me") return ++probeAnswers === 1 ? json(503, {code: "service_unavailable"}) : expired();
      if (path === "/auth/refresh") return new Response(null, {status: 204});
      return n <= 2 ? expired() : json(200, {ok: 1});
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    await expect(api.GET("/account/limits")).rejects.toMatchObject({status: 503});
    await expect(api.GET("/account/limits")).resolves.toMatchObject({data: {ok: 1}});
    expect(s.times("POST /auth/refresh")).toBe(1);
  });

  it("shares one probe and one refresh between parallel requests", async () => {
    let live = false;
    const s = server(async ({path}) => {
      if (path === "/auth/refresh") {
        await new Promise((r) => setTimeout(r, 10));
        live = true;
        return new Response(null, {status: 204});
      }
      return live ? json(200, {path}) : expired();
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    await Promise.all([api.GET("/account/limits"), api.GET("/account/sessions"), api.GET("/notifications")]);
    // /me was asked by the probe only, never by the callers here.
    expect(s.times("GET /me")).toBe(1);
    expect(s.times("POST /auth/refresh")).toBe(1);
  });

  it("is single-flight: parallel 401s share one refresh and each repeats once", async () => {
    let live = false;
    const s = server(async ({path}) => {
      if (path === "/auth/refresh") {
        await new Promise((r) => setTimeout(r, 20));
        live = true;
        return new Response(null, {status: 204});
      }
      return live ? json(200, {path}) : expired();
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    const results = await Promise.all([api.GET("/me"), api.GET("/account/sessions"), api.GET("/account/passkeys"), api.GET("/notifications")]);
    expect(results.map((r) => (r.data as unknown as {path: string}).path)).toEqual(["/me", "/account/sessions", "/account/passkeys", "/notifications"]);
    expect(s.times("POST /auth/refresh")).toBe(1);
    // The callers asked /me too, so /me is hit by the caller, by the probe and by the repeat.
    for (const p of ["/account/sessions", "/account/passkeys", "/notifications"]) expect(s.times(`GET ${p}`)).toBe(2);
    expect(s.times("GET /me")).toBe(3);
  });

  it("starts a new refresh for a 401 that arrives after the first one finished", async () => {
    let live = false;
    const s = server(({path}) => {
      if (path === "/auth/refresh") {
        live = true;
        return new Response(null, {status: 204});
      }
      return live ? json(200, {}) : expired();
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    await api.GET("/account/limits");
    live = false;
    await api.GET("/account/sessions");
    expect(s.times("POST /auth/refresh")).toBe(2);
  });

  it("never loops: a repeat that is refused again is the final answer", async () => {
    const s = server(({path}) => (path === "/auth/refresh" ? new Response(null, {status: 204}) : expired()));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    const e = await api.GET("/me").catch((x: unknown) => x);
    expect(hasCode(e, "session_expired")).toBe(true);
    // The request, the probe, the refresh, one repeat, and one more probe (dead). Nothing after that.
    expect(s.seen).toHaveLength(5);
    expect(s.times("POST /auth/refresh")).toBe(1);
  });

  it("probes /me once more when the repeat after a refresh is refused: the other tab's cookie may not be applied yet (wp4-r15-1)", async () => {
    // Tab B: refresh answers 204 with no Set-Cookie (tab A rotated). B's repeat leaves with the old cookie
    // and is refused; by the second look the browser holds the new cookie.
    let applied = false;
    const s = server(({path, body}, n) => {
      if (path === "/auth/refresh") return new Response(null, {status: 204});
      if (path === "/me") return applied ? json(200, {ok: 1}) : expired();
      if (path === "/account/phone/change") {
        if (n === 1) return expired();
        if (applied) return json(202, {echo: body});
        applied = true; // the cookie arrives while the refused repeat is on its way back
        return expired();
      }
      return expired();
    });
    const onEnded = vi.fn();
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {onEnded}});
    const r = await api.POST("/account/phone/change", {body: {new_phone: "09120000000"}});
    expect(r.data).toEqual({echo: JSON.stringify({new_phone: "09120000000"})});
    expect(s.seen.map((x) => `${x.method} ${x.path}`)).toEqual([
      "POST /account/phone/change",
      "GET /me",
      "POST /auth/refresh",
      "POST /account/phone/change",
      "GET /me",
      "POST /account/phone/change",
    ]);
    expect(s.times("POST /auth/refresh")).toBe(1);
    expect(onEnded).not.toHaveBeenCalled();
  });

  it("does not take a probe that said nothing for a dead session after a refused repeat (wp4-r15-1)", async () => {
    let probes = 0;
    const s = server(({path}) => {
      if (path === "/auth/refresh") return new Response(null, {status: 204});
      if (path === "/me") return ++probes === 1 ? expired() : json(503, {code: "service_unavailable"});
      return expired();
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    const e = await api.GET("/account/limits").catch((x: unknown) => x);
    // Not session_expired: the caller must not end the session over a look that failed.
    expect(e).toMatchObject({status: 503, code: "service_unavailable"});
    expect(s.times("GET /account/limits")).toBe(2);
  });

  it("does not look twice when the repeat follows a probe that already said live (wp4-r15-1)", async () => {
    const s = server(({path}) => (path === "/me" ? json(200, {}) : expired()));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    const e = await api.GET("/account/limits").catch((x: unknown) => x);
    expect(hasCode(e, "session_expired")).toBe(true);
    expect(s.times("GET /me")).toBe(1);
    expect(s.times("GET /account/limits")).toBe(2);
  });

  it("ends the session when the refresh itself says 401: onEnded once, the original error thrown", async () => {
    const onEnded = vi.fn();
    const s = server(({path}) => (path === "/auth/refresh" ? expired() : expired()));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {onEnded}});
    const all = await Promise.all([api.GET("/me").catch((x: unknown) => x), api.GET("/account/limits").catch((x: unknown) => x)]);
    for (const e of all) expect(hasCode(e, "session_expired")).toBe(true);
    expect(onEnded).toHaveBeenCalledTimes(1);
    expect(s.times("POST /auth/refresh")).toBe(1);
    // No repeat after an ended session: /me was asked by its caller and by the one probe, the other call once.
    expect(s.times("GET /me")).toBe(2);
    expect(s.times("GET /account/limits")).toBe(1);
  });

  it("does not look like a logout when the refresh fails for another reason", async () => {
    const onEnded = vi.fn();
    const s = server(({path}) => (path === "/auth/refresh" ? json(503, {code: "service_unavailable"}, {"Retry-After": "2"}) : expired()));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {onEnded}});
    const e = await api.GET("/me").catch((x: unknown) => x);
    expect(e).toMatchObject({status: 503, code: "service_unavailable", retryAfterS: 2});
    expect(onEnded).not.toHaveBeenCalled();
    // A 503 is retried by the query layer, so the next call tries to refresh again.
    await api.GET("/me").catch(() => undefined);
    expect(s.times("POST /auth/refresh")).toBe(2);
  });

  it("passes a refresh network error on as a network error", async () => {
    const s = server(({path}) => (path === "/auth/refresh" ? Promise.reject(new TypeError("offline")) : expired()));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    expect(await api.GET("/me").catch((x: unknown) => x)).toBeInstanceOf(TypeError);
  });

  it("leaves /auth/* alone, and any other 401 code", async () => {
    const s = server(({path}) => (path === "/auth/logout" ? expired() : json(401, {code: "invalid_credentials"})));
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    expect(hasCode(await api.POST("/auth/logout").catch((x: unknown) => x), "session_expired")).toBe(true);
    expect(hasCode(await api.POST("/auth/reauth", {body: {password: "x"}}).catch((x: unknown) => x), "invalid_credentials")).toBe(true);
    expect(hasCode(await api.POST("/account/password", {body: {new_password: "x"}}).catch((x: unknown) => x), "invalid_credentials")).toBe(true);
    expect(s.times("POST /auth/refresh")).toBe(0);
  });

  it("recovers the reauth routes: they need a session and nothing else, so a dead cookie is no reason to say the session ended", async () => {
    const s = server(({path}, n) => {
      if (path === "/auth/refresh") return new Response(null, {status: 204});
      if (path === "/auth/reauth") return n === 1 ? expired() : json(200, {reauth_until: "2030-01-01T00:00:00Z"});
      return expired();
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    await api.POST("/auth/reauth", {body: {password: "x"}});
    expect(s.seen.map((x) => `${x.method} ${x.path}`)).toEqual(["POST /auth/reauth", "GET /me", "POST /auth/refresh", "POST /auth/reauth"]);
    expect(s.seen[3]!.body).toBe(JSON.stringify({password: "x"}));
  });

  // The rule is read from the contract, so a route added to /auth/* later cannot fall on the wrong side unnoticed.
  it("recovers exactly the /auth routes that need a session, except the two logouts that run their own loop", () => {
    const text = readFileSync(path.join(import.meta.dirname, "../../../api/openapi.yaml"), "utf8");
    const found: Record<string, string> = {};
    let current = "";
    for (const line of text.split("\n")) {
      const route = /^ {2}(\/\S+):\s*$/.exec(line);
      if (route) current = route[1]!;
      const auth = /x-ctrlz-auth: (\S+)/.exec(line);
      if (auth && current.startsWith("/auth/")) found[current] = auth[1]!;
    }
    expect(Object.keys(found).length).toBeGreaterThan(15);
    for (const [route, auth] of Object.entries(found)) {
      const own = route === "/auth/logout" || route === "/auth/logout-all";
      expect(isRecoverable(route), `${route} (${auth})`).toBe(auth !== "none" && !own);
    }
  });

  it("covers a browser restart: no session cookie is session_expired too, and the refresh cookie rebuilds it", async () => {
    let cookies = "refresh-only";
    const s = server(({path}) => {
      if (path === "/auth/refresh") {
        cookies = "session+refresh";
        return new Response(null, {status: 204});
      }
      return cookies === "refresh-only" ? expired() : json(200, {tenant: "ok"});
    });
    const api = createApiClient<paths>({baseUrl: BASE, fetch: s.fetch, refresh: {}});
    await expect(api.GET("/me")).resolves.toMatchObject({data: {tenant: "ok"}});
  });
});

describe("admin", () => {
  it("has no refresh: a 401 is the answer", async () => {
    const s = server(() => expired());
    const api = createApiClient<AdminPaths>({baseUrl: BASE, fetch: s.fetch, refresh: false});
    const e = await api.GET("/me").catch((x: unknown) => x);
    expect(hasCode(e, "session_expired")).toBe(true);
    expect(s.seen).toHaveLength(1);
  });
});

describe("shouldRetry", () => {
  it("retries a network error and a 503 twice, and never a 4xx or a 500", () => {
    expect(shouldRetry(0, new TypeError("x"))).toBe(true);
    expect(shouldRetry(1, new ApiError(503, "service_unavailable"))).toBe(true);
    expect(shouldRetry(2, new ApiError(503, "service_unavailable"))).toBe(false);
    expect(shouldRetry(2, new TypeError("x"))).toBe(false);
    for (const status of [400, 401, 403, 404, 409, 422, 429, 500, 502]) expect(shouldRetry(0, new ApiError(status, "unknown")), String(status)).toBe(false);
    expect(shouldRetry(0, new Error("x"))).toBe(false);
  });
});
