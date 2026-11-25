import createClient, {defaultPathSerializer, type Middleware, type PathSerializer} from "openapi-fetch";

import {ApiError, apiErrorFromResponse} from "./errors.ts";

// Spec 14.2 to 14.4. Both clients (tenant and admin) are made here, so they cannot
// drift apart. The browser talks to its own origin only: `baseUrl` is a path and
// `credentials` is `same-origin`. There is no token to send and no CSRF header to
// add (AUTH 3.6): the cookies are HttpOnly, SameSite, and the API checks `Origin`
// and `Sec-Fetch-Site` itself. The client therefore never sets `Origin`, never
// reads a cookie, and never sends a request cross-origin.

/** Turns every non-2xx answer into an `ApiError`, thrown out of the call (spec 14.3). */
export const errorMiddleware: Middleware = {
  async onResponse({response}) {
    if (response.ok) return undefined;
    throw await apiErrorFromResponse(response);
  },
};

// `live`: the probe found the session alive, so no refresh was needed (see the middleware below).
// `failed.error` is an ApiError for a refused answer, or the network error itself.
type RecoveryResult = {kind: "refreshed"} | {kind: "live"} | {kind: "ended"} | {kind: "failed"; error: unknown};

export type RefreshOptions = {
  /** Runs once when the refresh itself answers 401: the session is over (spec 14.4). */
  onEnded?: () => void;
};

type FetchFn = (input: Request) => Promise<Response>;

/**
 * Calls a fetch function with no receiver. The `options.fetch` that openapi-fetch hands
 * to a middleware is the browser's own `fetch`, and `options.fetch(request)` calls it
 * with `this` set to the options object: Chrome then throws "Illegal invocation". A
 * function passed around as a value and called bare is safe, so every call of a fetch
 * in this file goes through here, and the tests' fake `fetch` throws on any `this`.
 */
function send(fetchFn: FetchFn, request: Request): Promise<Response> {
  return fetchFn(request);
}

/**
 * Whether a 401 `session_expired` of this route is worth recovering. `/auth/*` is skipped as a rule
 * (login, refresh and the like have no session to renew, and logout runs its own loop in
 * `logoutAndLeave`), except the reauth routes: they need a live session and nothing else, so a
 * session cookie that idled out under a Remember me login is the same case as any other route. Left
 * out, a reauth click that raced the recovery would say "session ended" while the refresh cookie
 * was alive. The match is on the path prefix, so a reauth route added later is covered.
 */
export function isRecoverable(schemaPath: string): boolean {
  return !schemaPath.startsWith("/auth/") || schemaPath.startsWith("/auth/reauth");
}

/**
 * AUTH 3.4 and 3.5. On 401 `session_expired`, except for `/auth/*` (see `isRecoverable`):
 * one recovery per tab however many requests are waiting, then the original
 * request once more, from the clone kept in `onRequest` since a body is consumed on
 * send. The repeat never goes through the middleware again, so there is no loop. A
 * missing session cookie gives the same code, so this one rule also covers a browser
 * restart with Remember me.
 *
 * The recovery is a probe, then a refresh. The probe is a `GET /me` that does not go
 * through the middleware: a 401 can come from a request that was sent with the old
 * cookie just before a rotation (reauth, TOTP or password change, AUTH 3.7), and the
 * browser then already holds the new one. A refresh in that state does harm: without
 * Remember me there is no refresh cookie, so it answers 401 and clears the live session
 * cookie as well (AUTH 3.5). `/me` is safe to repeat, so asking it first costs one
 * request when the session really expired and saves the session when it did not.
 *
 * A 204 without `Set-Cookie` is the concurrent-tab case (AUTH 3.4): another
 * tab's response set the cookies, so the repeat works all the same. Nothing orders that
 * Set-Cookie before this tab's repeat, so a repeat after a refresh that still answers
 * `session_expired` gets one more probe (wp4-r15-1), and a live probe one more repeat.
 */
export function createRefreshMiddleware({onEnded}: RefreshOptions = {}): Middleware {
  const spare = new WeakMap<Request, Request>();
  let inFlight: Promise<RecoveryResult> | null = null;

  /**
   * The probe answers three ways, and only two of them say anything about the session: 200 means
   * live, 401 means dead. Any other answer (429, 5xx, a dropped connection) says nothing, so the
   * recovery stops there and fails like a refresh that was refused for another reason. Going on
   * to the refresh would be the harmful step: without Remember me it answers 401 and clears a
   * session cookie that a rotation had just made live. Nothing is cleared, and a dead cookie is
   * still recoverable by the next 401.
   */
  async function probe(baseUrl: string, fetchFn: FetchFn): Promise<"live" | "dead" | {error: unknown}> {
    try {
      const response = await send(fetchFn, new Request(`${baseUrl}/me`, {method: "GET", credentials: "same-origin", cache: "no-store"}));
      if (response.ok) return "live";
      if (response.status === 401) return "dead";
      return {error: await apiErrorFromResponse(response)};
    } catch (error) {
      return {error};
    }
  }

  function recoverOnce(baseUrl: string, fetchFn: FetchFn): Promise<RecoveryResult> {
    inFlight ??= (async (): Promise<RecoveryResult> => {
      try {
        const probed = await probe(baseUrl, fetchFn);
        if (probed === "live") return {kind: "live"};
        if (probed !== "dead") return {kind: "failed", error: probed.error};
        const response = await send(
          fetchFn,
          new Request(`${baseUrl}/auth/refresh`, {method: "POST", credentials: "same-origin", cache: "no-store"}),
        );
        if (response.ok) return {kind: "refreshed"};
        if (response.status === 401) {
          onEnded?.();
          return {kind: "ended"};
        }
        // 429, 5xx: the session may well be alive. Say so, and do not look like a logout.
        return {kind: "failed", error: await apiErrorFromResponse(response)};
      } finally {
        inFlight = null;
      }
    })();
    return inFlight;
  }

  return {
    onRequest({request, schemaPath}) {
      if (isRecoverable(schemaPath)) spare.set(request, request.clone());
      return undefined;
    },
    async onResponse({request, response, schemaPath, options}) {
      if (response.status !== 401 || !isRecoverable(schemaPath)) return undefined;
      const again = spare.get(request);
      if (!again) return undefined;
      spare.delete(request);

      if ((await apiErrorFromResponse(response)).code !== "session_expired") return undefined;

      const fetchFn = options.fetch as FetchFn;
      const result = await recoverOnce(options.baseUrl, fetchFn);
      if (result.kind === "failed") throw result.error;
      // Ended: the 401 goes on to the error middleware as it is. Otherwise repeat once.
      if (result.kind === "ended") return undefined;
      // The second repeat is cut before the first goes out: a body is consumed on send.
      const second = result.kind === "refreshed" ? again.clone() : undefined;
      const repeated = await send(fetchFn, again);
      if (!second || repeated.status !== 401) return repeated;
      if ((await apiErrorFromResponse(repeated.clone())).code !== "session_expired") return repeated;

      // A 204 from the refresh may carry no Set-Cookie: another tab rotated first and this tab's repeat
      // can leave before that tab's cookies are applied (AUTH 3.4). `/me` is the probe, so it is still
      // "one retry, never a loop": one more look, and a live answer earns one more repeat. A dead or
      // unreadable answer leaves the 401 as it was. The 401 ends the session in the caller, so a probe
      // that said nothing (429, 5xx, offline) must not be read as dead: it is thrown, nothing is ended.
      const again2 = await probe(options.baseUrl, fetchFn);
      if (again2 === "live") return send(fetchFn, second);
      if (again2 !== "dead") throw again2.error;
      return repeated;
    },
    onError({request}) {
      spare.delete(request);
      return undefined;
    },
  };
}

function isDotSegment(segment: string): boolean {
  let value = segment;
  // Decode until stable: `%2e%2e` and `%252e%252e` are both seen for what they could become.
  for (let i = 0; i < 4; i++) {
    if (value === "" || value === "." || value === "..") return true;
    let next: string;
    try {
      next = decodeURIComponent(value);
    } catch {
      return false;
    }
    if (next === value) return false;
    value = next;
  }
  return false;
}

/**
 * openapi-fetch encodes a path value with encodeURIComponent, which leaves `.` and `..` alone, and
 * `new Request` then folds them, so `rule_id: ".."` would climb out of its route template (wp4-r13-1).
 * The check runs on the built path, not on the values, so a parameter of any style (array, object) is
 * covered by the same rule: every segment after the leading slash must be a real segment.
 */
export const safePathSerializer: PathSerializer = (pathname, pathParams) => {
  // openapi-fetch hands over baseUrl and template together, so the origin of a test's absolute baseUrl is cut off first.
  const built = defaultPathSerializer(pathname, pathParams);
  const path = built.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, "");
  for (const segment of path.split("/").slice(1)) {
    if (isDotSegment(segment)) throw new ApiError(400, "bad_request");
  }
  return built;
};

export type ApiClientOptions = {
  /** A path on this origin. Tests pass an absolute URL together with their own `fetch`. */
  baseUrl?: string;
  fetch?: FetchFn;
  /** Admin has no refresh (spec 14.2). */
  refresh?: false | RefreshOptions;
};

export function createApiClient<Paths extends object>({baseUrl = "/api/v1", fetch, refresh}: ApiClientOptions = {}) {
  const client = createClient<Paths>({
    baseUrl,
    pathSerializer: safePathSerializer,
    credentials: "same-origin",
    // Answers carry a session. Never from or into an HTTP cache: TanStack Query is the cache.
    cache: "no-store",
    ...(fetch ? {fetch} : {}),
  });
  // Responses run in reverse order, so the refresh sees the 401 before it becomes an error.
  client.use(errorMiddleware);
  if (refresh !== undefined && refresh !== false) client.use(createRefreshMiddleware(refresh));
  return client;
}

/**
 * The body of a success. The error middleware has already thrown for a non-2xx,
 * so `data` is missing only on a 204 or on a server that broke its own schema.
 */
export function required<T>(result: {data?: T}): T {
  if (result.data === undefined) throw new ApiError(502, "unknown");
  return result.data;
}
