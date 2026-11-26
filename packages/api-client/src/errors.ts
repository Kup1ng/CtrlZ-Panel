// Spec 14.3. The error body of the API and the one class that carries it.

/**
 * Every code of AUTH 14.3 (both documents), plus `unknown` for a body that is not
 * `Error` JSON or carries a code this client does not know. OpenAPI types
 * `Error.code` as a plain string (open question 9), so `errors.test.ts` compares
 * this list with the Go constants of `internal/httpx` and with the `Errors:` lines
 * of both documents: a code added on the server fails that test until it is added
 * here and in `messages/*\/errors.json`.
 */
export const ERROR_CODES = [
  "bad_request",
  "session_expired",
  "invalid_credentials",
  "otp_invalid",
  "otp_expired",
  "totp_invalid",
  "totp_step_reused",
  "ticket_invalid",
  "passkey_invalid",
  "csrf_rejected",
  "password_change_required",
  "reauth_required",
  "account_suspended",
  "registration_closed",
  "setup_required",
  "totp_fresh_required",
  "not_found",
  "invite_invalid",
  "passkey_unavailable",
  "conflict",
  "phone_unavailable",
  "totp_already_enabled",
  "totp_not_enabled",
  "totp_not_pending",
  "enforce_precondition_failed",
  "password_not_one_time",
  "too_large",
  "validation_failed",
  "invalid_phone",
  "password_weak",
  "rate_limited",
  "too_many_attempts",
  "otp_limited",
  "otp_locked",
  "internal",
  "service_unavailable",
  "server_busy",
  "sms_unavailable",
  "profile_locked",
  "profile_in_use",
  "idempotency_key_reused",
  "job_running",
  "endpoint_held",
  "destinations_lost",
  "token_not_allowed",
  "token_invalid",
  "token_ip_not_allowed",
  "token_read_only",
  "ip_unavailable",
  "ip_suspended",
  "needs_admin_approval",
  "setup_unavailable",
  // P4 nodes (p4-nodes 9.4): the admin routes of the nodes, the pairs, the settings and the certificates. P4_ERROR_CODES names them.
  "fingerprint_mismatch",
  "enrollment_state",
  "key_reused",
  "node_limit_reached",
  "address_refused",
  "table_invalid",
  "node_state",
  "node_paired",
  "node_in_table",
  "second_peer",
  "global_pair_required",
  "pair_in_use",
  "upstream_loop",
  "qps_out_of_range",
  "domain_invalid",
  "transition_active",
  "cert_invalid",
  "cert_key_mismatch",
  "cert_not_public",
  "cert_expiring",
  // Client-only codes, never sent by the API (see CLIENT_ONLY_CODES).
  "unknown",
  "logout_all_incomplete",
] as const;

/**
 * The codes of p4-nodes 9.4. They are in ERROR_CODES above; the list is separate so that the test against internal/httpx can tell a
 * code that the branch of the routes has not yet brought to this tree from a code that is missing here.
 */
export const P4_ERROR_CODES = ["fingerprint_mismatch","enrollment_state","key_reused","node_limit_reached","address_refused","table_invalid","node_state","node_paired","node_in_table","second_peer","global_pair_required","pair_in_use","upstream_loop","qps_out_of_range","domain_invalid","transition_active","cert_invalid","cert_key_mismatch","cert_not_public","cert_expiring"] as const;

/**
 * Codes the client makes up. `unknown` stands for any answer it cannot read.
 * `logout_all_incomplete`: Log out all met a dead session, the refresh that followed was refused, and
 * the browser's cookies are cleared, but the account's other sessions were NOT ended. Saying "session
 * ended" there would hide that; the text asks the user to sign in and repeat it. The tests that compare
 * ERROR_CODES with the server's list leave these out.
 */
export const CLIENT_ONLY_CODES = ["unknown", "logout_all_incomplete"] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

/** Codes of a field error, `Error.fields[].code` (AUTH 4.3 and the phone change routes). */
export const FIELD_ERROR_CODES = [
  "too_short",
  "too_common",
  "contains_phone",
  "repeated",
  "sequence",
  "weak",
  "required",
  "invalid",
  "expired",
  "locked",
] as const;

export type FieldErrorCode = (typeof FIELD_ERROR_CODES)[number];

export type FieldError = {name: string; code: string};

const KNOWN = new Set<string>(ERROR_CODES);

export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === "string" && KNOWN.has(value);
}

/**
 * The message is the code alone: no URL, no body, nothing a console or an error
 * boundary could leak (spec 14.3). `requestId` is what the owner quotes.
 */
export class ApiError extends Error {
  override readonly name = "ApiError";
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    readonly requestId?: string,
    readonly retryAfterS?: number,
    readonly fields?: FieldError[],
  ) {
    super(code);
  }
}

export function isApiError(value: unknown): value is ApiError {
  // `name` as well as `instanceof`: two copies of this module (a test and the app) must still agree.
  return value instanceof ApiError || (value instanceof Error && value.name === "ApiError" && "code" in value);
}

/** True for an `ApiError` with one of `codes`. */
export function hasCode(error: unknown, ...codes: ErrorCode[]): error is ApiError {
  return isApiError(error) && codes.includes(error.code);
}

const MAX_RETRY_S = 86_400;

function cleanSeconds(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= MAX_RETRY_S ? value : undefined;
}

// Retry-After is delta-seconds on our routes. The HTTP-date form is ignored.
function headerSeconds(value: string | null): number | undefined {
  if (value === null || !/^\d{1,6}$/.test(value.trim())) return undefined;
  return cleanSeconds(Number(value));
}

function cleanFields(value: unknown): FieldError[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: FieldError[] = [];
  for (const item of value.slice(0, 32)) {
    if (typeof item !== "object" || item === null) continue;
    const {name, code} = item as Record<string, unknown>;
    if (typeof name === "string" && typeof code === "string" && name.length <= 64 && code.length <= 64) out.push({name, code});
  }
  return out.length > 0 ? out : undefined;
}

/**
 * Builds the `ApiError` of a non-2xx response. A body that is not `Error` JSON, or
 * names a code this client does not know, becomes `unknown`; the status survives.
 * `Retry-After` fills `retryAfterS` when the body lacks it.
 */
export async function apiErrorFromResponse(response: Response): Promise<ApiError> {
  let body: Record<string, unknown> | undefined;
  try {
    const text = await response.clone().text();
    if (text.length <= 65_536) {
      const parsed: unknown = JSON.parse(text);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
    }
  } catch {
    body = undefined;
  }

  const code: ErrorCode = body && isErrorCode(body.code) ? body.code : "unknown";
  const rawId = body && typeof body.request_id === "string" ? body.request_id : response.headers.get("X-Request-Id");
  const requestId = rawId && rawId.length <= 64 && /^[\w.-]+$/.test(rawId) ? rawId : undefined;
  const retryAfterS = cleanSeconds(body?.retry_after_s) ?? headerSeconds(response.headers.get("Retry-After"));
  return new ApiError(response.status, code, requestId, retryAfterS, cleanFields(body?.fields));
}

/**
 * The `errors.<code>` message key for anything thrown by the client. A network
 * failure and any other throw are `unknown` as well: the text for it says "try again".
 */
export function errorMessageKey(error: unknown): ErrorCode {
  return isApiError(error) ? error.code : "unknown";
}

/**
 * The ICU values every `errors.*` message may use. A message with a countdown
 * has an `=0` branch for "no figure", so these are always safe to pass.
 */
export function errorMessageArgs(error: unknown): {retryAfterS: number} {
  return {retryAfterS: isApiError(error) ? (error.retryAfterS ?? 0) : 0};
}

/** Field name to field error code, for `Form validationErrors` (spec 10). */
export function fieldErrors(error: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (isApiError(error)) for (const f of error.fields ?? []) out[f.name] ??= f.code;
  return out;
}
