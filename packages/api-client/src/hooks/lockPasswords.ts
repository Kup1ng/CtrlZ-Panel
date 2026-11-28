import type {components} from "../generated/panel";
import {hasCode, isApiError} from "../errors.ts";

// Spec p3 3.3. A change that takes a locked profile away from an identity (an Endpoint's profile, a schedule window, a client, Hard or
// Soft Disabled, delete, rotate, a claim release, Require Authorized IPs) needs that profile's lock password in the same request:
// `lock_passwords: [{profile_id, password}]`, at most 8.
//
//   - 423 `profile_locked` with a field `/lock_passwords` coded `required`: a password is missing. The answer names no profile, so the
//     screen asks for the password of each locked profile the change involves and sends the request again with them.
//   - 401 `invalid_credentials` with `/lock_passwords/<i>` coded `invalid`: the i-th password is wrong. 429 `too_many_attempts`: a scope is spent.
//   - 409 `conflict`: a profile was locked again between the check and the write. Send it again.
//
// The passwords are secrets: they live in a state-only dialog and in the variables of one mutation (FE 9, 14.4).

export type LockPasswords = components["schemas"]["LockPasswords"];
export type LockPassword = components["schemas"]["LockPassword"];

/** The most passwords one request may carry. */
export const MAX_LOCK_PASSWORDS = 8;

const POINTER = /^\/lock_passwords(?:\/(\d+))?$/;

/** The request was refused because a lock password is missing. */
export function needsLockPasswords(error: unknown): boolean {
  return hasCode(error, "profile_locked") && (error.fields ?? []).some((f) => f.name === "/lock_passwords" && f.code === "required");
}

/** The request was refused with 422 `exceeded` on `/lock_passwords`: it needs more than 8, so no list satisfies it. */
export function tooManyLockPasswords(error: unknown): boolean {
  return hasCode(error, "validation_failed") && (error.fields ?? []).some((f) => f.name === "/lock_passwords" && f.code === "exceeded");
}

/** The index of the password that was wrong (the order in which they were sent), or `null`. */
export function wrongLockPasswordIndex(error: unknown): number | null {
  if (!isApiError(error) || error.code !== "invalid_credentials") return null;
  for (const f of error.fields ?? []) {
    const m = POINTER.exec(f.name);
    if (m?.[1] !== undefined && f.code === "invalid") return Number(m[1]);
  }
  return null;
}

/** A body member for a request: left out when there is none, so an unlocked profile's request carries no `lock_passwords` at all. */
export function withLockPasswords<T extends object>(body: T, passwords: LockPasswords | undefined): T & {lock_passwords?: LockPasswords} {
  return passwords && passwords.length > 0 ? {...body, lock_passwords: passwords} : body;
}
