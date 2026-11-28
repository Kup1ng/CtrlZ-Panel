// The bound of a lock password (spec p2 7.1), checked in the browser so that a value that the API would refuse as `too_short` or `too_long`
// is told before a request, and in the same words the API's field code gives.
//
// 6 to 128 code points, counted after NFKC (AUTH 4.2), which is how the server counts, so one code point that NFKC makes eighteen
// (U+FDFA) is counted as eighteen here too. A code point, not a UTF-16 unit: `Array.from` walks code points. The half-space U+200C is
// dropped by the server's normaliser, and so is it here, so a password typed on a Persian keyboard is the same with or without it.
// The check is a courtesy: the API decides.

export const LOCK_PASSWORD_MIN = 6;
export const LOCK_PASSWORD_MAX = 128;
export const LOCK_MESSAGE_MAX = 256;

/** The server's normal form of a lock password, for counting: NFKC, without the zero width non-joiner. */
export function normalizeLockPassword(value: string): string {
  return value.normalize("NFKC").replaceAll("‌", "");
}

export function lockPasswordLength(value: string): number {
  return Array.from(normalizeLockPassword(value)).length;
}

export type LockPasswordProblem = "required" | "too_short" | "too_long";

export function checkLockPassword(value: string): LockPasswordProblem | null {
  if (value === "") return "required";
  const n = lockPasswordLength(value);
  if (n < LOCK_PASSWORD_MIN) return "too_short";
  if (n > LOCK_PASSWORD_MAX) return "too_long";
  return null;
}

/** An unlock password is not bounded from below by the client: a wrong short one is simply wrong. Only the upper bound and emptiness. */
export function checkUnlockPassword(value: string): LockPasswordProblem | null {
  if (value === "") return "required";
  return lockPasswordLength(value) > LOCK_PASSWORD_MAX ? "too_long" : null;
}

export function checkLockMessage(value: string): "too_long" | null {
  return Array.from(value.trim()).length > LOCK_MESSAGE_MAX ? "too_long" : null;
}
