import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

// The typed code that is not the six digits of an OTP: the recovery code (16, `XXXX-XXXX-XXXX-XXXX`, AUTH 6.5).
// The server strips spaces and hyphens and folds case itself; the client does it too, so what is shown
// is grouped and what is sent is the canonical text, and nothing depends on the server being forgiving.
// The invite is not here: its token is a signed 140-character string that is never typed, so it must not be folded
// (inviteToken.ts, D67).

export const RECOVERY_LENGTH = 16;

// Shown in an empty field. A shape and not a word, so it is the same in both languages and not a message.
export const RECOVERY_PLACEHOLDER = "XXXX-XXXX-XXXX-XXXX";

/** Letters and digits only, upper case, Persian and Arabic digits as ASCII. Anything else is dropped. */
export function canonicalCode(text: string, maxLength: number): string {
  return toAsciiDigits(text)
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, maxLength);
}

/** `ABCD-EFGH-...`, four at a time, for display while the user types. */
export function groupCode(canonical: string): string {
  return canonical.match(/.{1,4}/g)?.join("-") ?? "";
}

export const canonicalRecovery = (text: string) => canonicalCode(text, RECOVERY_LENGTH);

/** A full recovery code, as far as its length can tell. */
export const isFullRecovery = (canonical: string) => canonical.length === RECOVERY_LENGTH;

/** Where the caret goes in `groupCode(canonical)` when `count` canonical characters are before it. */
export function groupedCaret(count: number): number {
  return count > 0 ? count + Math.floor((count - 1) / 4) : 0;
}

/**
 * The `onChange` of a field that shows a code in groups and reports the canonical text. Rewriting the value
 * moves the caret to the end whenever the regrouped text differs from what was typed, so an edit in the
 * middle of a code (fixing one mistyped character of twenty) threw the caret away every time (wp8-r5-3).
 * The caret is counted in canonical characters before it and put back at the same count after the
 * regrouping. It runs in a microtask because React writes the value back at the end of the event, also
 * when the canonical text did not change (a character that was dropped).
 */
export function changeGrouped(text: string, maxLength: number, report: (canonical: string) => void): void {
  const input = typeof document === "undefined" ? null : document.activeElement;
  report(canonicalCode(text, maxLength));
  if (!(input instanceof HTMLInputElement) || input.selectionStart === null) return;
  const before = canonicalCode(text.slice(0, input.selectionStart), maxLength).length;
  queueMicrotask(() => {
    if (document.activeElement !== input) return;
    const at = Math.min(groupedCaret(before), input.value.length);
    input.setSelectionRange(at, at);
  });
}
