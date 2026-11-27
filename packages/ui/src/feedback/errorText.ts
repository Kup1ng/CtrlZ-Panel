"use client";

import {errorMessageArgs, errorMessageKey} from "@ctrlz/api-client/errors.ts";
import {useTranslations} from "next-intl";
import {useCallback, useMemo} from "react";

// Spec 14.3. Turns whatever a call threw into the text of `errors.<code>`. A network failure and any
// other throw read as `unknown` ("try again"), so nothing a screen catches can show a raw message,
// a URL or a stack. A message with a countdown has an `=0` branch, so the arguments are always safe.

/** `(error) => text`, bound to the current language. */
export function useErrorText(): (error: unknown) => string {
  const t = useTranslations("errors");
  return useCallback((error: unknown) => t(errorMessageKey(error), errorMessageArgs(error)), [t]);
}

/**
 * Text of one field error code. A screen with codes of its own (the admin app's `admin.fieldErrors`) names that namespace, and
 * its codes are looked up there first, so a code that only one app's API answers never reads as a sentence in the shared
 * `errors.fields` (wp10-r5-2). Then `errors.fields.*`. A code this client has no text for reads as the generic "not
 * valid" line, because showing the code itself would be raw wording.
 */
export function useFieldErrorText(
  namespace?: string,
): ((code: string, field?: string) => string) & {hasOwn: (code: string, field?: string) => boolean} {
  const t = useTranslations("errors");
  const own = useTranslations((namespace ?? "errors") as never) as unknown as {
    has: (key: string) => boolean;
    (key: string): string;
  };
  return useMemo(() => {
    // A code can mean different things on different fields (`too_long` is a password on one route and an SMS template body on
    // another), so the screen's namespace is read by field first (`<namespace>.<field>.<code>`), then by code alone. A line
    // for a code on one field never stands for that code on another (wp10-r18-1).
    const ownKey = (code: string, field?: string): string | null => {
      if (namespace === undefined) return null;
      if (field !== undefined && own.has(`${field}.${code}`)) return `${field}.${code}`;
      return own.has(code) ? code : null;
    };
    const text = (code: string, field?: string) => {
      const key = ownKey(code, field);
      if (key !== null) return own(key);
      const shared = `fields.${code}`;
      return t.has(shared as never) ? t(shared as never) : t("fields.invalid");
    };
    // Whether the screen's own namespace has a line for the code on this field, as against the shared fallback.
    return Object.assign(text, {hasOwn: (code: string, field?: string) => ownKey(code, field) !== null});
  }, [t, own, namespace]);
}
