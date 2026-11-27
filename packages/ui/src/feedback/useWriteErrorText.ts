"use client";

import {hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {useCallback} from "react";

import {useErrorText} from "./errorText.ts";
import {useScreenFieldText} from "./useScreenFieldText.ts";

// The words for a refused write of a Redirect (spec p2 3.6, 9.4). A 422 `validation_failed` says which rule broke in its `fields`, and these three
// codes have a sentence each in `errors.fields` that tells the person what to do. Without this the dialog would only say "one of the values is not
// valid". Any other error reads as it always did, through `errors.<code>`.

const REDIRECT_CODES = new Set(["iranian_name", "location_not_allowed", "no_shared_destination"]);
const SLUG_INDEX = /^\/slugs\/(\d+)(?:\/|$)/;

/**
 * `(error, names?) => text`. `names` are the names of the services of the request in the order they were sent, so that a field `/slugs/3`
 * is said as "<name>: <sentence>".
 */
export function useWriteErrorText(): (error: unknown, names?: readonly string[]) => string {
  const errorText = useErrorText();
  const fieldText = useScreenFieldText();
  return useCallback(
    (error: unknown, names?: readonly string[]) => {
      if (isApiError(error) && hasCode(error, "validation_failed")) {
        const lines: string[] = [];
        for (const field of error.fields ?? []) {
          if (!REDIRECT_CODES.has(field.code)) continue;
          const index = SLUG_INDEX.exec(field.name)?.[1];
          const name = index !== undefined ? names?.[Number(index)] : undefined;
          const line = name ? `${name}: ${fieldText(field.code)}` : fieldText(field.code);
          if (!lines.includes(line)) lines.push(line);
        }
        if (lines.length > 0) return lines.join(" ");
      }
      return errorText(error);
    },
    [errorText, fieldText],
  );
}

