"use client";

import {hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {useCallback} from "react";

import {useErrorText} from "../../feedback/errorText.ts";
import {useScreenFieldText} from "../../feedback/useScreenFieldText.ts";

// The words of a refused write of a small form (a folder, a Copy or Move, a group Edit): a 422 `validation_failed` names which value broke
// by its code, and the sentence of that code says more than "one of the values is not valid" (`has_inheriting_rules`, `needs_folder_action`,
// `exists`, `iranian_name`...). Any other error reads as `errors.<code>`.

export function useFormErrorText(): (error: unknown) => string {
  const errorText = useErrorText();
  const fieldText = useScreenFieldText();
  return useCallback(
    (error: unknown) => {
      if (isApiError(error) && hasCode(error, "validation_failed") && (error.fields ?? []).length > 0) {
        const lines: string[] = [];
        for (const field of error.fields ?? []) {
          const line = fieldText(field.code);
          if (!lines.includes(line)) lines.push(line);
        }
        return lines.join(" ");
      }
      return errorText(error);
    },
    [errorText, fieldText],
  );
}
