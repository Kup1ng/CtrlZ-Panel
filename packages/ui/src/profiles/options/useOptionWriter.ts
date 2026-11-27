"use client";

import {usePatchOptions, type OptionsPatch} from "@ctrlz/api-client/hooks/options.ts";
import {toast} from "@heroui/react";
import {useCallback} from "react";

import {useErrorText} from "../../feedback/errorText.ts";
import {sendQuietly as sendQuietlyWith} from "./quietly.ts";

// One write of the options, as a row sends it: `PATCH /profiles/{id}/options` with the fields to set and `clear` for the ones to unset.
// The hook already shows the new value at once and puts the old one back on a refusal (optimistic.ts), and a 423 makes the frame read
// the profile again so the lock banner shows (noteLockedProfile).
//
//   send(patch)         resolves to null when it worked, or to the error: for an in-place form, which words it under its own field
//   sendQuietly(patch)  a switch has no field to word it under, so a refusal is a toast; one the app already handled (the session
//                       ended) and a 423 (the banner says it) add nothing. A refusal that comes after the session ended is
//                       not the present person's, so it shows no toast (S2-r2-7).

export function useOptionWriter(profileId: string) {
  const patch = usePatchOptions();
  const errorText = useErrorText();
  const {mutateAsync} = patch;

  const send = useCallback(
    async (body: OptionsPatch): Promise<unknown> => {
      try {
        await mutateAsync({profileId, patch: body});
        return null;
      } catch (error) {
        return error ?? new Error("unknown");
      }
    },
    [mutateAsync, profileId],
  );

  const sendQuietly = useCallback(
    (body: OptionsPatch, failed: string): Promise<boolean> => sendQuietlyWith(send, body, failed, errorText, (message) => void toast.danger(message)),
    [send, errorText],
  );

  return {isPending: patch.isPending, send, sendQuietly};
}
