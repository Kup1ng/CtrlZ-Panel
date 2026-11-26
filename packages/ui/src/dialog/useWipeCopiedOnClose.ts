"use client";

import {wipeCopiedSecret} from "@ctrlz/api-client/clipboard.ts";
import {useEffect} from "react";

/**
 * Overwrites what Copy put in the clipboard when the dialog that offered it goes away, whichever way it goes (the Close button, Escape, the
 * confirmation, a leave of the page): the cleanup of an effect runs for all of them, in the same task as the press that closed it, which is
 * the moment Safari and Chrome still allow a clipboard write (gate-r5-8). It does nothing when nothing was copied.
 */
export function useWipeCopiedOnClose() {
  useEffect(
    () => () => {
      void wipeCopiedSecret();
    },
    [],
  );
}
