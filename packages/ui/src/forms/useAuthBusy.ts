"use client";

import {useEffect, useSyncExternalStore} from "react";

// Whether a sign-in family call is running anywhere on the page. The forms report it through SubmitButton (and the
// passkey step by hand); the corner menu reads it to keep the language switch off, since that switch is a full
// page load and a call that answers during it would open a session behind a blank login page (wp8-r9-6). A count,
// not a flag, so two reporters cannot clear each other, and an unmount lets go of its share.

let count = 0;
const listeners = new Set<() => void>();
const change = (by: number) => {
  count += by;
  for (const listener of listeners) listener();
};

export function useReportAuthBusy(busy: boolean) {
  useEffect(() => {
    if (!busy) return;
    change(1);
    return () => change(-1);
  }, [busy]);
}

export function useAuthBusy(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
    () => count > 0,
    () => false,
  );
}

// Whether a step on the page holds something that a reload would lose: a ticket or an SMS challenge. The language
// switch is a full load, so it would send the visitor back to the first step, cost another SMS and a rate-limit
// slot, and a ticket or challenge is never carried across (wp8-r10-2). The invite page no longer holds the switch at
// its lookup and info steps: it carries a link's code in the destination's fragment instead (wp8-r20-1, see
// useCarryAcrossLocaleSwitch). Its confirm step still holds, because that step has a challenge.
// The corner menu keeps the other language off while any step holds, and says why. Same counting as above.

// Why it holds is said under the language, and the usual reason ("go back to the first step") is false on a step that has no way back
// (the admin's first-run authenticator step, gate-r32-5). Such a step reports `reason: "finish"`; the hint says "back" as soon as one
// holder has a way back, because that sentence is then true for the page.
let held = 0;
let heldNoBack = 0;
const heldListeners = new Set<() => void>();
const changeHeld = (by: number, noBack: boolean) => {
  held += by;
  if (noBack) heldNoBack += by;
  for (const listener of heldListeners) listener();
};

export function useReportAuthHolding(holding: boolean, reason: "back" | "finish" = "back") {
  useEffect(() => {
    if (!holding) return;
    const noBack = reason === "finish";
    changeHeld(1, noBack);
    return () => changeHeld(-1, noBack);
  }, [holding, reason]);
}

/** True when every holding step is one with no way back: the corner menu then says "finish this step". */
export function useAuthHoldingFinishOnly(): boolean {
  return useSyncExternalStore(
    (listener) => {
      heldListeners.add(listener);
      return () => void heldListeners.delete(listener);
    },
    () => held > 0 && held === heldNoBack,
    () => false,
  );
}

export function useAuthHolding(): boolean {
  return useSyncExternalStore(
    (listener) => {
      heldListeners.add(listener);
      return () => void heldListeners.delete(listener);
    },
    () => held > 0,
    () => false,
  );
}
