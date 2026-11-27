"use client";

import {createContext, useCallback, useContext, useEffect, useState, type ReactNode} from "react";

// A dialog whose body can start a call that answers with a one-time secret (a setup link, an Apple profile link) must not be closable while it
// runs, or the answer arrives with no screen and leaves a live link nobody saw (wp9-r1-2). DialogFrame has `isLocked`, but the call is deep in
// the body, so the body says so here: `useLockDialogWhile(pending)` counts it, and the owner of the frame reads `locked`. Outside a
// DialogLockProvider (the share page, which is no dialog) it does nothing.

const Lock = createContext<((delta: number) => void) | null>(null);

/** The count of calls that hold the dialog: `change` goes to DialogLockProvider, `locked` to the frame's `isLocked`. */
export function useDialogLockState() {
  const [count, setCount] = useState(0);
  const change = useCallback((delta: number) => setCount((n) => Math.max(0, n + delta)), []);
  return {locked: count > 0, change};
}

export function DialogLockProvider({change, children}: {change: (delta: number) => void; children: ReactNode}) {
  return <Lock.Provider value={change}>{children}</Lock.Provider>;
}

/** Holds the dialog open while `active`, and lets go when it ends or the component goes. */
export function useLockDialogWhile(active: boolean) {
  const change = useContext(Lock);
  useEffect(() => {
    if (!active || !change) return;
    change(1);
    return () => change(-1);
  }, [active, change]);
}
