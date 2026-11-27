"use client";

import {createContext, useContext, useEffect, useMemo, useState, type ReactNode} from "react";

// A setup link, or an Apple profile link, is made by a call whose answer is shown once, from state, and nowhere else (S7-r2-2, S7-r2-9). The panel that
// makes it says here whether the call is running (`pending`) and whether the link is on screen (`shown`); the flow around it reads that to refuse a
// step that would unmount the panel while the answer is on its way, and to ask before one that would drop a link nobody copied yet. A client picker
// above the flow reads it too, because a change of client reloads the whole flow.
//
// Outside a scope (a test that draws one panel) the context is empty and nothing is held.

export type SecretHold = {pending: boolean; shown: boolean};
export const NO_HOLD: SecretHold = {pending: false, shown: false};

type Value = {hold: SecretHold; report: (hold: SecretHold) => void};
const Context = createContext<Value>({hold: NO_HOLD, report: () => {}});

export function SecretHoldScope({children}: {children: ReactNode}) {
  const [hold, report] = useState<SecretHold>(NO_HOLD);
  const value = useMemo(() => ({hold, report}), [hold]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export const useSecretHold = (): SecretHold => useContext(Context).hold;

/** Tells the scope what this panel holds, and that it holds nothing once it is gone. */
export function useReportSecretHold(pending: boolean, shown: boolean) {
  const {report} = useContext(Context);
  useEffect(() => {
    report({pending, shown});
    return () => report(NO_HOLD);
  }, [report, pending, shown]);
}
