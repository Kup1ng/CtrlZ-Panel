"use client";

import {useMe} from "@ctrlz/api-client/hooks/me.ts";
import {useTranslations} from "next-intl";
import {createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {callWithRecovery, useApiErrorActions} from "../feedback/handleApiError.ts";
import {ReauthPanel} from "./ReauthPanel.tsx";

// Spec 12.1 and 14.3. A call that answers 403 `reauth_required` (the ten minute window ended while a
// row was open, or a newer session is being ended) opens this dialog, and the call is repeated once
// when the person proved themselves. The dialog is state-only, as the spec asks of anything that
// holds a secret: nothing of it is in the address bar.
//
// One provider per page that can meet the error. `useRecoverable` hands out `run(call)`, which is
// `callWithRecovery` bound to the router, the session and this dialog.

type ReauthControl = {ask: () => Promise<boolean>};
const ReauthContext = createContext<ReauthControl | null>(null);

export function ReauthProvider({children}: {children: ReactNode}) {
  const t = useTranslations("account");
  const {data: me} = useMe();
  const [open, setOpen] = useState(false);
  // Two calls that fail at once share one dialog and one answer.
  const waiting = useRef<{promise: Promise<boolean>; settle: (ok: boolean) => void} | null>(null);

  const ask = useCallback(() => {
    if (!waiting.current) {
      let settle: (ok: boolean) => void = () => undefined;
      const promise = new Promise<boolean>((resolve) => {
        settle = resolve;
      });
      waiting.current = {promise, settle};
      setOpen(true);
    }
    return waiting.current.promise;
  }, []);

  const answer = useCallback((ok: boolean) => {
    waiting.current?.settle(ok);
    waiting.current = null;
    setOpen(false);
  }, []);

  const control = useMemo(() => ({ask}), [ask]);

  return (
    <ReauthContext value={control}>
      {children}
      <DialogFrame isOpen={open} onClose={() => answer(false)} title={t("reauth.title")}>
        {open && me ? <ReauthPanel me={me} onDone={() => answer(true)} onCancel={() => answer(false)} submitLabel={t("reauth.confirm")} /> : null}
      </DialogFrame>
    </ReauthContext>
  );
}

/** Opens the dialog and resolves `true` when the person proved themselves, `false` when they gave up. */
export function useReauth(): () => Promise<boolean> {
  const control = useContext(ReauthContext);
  if (!control) throw new Error("useReauth needs a ReauthProvider");
  return control.ask;
}

/**
 * `run(call)`: the call, and once more after a reauth when it answers `reauth_required` (spec 14.3). Any
 * other global error is acted on as everywhere else; what is still thrown is the screen's to show unless
 * `isHandledError` says it was dealt with.
 */
export function useRecoverable() {
  const reauth = useReauth();
  const actions = useApiErrorActions({reauth});
  // The actions are a new object every render; the latest one is read when the call fails, so `run` keeps its identity.
  const latest = useRef(actions);
  useEffect(() => {
    latest.current = actions;
  });
  return useCallback(<T,>(call: () => Promise<T>) => callWithRecovery(call, latest.current), []);
}
