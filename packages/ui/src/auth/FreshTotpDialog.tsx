"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";
import {submitFreshTotp} from "@ctrlz/api-client/admin/fresh.ts";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {callWithRecovery, useApiErrorActions} from "../feedback/handleApiError.ts";
import {AuthForm} from "../forms/AuthForm.tsx";
import {EditorActions} from "../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {OTP_LENGTH, OtpField} from "../forms/OtpField.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {keepFocus} from "../admin/shared/restoreFocus.ts";

// Spec 11.3, T-326. A call the API marks `admin-fresh` answers 403 `totp_fresh_required` outside the five minute
// window that a TOTP code opens. The call is repeated once after the admin proves the code here, through the same
// recovery as the panel's reauth dialog (feedback/handleApiError.ts: `callWithRecovery`, which never loops).
//
// The dialog is state-only, as the spec asks of anything that handles a code: nothing of it is in the address bar.
// One provider for the shell; `useFreshRecoverable()` hands out `run(call)`. Two calls that fail at once share one
// dialog and one answer, so the admin is asked for a code once.

type FreshControl = {ask: () => Promise<boolean>};
const FreshContext = createContext<FreshControl | null>(null);

export function FreshTotpProvider({children}: {children: ReactNode}) {
  const t = useTranslations("admin");
  const [open, setOpen] = useState(false);
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

  // A provider that goes away with a question open answers it, so the call that waits does not hang for ever.
  useEffect(
    () => () => {
      waiting.current?.settle(false);
      waiting.current = null;
    },
    [],
  );

  const control = useMemo(() => ({ask}), [ask]);

  return (
    <FreshContext value={control}>
      {children}
      <DialogFrame isOpen={open} onClose={() => answer(false)} title={t("fresh.title")}>
        {open ? <FreshForm onDone={() => answer(true)} onCancel={() => answer(false)} /> : null}
      </DialogFrame>
    </FreshContext>
  );
}

/** Answers that leave the typed code useless: wrong, already used, or a lockout after which a new one is needed anyway. */
const CODE_SPENT = ["totp_invalid", "totp_step_reused", "too_many_attempts"] as const;

function FreshForm({onDone, onCancel}: {onDone: () => void; onCancel: () => void}) {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  const queryClient = useQueryClient();
  const form = useApiForm({focus: "totp_code"});
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);

  async function submit(override?: string) {
    if (busy.current || form.blocked) return;
    const value = toAsciiDigits(override ?? code);
    if (value.length !== OTP_LENGTH) return form.setFieldError("code", a("fields.totp.required"));
    busy.current = true;
    setPending(true);
    form.clear();
    let done = false;
    try {
      await submitFreshTotp(queryClient, value);
      done = true;
      onDone();
    } catch (error) {
      // Only a code that was refused (or that a lockout will make useless) is emptied. A 503, server_busy, an unknown failure or a
      // dropped connection says nothing about the code, and Retry must resend the same one (wp10-r9-2, as the login does, wp10-r5-1).
      if (hasCode(error, ...CODE_SPENT)) setCode("");
      if (hasCode(error, "totp_invalid", "totp_step_reused")) form.fail(error, {field: "code"});
      else form.fail(error);
    } finally {
      if (!done) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <OtpField
        name="totp_code"
        label={a("fields.totp.label")}
        description={t("fresh.text")}
        value={code}
        onChange={form.bind("code", setCode).onChange}
        onComplete={(full) => void submit(full)}
        isDisabled={pending}
        errorMessage={form.fieldMessage("code")}
      />
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={t("fresh.submit")} isPending={pending} retryIn={form.retryIn} onCancel={onCancel} />
    </AuthForm>
  );
}

/** Opens the dialog and resolves `true` when the admin proved the code, `false` when they gave up. */
export function useFreshTotp(): () => Promise<boolean> {
  const control = useContext(FreshContext);
  if (!control) throw new Error("useFreshTotp needs a FreshTotpProvider");
  return control.ask;
}

/**
 * `run(call)`: the call, and once more after the dialog when it answers `totp_fresh_required` (spec 14.3). Any other
 * global error is acted on as everywhere else; what is still thrown is the screen's to show unless `isHandledError`
 * says it was dealt with.
 */
export function useFreshRecoverable() {
  const freshTotp = useFreshTotp();
  const actions = useApiErrorActions({freshTotp});
  // The actions are a new object every render; the latest one is read when the call fails, so `run` keeps its identity.
  const latest = useRef(actions);
  useEffect(() => {
    latest.current = actions;
  });
  return useCallback(<T,>(call: () => Promise<T>) => callWithRecovery(call, latest.current), []);
}
