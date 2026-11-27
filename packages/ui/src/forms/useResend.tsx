"use client";

import {useTranslations} from "next-intl";
import {useCallback, useDeferredValue, useEffect, useRef, useState, type ReactNode, type RefObject} from "react";

import {ResendTimer} from "./ResendTimer.tsx";
import {retryAfterOf, type ApiForm, type FailOptions} from "./useApiForm.ts";
import {useResendNotice} from "./useResendNotice.tsx";

// "Resend code", once, for every page that has one (Login, Register, Invite, Forgot Password). Its rules
// are the same everywhere, so they are held here and not four times (wp8-r3-3, r3-6):
//
//  - It is a request of its own, charged to the send limit of the visitor's network (AUTH 5.5). It is not
//    sent while the form is blocked (a wait on the submit, or offline), and the button says so.
//  - A 429 on it holds the Resend button for `retry_after_s`. It does not start the form's submit wait: the
//    code that was sent earlier is still valid, and Verify and the sixth digit must keep working.
//  - Whatever the answer, the focus returns to the code field: the keyed timer is replaced on success and on
//    a new hold, and the button that had the focus is gone (wp8-r2-2).
//  - A success says so in a live region (useResendNotice).
//  - `unavailable` (the API now says SMS is down) turns Resend off and says why, and leaves the form alone: the
//    code that was sent is still valid, and a later answer of /auth/config must not take the step away (wp8-r14-1).
//  - A failed Resend still on screen when SMS goes down is taken back: its Retry would do nothing, and the reason
//    line says what the visitor needs (wp8-r15-1). That line is a live region, so it is announced (wp8-r15-2).
//  - The failure is the form's FormError, with a Retry that resends (`retry` of `fail`), and `resending` lets
//    the caller keep "use a different number" off while the request runs, so a late answer cannot take the
//    visitor back to the code step (wp8-r4-3).

export function useResend({
  form,
  busyRef,
  readyAt,
  disabled,
  send,
  onFailure,
  failOptions,
  unavailable = false,
}: {
  form: ApiForm;
  /** Shared with the form's submit: a code is never verified while a new one is being asked for, and back. */
  busyRef: RefObject<boolean>;
  /** When the current challenge lets Resend wake: `Date.now()` plus its `resend_after_s`. */
  readyAt: number;
  /** The submit is running. */
  disabled: boolean;
  /** Asks for a new code and stores it (the caller's challenge changes). Throws what the call threw. */
  send: () => Promise<void>;
  /** True when the caller has dealt with the failure itself (`registration_closed`), so nothing is shown here. */
  onFailure?: (error: unknown) => boolean;
  failOptions?: (error: unknown) => FailOptions;
  /** SMS is down now: Resend is off, with the reason, while Verify keeps working. */
  unavailable?: boolean;
}): {timer: ReactNode; notice: ReactNode; resending: boolean} {
  const t = useTranslations("auth");
  const {focusField, clear, fail, blocked, retryOverride} = form;
  const [resending, setResending] = useState(false);
  // The end of the wait a 429 asked for. The timer wakes at the later of this and the challenge's own time.
  const [holdUntil, setHoldUntil] = useState(0);
  const focusCode = useCallback(() => focusField("code"), [focusField]);
  const {notice, resent} = useResendNotice(focusCode);
  // The Retry button of a failed Resend runs the latest `resend`, not the one of the render that failed.
  const latest = useRef<() => Promise<void>>(async () => {});
  const holdRef = useRef(0);
  useEffect(() => {
    latest.current = resend;
  });

  // Only a failed Resend sets a retry override (a failed submit has none), so this never takes back a Verify error.
  const staleRetry = unavailable && retryOverride !== null;
  useEffect(() => {
    if (staleRetry) clear();
  }, [staleRetry, clear]);

  async function resend() {
    if (busyRef.current || blocked || unavailable || Date.now() < holdRef.current) return;
    busyRef.current = true;
    setResending(true);
    clear();
    try {
      await send();
      resent();
    } catch (error) {
      if (!onFailure?.(error)) {
        const wait = retryAfterOf(error);
        if (wait > 0) {
          holdRef.current = Date.now() + wait * 1000;
          setHoldUntil(holdRef.current);
        }
        // The form's Retry button under this failure asks for the code again (wp8-r4-1). During a hold the
        // Resend button is the retry, with its countdown, so there is none here.
        fail(error, {...failOptions?.(error), noWait: true, retry: wait > 0 ? false : () => void latest.current()});
        focusCode();
      }
    } finally {
      busyRef.current = false;
      setResending(false);
    }
  }

  const wakesAt = Math.max(readyAt, holdUntil);
  const timer = (
    <ResendTimer key={wakesAt} readyAt={wakesAt} onResend={() => void resend()} isPending={resending} isDisabled={disabled || blocked || unavailable} />
  );
  // Always mounted, empty on the first commit and filled in the next render, so a screen reader announces the
  // change the way it does the alert of FormError (wp8-r15-2).
  const reason = useDeferredValue(unavailable, false);
  const withReason = (
    <>
      {notice}
      <p role="status" aria-live="polite" className="text-muted text-center text-xs empty:hidden">
        {reason ? t("resend.smsDown") : null}
      </p>
    </>
  );
  return {timer, notice: withReason, resending};
}
