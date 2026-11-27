"use client";

import {errorMessageArgs, fieldErrors, hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useMemo, useRef, useState} from "react";

import {handleApiError, useApiErrorActions} from "../feedback/handleApiError.ts";
import {useErrorText, useFieldErrorText} from "../feedback/errorText.ts";
import {useCountdown} from "./useCountdown.ts";
import {useOnlineStatus} from "./useOnlineStatus.ts";

// Spec 10, "useApiForm". The state every auth form shares: the error that belongs under no field
// (shown by FormError), the messages that belong under a field (`Error.fields` of the answer, or a check
// the page made itself), the focus that follows a failure, and the wait a 429 or a 503 asks for.
//
// A field's message is handed to it by `bind` and goes away when the field is edited (`clearField`).
// The messages come from our i18n and not from the browser's language (`validationBehavior="aria"`).

/** Codes that carry a wait. The submit button stays disabled for `retry_after_s`. */
export const WAIT_CODES = ["rate_limited", "too_many_attempts", "otp_limited", "otp_locked", "server_busy"] as const;

/** Seconds a failed call asks the caller to wait, 0 when it asks for none. */
export function retryAfterOf(error: unknown): number {
  return isApiError(error) && hasCode(error, ...WAIT_CODES) ? errorMessageArgs(error).retryAfterS : 0;
}

/**
 * Names the server gives a field that the pages call by another name: a second factor, whichever kind it is,
 * is the one "code" field of its step, and an invite's token is the "token" field.
 */
const FIELD_ALIASES: Record<string, string> = {totp_code: "code", recovery_code: "code", invite_token: "token"};

export type FailOptions = {
  /**
   * A failure with no `fields` of its own that still belongs to one field (a wrong code is the code's
   * error, not the form's): the message goes under that field.
   */
  field?: string;
  /**
   * The words for `field` when the API's code is too general for them: a wrong recovery code is answered with the
   * authenticator's `totp_invalid`, and its message must not name an app the visitor no longer has (wp8-r24-1).
   */
  message?: string;
  /** The server's field name is not the name the form uses for it. */
  rename?: Record<string, string>;
  /**
   * The failure is shown but does not start the submit wait. For a call that is not the form's own submit
   * (Resend): the earlier code is still valid, so a wait on it must not block Verify (wp8-r3-6). The caller
   * keeps the wait it needs (`useResend` holds the Resend button).
   */
  noWait?: boolean;
  /**
   * What the Retry button of the form's FormError does for this failure, when it is not the form's submit
   * (a failed Resend must resend, not verify the code: wp8-r4-1). `false`: no Retry button, because the
   * caller has its own way to try again (the Resend button, held for the wait).
   */
  retry?: (() => void) | false;
};

/** The Retry action of one failure, for a call that is not the form's submit. */
export type RetryOverride = {run: (() => void) | false};

export function useApiForm(options: {focus?: string; fieldNamespace?: string} = {}) {
  const t = useTranslations("auth");
  const errorText = useErrorText();
  const fieldText = useFieldErrorText(options.fieldNamespace);
  const actions = useApiErrorActions();
  // The form element, kept here and handed out as a callback ref and a focus function: a ref object in
  // the returned value makes every property read of it look like a ref read during render.
  const element = useRef<HTMLFormElement | null>(null);
  const attachForm = useCallback((el: HTMLFormElement | null) => {
    element.current = el;
  }, []);
  const focusField = useCallback((name: string) => {
    element.current?.querySelector<HTMLElement>(`[name="${name}"]`)?.focus();
  }, []);
  const initialFocus = options.focus;
  // A step that has just appeared puts the focus on its first field (a step change is the visitor's own
  // action, so this is not the page-load autofocus that the a11y rule warns about). It happens once per
  // mount: the option may be computed from state the visitor goes on to edit (the login form's target
  // depends on whether a number has been typed), and a target that moved while they typed took the focus
  // out of the field they were in, and sent half a phone number into the password (wp8-r3-1). The target
  // that counts is the first one that has a field on the page: Forgot Password's passkey choice has no
  // form until it is made, and its target appears then.
  const focusedOnce = useRef(false);
  useEffect(() => {
    if (!initialFocus || focusedOnce.current) return;
    const target = element.current?.querySelector<HTMLElement>(`[name="${initialFocus}"]`);
    if (!target) return;
    focusedOnce.current = true;
    target.focus();
  }, [initialFocus]);
  const [formError, setFormError] = useState<unknown>(null);
  const [fieldMessages, setFieldMessages] = useState<Record<string, string[]>>({});
  const [focusTick, setFocusTick] = useState(0);
  const {remaining: retryIn, start: startWait} = useCountdown();
  // The submit button is disabled while a 429 or a busy server asks to wait, and while the browser is offline
  // (10.1). Everything else that can send the form (the sixth digit of a code, the Retry button of FormError)
  // does not pass through that button, so each submit asks this first (wp8-r1-7).
  const online = useOnlineStatus();
  const blocked = retryIn > 0 || !online;

  const [retryOverride, setRetryOverride] = useState<RetryOverride | null>(null);
  // The error whose `fields` are on the page as field messages, until a field is seen to show one (see the
  // focus effect): a name that no field of the page has must not leave the visitor with no message at all.
  const unplaced = useRef<unknown>(null);

  // The field the visitor was in last. The fields are disabled while a call runs and the browser drops the
  // focus to BODY, so a failure that no field owns can only give it back if it was kept: Enter in the
  // password field and a 500 must leave the visitor in the password field, not at the top of the form
  // (wp8-r5-2). Kept as the element and its name, since a step may render the same field again.
  const lastField = useRef<{el: HTMLElement; name: string | null} | null>(null);
  useEffect(() => {
    const onFocusIn = (event: FocusEvent) => {
      const target = event.target;
      if (!(target instanceof HTMLElement) || !element.current?.contains(target)) return;
      if (!target.matches("input, textarea, select")) return;
      lastField.current = {el: target, name: target.getAttribute("name")};
    };
    document.addEventListener("focusin", onFocusIn);
    return () => document.removeEventListener("focusin", onFocusIn);
  }, []);

  // After the error state is on the page: React Aria sets aria-invalid on the field it shows an error for.
  // A failure with no field (a busy server, a 500, a dropped connection) has none, and the fields were
  // disabled while the call ran, which dropped the focus to BODY: the alert is announced, but the next Tab
  // would start at the top of the document. The focus goes to the first enabled field then, unless it is
  // already on something that works (the Retry button that was just pressed) (wp8-r4-2).
  useEffect(() => {
    if (focusTick === 0) return;
    const form = element.current;
    if (!form) return;
    // A Select has no `aria-invalid` anywhere: React Aria marks only its wrapper with `data-invalid`, and the control to focus is the
    // trigger inside it. Without this a server message for a Select (an unpriced primary gateway) was taken for a name no
    // field has and shown as the generic form error (wp10-r3-1).
    const invalid = form.querySelector<HTMLElement>('[aria-invalid="true"]') ?? form.querySelector<HTMLElement>('[data-invalid="true"]');
    const orphan = unplaced.current;
    unplaced.current = null;
    if (invalid) {
      const control = invalid.matches("input, textarea, select, button") ? invalid : invalid.querySelector<HTMLElement>("button, input, textarea, select");
      (control ?? invalid).focus();
      return;
    }
    // The server named fields and none of them is on this page (a password over the length limit on a field
    // the page calls by another name): the messages are taken back and the failure is shown as the form's own,
    // with the focus where it was, instead of nothing at all (wp8-r5-4).
    if (orphan !== null) {
      setFieldMessages({});
      setFormError(orphan);
    }
    const active = document.activeElement;
    if (active && active !== document.body && !(active as HTMLButtonElement).disabled && document.contains(active)) return;
    const enabled = (el: HTMLElement | null | undefined) => (el && !(el as HTMLInputElement).disabled ? el : null);
    const last = lastField.current;
    const back =
      (last && form.contains(last.el) ? enabled(last.el) : null) ??
      (last?.name ? enabled(form.querySelector<HTMLElement>(`[name="${last.name}"]`)) : null) ??
      form.querySelector<HTMLElement>("input:not([type=hidden]):not([disabled]):not([data-account-name]), textarea:not([disabled]), select:not([disabled])");
    // The account-name field of AccountNameField is never a target: it is read-only and only for the password manager.
    back?.focus();
  }, [focusTick]);

  // Messages only. A wait belongs to the answer that asked for it and ends by itself: Resend and a switch
  // to the recovery code clear the messages too, and must not end the wait of a 429 on the submit (wp8-r3-3).
  const clear = useCallback(() => {
    setFormError(null);
    setFieldMessages({});
    setRetryOverride(null);
  }, []);

  /** A message the page found itself, before any request: "enter your number". */
  const setFieldError = useCallback((name: string, message: string) => {
    setFormError(null);
    setRetryOverride(null);
    unplaced.current = null;
    setFieldMessages({[name]: [message]});
    setFocusTick((n) => n + 1);
  }, []);

  /**
   * Shows what a failed call threw. Returns `true` when the error was not the form's to show (the session
   * is over, the account is suspended, the password must change: spec 14.3), and nothing is displayed.
   */
  const fail = useCallback(
    (error: unknown, options: FailOptions = {}): boolean => {
      if (handleApiError(error, actions)) return true;
      // A failure with no wait of its own ends one that is running only when it is a submit's, and a submit
      // is never sent during a wait (`blocked`), so this never cuts a wait short.
      if (!options.noWait) startWait(retryAfterOf(error));
      setRetryOverride(options.retry === undefined ? null : {run: options.retry});

      const entries = Object.entries(fieldErrors(error));
      unplaced.current = entries.length > 0 ? error : null;
      if (entries.length > 0) {
        const next: Record<string, string[]> = {};
        for (const [name, code] of entries) {
          const key = options.rename?.[name] ?? FIELD_ALIASES[name] ?? name;
          // `too_long` is sent by the password routes and has no line in errors.fields. A screen's line for it counts only on the
          // field it names (the admin's OTP template body, one billed part): by code alone it would read on a password too (wp10-r18-1).
          const message = code === "too_long" && !fieldText.hasOwn(code, name) ? t("fields.password.tooLong") : fieldText(code, name);
          (next[key] ??= []).push(message);
        }
        setFormError(null);
        setFieldMessages(next);
      } else if (options.field) {
        setFormError(null);
        setFieldMessages({[options.field]: [options.message ?? errorText(error)]});
      } else {
        setFieldMessages({});
        setFormError(error);
      }
      setFocusTick((n) => n + 1);
      return false;
    },
    [actions, errorText, fieldText, startWait, t],
  );

  const fieldMessage = useCallback((name: string): string | undefined => fieldMessages[name]?.[0], [fieldMessages]);

  /** Drops the message of one field: it was about the value that has just been edited. */
  const clearField = useCallback((name: string) => {
    setFieldMessages((prev) => {
      if (!(name in prev)) return prev;
      const rest = {...prev};
      delete rest[name];
      return rest;
    });
  }, []);

  /**
   * What a field needs from the form: its message, and an `onChange` that stores the value with `set` and
   * removes the message. The fields take the message as `error` and mark themselves invalid with it, so a
   * message the page found itself and one the server sent are shown the same way.
   */
  const bind = useCallback(
    <V,>(name: string, set: (value: V) => void) => ({
      error: fieldMessages[name]?.[0],
      onChange: (value: V) => {
        set(value);
        clearField(name);
      },
    }),
    [fieldMessages, clearField],
  );

  return useMemo(
    () => ({
      /** The `ref` of the `<Form>`. */
      attachForm,
      /** Puts the focus on the field with this `name`. */
      focusField,
      /** For `<FormError error={...}>`. */
      formError,
      /** The Retry action of the failure on show when it is not the submit's: read by `<FormError form={form}>`. */
      retryOverride,
      fieldMessage,
      clearField,
      bind,
      /** Seconds the submit button must still wait (a 429, a busy server), 0 when it need not. */
      retryIn,
      /** True while a submit must not go out: a wait is running, or the browser is offline. */
      blocked,
      fail,
      setFieldError,
      clear,
    }),
    [attachForm, focusField, formError, retryOverride, fieldMessage, clearField, bind, retryIn, blocked, fail, setFieldError, clear],
  );
}

export type ApiForm = ReturnType<typeof useApiForm>;
