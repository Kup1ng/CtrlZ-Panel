"use client";

import {ApiError} from "@ctrlz/api-client/errors.ts";
import {passkeyLogin} from "@ctrlz/api-client/webauthn.ts";
import {Button, Link, Spinner} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useRef, useState, type ActionDispatch} from "react";

import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {OtpField, OTP_LENGTH} from "../forms/OtpField.tsx";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useApiForm, type ApiForm} from "../forms/useApiForm.ts";
import {useReportAuthBusy, useReportAuthHolding} from "../forms/useAuthBusy.ts";
import {useResend} from "../forms/useResend.tsx";
import {isPageLeaving} from "../shell/pageLeaving.ts";
import {AuthCard} from "./AuthCard.tsx";
import {authApi, type LoginResult} from "./authApi.ts";
import {useAuthHref} from "./authHref.ts";
import {canonicalRecovery, isFullRecovery} from "./codes.ts";
import {
  loginErrorOutcome,
  resultOutcome,
  type LoginEvent,
  type LoginState,
  type LoginStep,
} from "./loginMachine.ts";
import {SecondFactorField, type SecondFactorMode} from "./SecondFactorInput.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// The steps of the login page that come after the first one (spec 10.2): the SMS code, the second factor
// and the passkey prompt. The first step, with its tabs and links, is in LoginFlow.tsx. Each step gets the
// state, the dispatcher, `applyResult` (what a LoginResult does) and `onError` (the outcome table).

export type LoginDispatch = ActionDispatch<[LoginEvent]>;

export type StepExtras = {
  /** `invalid_credentials`: the caller clears its password. `code`: the caller clears its slots. */
  onInvalidCredentials?: () => void;
  onCode?: () => void;
  /** The line under the code field, when the generic text of the API's code does not fit the field (a recovery code: wp8-r24-1). */
  codeMessage?: string;
};

export type LoginStepProps = {
  state: LoginState;
  dispatch: LoginDispatch;
  /** `false` when a sign-in that went through was dropped because the page is being left (wp8-r10-3): the step is not on its way out. */
  applyResult: (result: LoginResult) => boolean;
  /** The rows of the outcome table of 10.2. */
  onError: (error: unknown, step: LoginStep, form: ApiForm, extras?: StepExtras) => void;
};

export function handleLoginError(
  dispatch: LoginDispatch,
  error: unknown,
  step: LoginStep,
  form: ApiForm,
  extras: StepExtras = {},
): void {
  const outcome = loginErrorOutcome(step, error);
  switch (outcome.kind) {
    case "silent":
      return;
    case "back":
      dispatch({type: "back", to: outcome.to, notice: error});
      return;
    case "passkeyGone":
      dispatch({type: "passkeyGone"});
      return;
    case "suspended":
      dispatch({type: "suspended"});
      return;
    case "invalidCredentials":
      extras.onInvalidCredentials?.();
      form.fail(error);
      return;
    case "code":
      extras.onCode?.();
      form.fail(error, {field: "code", message: extras.codeMessage});
      return;
    case "form":
      form.fail(error);
  }
}

/** The SMS code (`otp-code`). The six digits submit as soon as they are in; Resend asks for a new challenge. */
export function OtpCodeStep({
  state,
  dispatch,
  applyResult,
  onError,
  smsAvailable = true,
}: LoginStepProps & {
  /** False when the API now says SMS is down: Resend is off, the code that was sent still works (wp8-r14-1). */
  smsAvailable?: boolean;
}) {
  const t = useTranslations("auth");
  useReportAuthHolding(true);
  const locale = useLocale() as "fa" | "en";
  const form = useApiForm({focus: "code"});
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  const challenge = state.challenge;
  const {timer: resendTimer, notice: resendNotice, resending} = useResend({
    form,
    busyRef: busy,
    readyAt: challenge?.readyAt ?? 0,
    disabled: pending,
    unavailable: !smsAvailable,
    send: async () => {
      const issued = await authApi.requestOtp({purpose: "login", phone: state.phone, locale});
      setCode("");
      dispatch({type: "otpSent", id: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
    },
  });

  async function submit(ascii: string) {
    if (busy.current || form.blocked || !challenge) return;
    if (ascii.length !== OTP_LENGTH) return form.setFieldError("code", t("fields.otp.required"));
    busy.current = true;
    setPending(true);
    form.clear();
    // A success stays pending until the page changes (wp8-r5-1).
    let leaving = false;
    try {
      leaving = applyResult(
        await authApi.loginOtp({phone: state.phone, challenge_id: challenge.id, code: ascii, remember_me: state.remember}),
      );
    } catch (error) {
      // The slots are cleared; the focus follows aria-invalid (useApiForm), once the field is enabled again.
      onError(error, "otp-code", form, {onCode: () => setCode("")});
    } finally {
      if (!leaving) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthCard title={t("login.otpCode.title")} description={t("login.otpCode.descriptionGeneric")}>
      <AuthForm form={form} onSubmit={() => void submit(code)}>
        <OtpField
          name="code"
          label={t("fields.otp.label")}
          value={code}
          onChange={form.bind("code", setCode).onChange}
          onComplete={(ascii) => void submit(ascii)}
          isDisabled={pending}
          errorMessage={form.fieldMessage("code")}
        />
        {/* The visitor already holds a valid code here, so a failed Resend must not send them to a password they may not have (wp8-r19-1). */}
        <FormError error={form.formError} form={form} smsDown={t("resend.smsDown")} onRetry={() => void submit(code)} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {t("login.otpCode.submit")}
        </SubmitButton>
      </AuthForm>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Button size="sm" variant="ghost" isDisabled={pending || resending} onPress={() => dispatch({type: "back", to: "otp-phone"})}>
          {t("login.otpCode.change")}
        </Button>
        {resendTimer}
      </div>
      {resendNotice}
    </AuthCard>
  );
}

/** Seconds left until `endsAt`, once a second. 0 when it has passed. */
function useSecondsUntil(endsAt: number): number {
  const [left, setLeft] = useState(() => Math.max(0, Math.ceil((endsAt - Date.now()) / 1000)));
  const waiting = left > 0;
  useEffect(() => {
    if (!waiting) return;
    const id = setInterval(() => setLeft(Math.max(0, Math.ceil((endsAt - Date.now()) / 1000))), 500);
    return () => clearInterval(id);
  }, [waiting, endsAt]);
  return left;
}

/** The authenticator code, or a recovery code in its place (`2fa`). The ticket stays in `state` and nowhere else. */
export function TwoFactorStep({state, dispatch, applyResult, onError}: LoginStepProps) {
  const t = useTranslations("auth");
  useReportAuthHolding(true);
  const form = useApiForm();
  const [mode, setMode] = useState<SecondFactorMode>("totp");
  const [totp, setTotp] = useState("");
  const [recovery, setRecovery] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  const ticket = state.ticket;
  // The field of the chosen way takes the focus, at first and after each switch to the recovery code and back.
  const {focusField} = form;
  useEffect(() => focusField(mode === "totp" ? "totp_code" : "recovery_code"), [mode, focusField]);
  const secondsLeft = useSecondsUntil(ticket?.endsAt ?? 0);
  const canRecover = ticket?.methods.includes("recovery_code") ?? false;

  // The ticket is good for a few minutes (AUTH 5.7). When it ends, the page says so and starts over, instead
  // of waiting for the server to refuse a code.
  // Not while a code is on its way: that call may still succeed, and the step must not be left under it. When it
  // fails the form is idle again and this runs then (wp8-r7-3).
  const ended = ticket !== null && secondsLeft === 0;
  useEffect(() => {
    if (ended && !pending) dispatch({type: "back", to: "password", notice: new ApiError(401, "ticket_invalid")});
  }, [ended, pending, dispatch]);

  async function submit(code: string) {
    if (busy.current || form.blocked || !ticket) return;
    busy.current = true;
    setPending(true);
    form.clear();
    let leaving = false;
    try {
      leaving = applyResult(
        await authApi.loginTotp(mode === "totp" ? {ticket: ticket.value, totp_code: code} : {ticket: ticket.value, recovery_code: code}),
      );
    } catch (error) {
      onError(error, "2fa", form, {
        onCode: () => (mode === "totp" ? setTotp("") : setRecovery("")),
        codeMessage: mode === "recovery" ? t("fields.recovery.invalid") : undefined,
      });
    } finally {
      if (!leaving) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  function onFormSubmit() {
    if (mode === "totp") {
      if (totp.length !== OTP_LENGTH) return form.setFieldError("code", t("fields.totp.required"));
      return void submit(totp);
    }
    if (!isFullRecovery(recovery)) return form.setFieldError("code", t("fields.recovery.required"));
    void submit(canonicalRecovery(recovery));
  }

  return (
    <AuthCard
      title={t("login.twoFactor.title")}
      description={mode === "totp" ? t("login.twoFactor.description") : t("login.twoFactor.recoveryDescription")}
    >
      <AuthForm form={form} onSubmit={() => void onFormSubmit()}>
        <SecondFactorField
          mode={mode}
          onModeChange={(next) => {
            form.clear();
            setMode(next);
          }}
          totp={totp}
          onTotp={form.bind("code", setTotp).onChange}
          recovery={recovery}
          onRecovery={form.bind("code", setRecovery).onChange}
          onComplete={(code) => void submit(code)}
          canRecover={canRecover}
          isDisabled={pending}
          errorMessage={form.fieldMessage("code")}
        />
        <FormError error={form.formError} onRetry={onFormSubmit} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {t("login.twoFactor.submit")}
        </SubmitButton>
      </AuthForm>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Button size="sm" variant="ghost" isDisabled={pending} onPress={() => dispatch({type: "back", to: "password"})}>
          {t("login.twoFactor.back")}
        </Button>
        <p className="text-muted text-xs">{t("login.twoFactor.expires", {seconds: secondsLeft})}</p>
      </div>
    </AuthCard>
  );
}

/**
 * The passkey prompt (`passkey`). It starts the browser's ceremony when it appears, once, and "Try again"
 * starts it again. Closing the prompt is silent (spec 10.2); a failed assertion gets the neutral message.
 */
export function PasskeyStep({state, dispatch, applyResult, onError, smsUsable}: LoginStepProps & {smsUsable: boolean}) {
  const t = useTranslations("auth");
  useReportAuthHolding(true);
  const href = useAuthHref();
  const form = useApiForm();
  const [pending, setPending] = useState(false);
  const started = useRef(false);
  const mounted = useRef(true);
  // The ceremony that is running. Leaving the step aborts it: the browser's prompt closes and the requests end
  // with an AbortError, which this step treats like a closed prompt (silent). Without it a prompt that is
  // completed after the visitor left would sign them in under the page they went to (wp8-r6-1, r7-6). "Back"
  // aborts at once. Any other way off the step (the Forgot Password link, the browser's Back) unmounts it, and
  // the cleanup of the effect aborts after a microtask, once a development remount has had its chance to say
  // "still here".
  const ceremony = useRef<AbortController | null>(null);
  const remember = state.remember;
  // The passkey step has no submit button, so it reports its own call (wp8-r9-6).
  useReportAuthBusy(pending);

  async function run() {
    const mine = new AbortController();
    ceremony.current = mine;
    setPending(true);
    form.clear();
    let leaving = false;
    try {
      const result = await passkeyLogin({rememberMe: remember, signal: mine.signal});
      // An answer that outlived its step is not acted on, whichever way it got past the abort. If it opened a
      // session the page can no longer show, the session is ended instead of left in the browser (wp8-r7-6).
      if (mine.signal.aborted || !mounted.current || isPageLeaving()) {
        if (resultOutcome(result).kind === "authenticated") void authApi.dropSession();
        // A step that is still mounted (a language switch that never finished) must not stay on its spinner:
        // "Try again" is there for it (wp8-r10-3). An aborted or unmounted step has nothing to reset.
        return;
      }
      leaving = applyResult(result);
    } catch (error) {
      if (mounted.current && !mine.signal.aborted) onError(error, "passkey", form);
    } finally {
      if (mounted.current && !leaving && !mine.signal.aborted) setPending(false);
    }
  }

  // One ceremony per visit to this step. A development build runs effects twice; the flag keeps the
  // second run from starting a second prompt, and `mounted` keeps the first one's answer from being dropped.
  useEffect(() => {
    mounted.current = true;
    if (!started.current) {
      started.current = true;
      void run();
    }
    return () => {
      mounted.current = false;
      const left = ceremony.current;
      queueMicrotask(() => {
        if (!mounted.current) left?.abort();
      });
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `run` reads the latest props and must not restart the prompt
  }, []);

  return (
    <AuthCard title={t("login.passkeyStep.title")} description={t("login.passkeyStep.description")} focusHeading>
      <div className="flex flex-col gap-4">
        <div role="status" className="text-muted flex items-center justify-center gap-2 text-sm">
          {pending ? (
            <>
              <Spinner size="sm" />
              <span>{t("login.passkeyStep.waiting")}</span>
            </>
          ) : null}
        </div>
        <FormError error={form.formError} />
        <OfflineNotice />
        <PrimaryButton fullWidth isPending={pending} isDisabled={form.blocked} onPress={() => void run()}>
          {form.retryIn > 0 ? t("form.retryIn", {seconds: form.retryIn}) : t("login.passkeyStep.retry")}
        </PrimaryButton>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <Button
            size="sm"
            variant="ghost"
            onPress={() => {
              ceremony.current?.abort();
              dispatch({type: "back", to: "password"});
            }}
          >
            {t("login.passkeyStep.back")}
          </Button>
          {/* The same rule as the first step (10.6): Forgot Password needs a text message, so without SMS there is no link. */}
          {smsUsable ? (
            <Link href={href("/forgot-password")} className="text-sm" isDisabled={pending}>
              {t("login.forgot")}
            </Link>
          ) : null}
        </div>
      </div>
    </AuthCard>
  );
}
