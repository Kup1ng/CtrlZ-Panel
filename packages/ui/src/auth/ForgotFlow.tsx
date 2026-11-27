"use client";

import {ApiError, hasCode} from "@ctrlz/api-client/errors.ts";
import {isWebAuthnCancel, isWebAuthnSupported, passkeyResetProof} from "@ctrlz/api-client/webauthn.ts";
import {Link as AppLink} from "@ctrlz/i18n/navigation.ts";
import {Alert, Button, buttonVariants, Link, toast} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useRef, useState, useSyncExternalStore} from "react";

import {AccountNameField} from "../forms/AccountNameField.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {OtpField, OTP_LENGTH} from "../forms/OtpField.tsx";
import {hasInvisiblePassword} from "../forms/invisible.ts";
import {PasswordField} from "../forms/PasswordField.tsx";
import {PhoneField} from "../forms/PhoneField.tsx";
import {useResend} from "../forms/useResend.tsx";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useReportAuthHolding} from "../forms/useAuthBusy.ts";
import {useApiForm} from "../forms/useApiForm.ts";
import {LoadingBlock} from "../forms/LoadingBlock.tsx";
import {AuthCard} from "./AuthCard.tsx";
import {authApi, type Locale, type ResetVerified} from "./authApi.ts";
import {useAuthHref} from "./authHref.ts";
import {canonicalRecovery, isFullRecovery} from "./codes.ts";
import {PasswordMeter} from "./PasswordMeter.tsx";
import {SecondFactorField, type SecondFactorMode} from "./SecondFactorInput.tsx";
import {useAuthConfig} from "./useAuthConfig.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec 10.6 and AUTH 4.4. Four steps: the number, the SMS code, the new password (with the account's second
// factor when it has one), and the result. The page is blocked when SMS is unavailable: the code could not
// arrive, and the notice says to contact the administrator.
//
// The reset ticket is the proof of the first two steps. It lives in state only, five minutes at the server,
// and `ticket_invalid` starts the page again. Step 1 always advances for a well-formed number, known or not
// (AUTH 5.3), so the wording never says a code was sent to an account.

const CONFIG_FAILED = new ApiError(503, "service_unavailable");

type Phase = "phone" | "code" | "new" | "done";

export function ForgotFlow() {
  const t = useTranslations("auth");
  const href = useAuthHref();
  const config = useAuthConfig();
  const [phase, setPhase] = useState<Phase>("phone");
  const [phone, setPhone] = useState("");
  const [challenge, setChallenge] = useState<{id: string; readyAt: number} | null>(null);
  const [verified, setVerified] = useState<ResetVerified | null>(null);
  const [notice, setNotice] = useState<unknown>(null);
  const [deferred, setDeferred] = useState(false);

  // The number step is the only one that sends a text. Once a code was sent or a ticket was issued, a later answer
  // of /auth/config must not take the page away: it would drop the ticket and what was typed (wp8-r14-1).
  if (phase === "phone" && config.status === "loading") {
    return (
      <AuthCard title={t("forgot.title")}>
        <LoadingBlock />
        <p className="text-center text-sm">
          <Link href={href("/login")}>{t("forgot.back")}</Link>
        </p>
      </AuthCard>
    );
  }
  if (phase === "phone" && config.status === "failed") {
    return (
      <AuthCard title={t("forgot.title")}>
        <FormError error={CONFIG_FAILED} onRetry={config.retry} />
        {/* Like every other gated state, so a config that keeps failing is not a dead end (wp8-r21-1). */}
        <p className="text-center text-sm">
          <Link href={href("/login")}>{t("forgot.back")}</Link>
        </p>
      </AuthCard>
    );
  }
  if (phase === "phone" && !config.smsAvailable) {
    return (
      <AuthCard title={t("forgot.unavailableTitle")} description={t("forgot.unavailableText")} focusHeading>
        <div className="flex justify-center text-sm">
          <Link href={href("/login")}>{t("forgot.back")}</Link>
        </div>
      </AuthCard>
    );
  }

  const restart = (error: unknown) => {
    setNotice(error);
    setChallenge(null);
    setVerified(null);
    setPhase("phone");
  };

  switch (phase) {
    case "code":
      return challenge ? (
        <CodeStep
          phone={phone}
          challenge={challenge}
          smsAvailable={config.smsAvailable}
          onChallenge={setChallenge}
          onVerified={(result) => {
            setVerified(result);
            setNotice(null);
            setPhase("new");
          }}
          onRestart={restart}
          onChangeNumber={() => restart(null)}
        />
      ) : null;
    case "new":
      return verified ? (
        <NewPasswordStep
          phone={phone}
          verified={verified}
          onRestart={restart}
          onDone={(wasDeferred) => {
            setDeferred(wasDeferred);
            setPhase("done");
            toast.success(t("forgot.doneToast"));
          }}
        />
      ) : null;
    case "done":
      return (
        <AuthCard title={t("forgot.doneTitle")} description={deferred ? t("forgot.doneDeferred") : t("forgot.doneText")} focusHeading>
          <AppLink href={href("/login")} className={buttonVariants({variant: "primary", fullWidth: true})}>
            {t("forgot.signIn")}
          </AppLink>
        </AuthCard>
      );
    default:
      return (
        <PhoneStep
          phone={phone}
          // The notice belongs to the attempt that has just ended. It goes with the next thing the visitor
          // does, so a failed retry does not show it beside its own error (wp8-r3-2).
          onPhone={(value) => {
            setPhone(value);
            setNotice(null);
          }}
          notice={notice}
          onSend={() => setNotice(null)}
          onSent={(sent) => {
            setChallenge(sent);
            setNotice(null);
            setPhase("code");
          }}
        />
      );
  }
}

function PhoneStep({
  phone,
  onPhone,
  notice,
  onSend,
  onSent,
}: {
  phone: string;
  onPhone: (value: string) => void;
  notice: unknown;
  onSend: () => void;
  onSent: (challenge: {id: string; readyAt: number}) => void;
}) {
  const t = useTranslations("auth");
  const href = useAuthHref();
  const locale = useLocale() as Locale;
  const form = useApiForm({focus: "phone"});
  const [pending, setPending] = useState(false);

  async function submit() {
    if (pending || form.blocked) return;
    if (!phone.trim()) return form.setFieldError("phone", t("fields.phone.required"));
    setPending(true);
    form.clear();
    onSend();
    try {
      const issued = await authApi.requestOtp({purpose: "reset", phone, locale});
      onSent({id: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
    } catch (error) {
      form.fail(error, hasCode(error, "invalid_phone") ? {field: "phone"} : {});
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthCard title={t("forgot.title")} description={t("forgot.subtitle")}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <FormError error={notice} />
        <PhoneField value={phone} {...form.bind("phone", onPhone)} isDisabled={pending} />
        <FormError error={form.formError} smsDown={t("forgot.unavailableText")} onRetry={() => void submit()} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {t("forgot.submit")}
        </SubmitButton>
      </AuthForm>
      <p className="text-center text-sm">
        <Link href={href("/login")}>{t("forgot.back")}</Link>
      </p>
    </AuthCard>
  );
}

function CodeStep({
  phone,
  challenge,
  smsAvailable,
  onChallenge,
  onVerified,
  onRestart,
  onChangeNumber,
}: {
  phone: string;
  challenge: {id: string; readyAt: number};
  /** False when the API now says SMS is down: Resend is off, the code that was sent still verifies. */
  smsAvailable: boolean;
  onChallenge: (challenge: {id: string; readyAt: number}) => void;
  onVerified: (result: ResetVerified) => void;
  onRestart: (error: unknown) => void;
  onChangeNumber: () => void;
}) {
  const t = useTranslations("auth");
  useReportAuthHolding(true);
  const locale = useLocale() as Locale;
  const form = useApiForm({focus: "code"});
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  const {timer: resendTimer, notice: resendNotice, resending} = useResend({
    form,
    busyRef: busy,
    readyAt: challenge.readyAt,
    disabled: pending,
    unavailable: !smsAvailable,
    send: async () => {
      const issued = await authApi.requestOtp({purpose: "reset", phone, locale});
      setCode("");
      onChallenge({id: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
    },
  });

  async function submit(ascii: string) {
    if (busy.current || form.blocked) return;
    if (ascii.length !== OTP_LENGTH) return form.setFieldError("code", t("fields.otp.required"));
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      onVerified(await authApi.resetVerify({phone, challenge_id: challenge.id, code: ascii}));
    } catch (error) {
      if (hasCode(error, "otp_expired", "otp_locked")) onRestart(error);
      else if (hasCode(error, "otp_invalid")) {
        setCode("");
        form.fail(error, {field: "code"});
      } else form.fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  return (
    <AuthCard title={t("forgot.codeTitle")} description={t("forgot.codeDescription")}>
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
        {/* A failed Resend is the only way this step meets sms_unavailable, and the code in hand still works (wp8-r18-2). */}
        <FormError error={form.formError} form={form} smsDown={t("resend.smsDown")} onRetry={() => void submit(code)} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {t("forgot.verify")}
        </SubmitButton>
      </AuthForm>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Button size="sm" variant="ghost" isDisabled={pending || resending} onPress={onChangeNumber}>
          {t("forgot.change")}
        </Button>
        {resendTimer}
      </div>
      {resendNotice}
    </AuthCard>
  );
}

const noopSubscribe = () => () => undefined;

/** Which way the passkey account proves itself: not yet, with the passkey, or by going without it for 72 hours. */
type PasskeyChoice = "choose" | "proven" | "lost";

function NewPasswordStep({
  phone,
  verified,
  onRestart,
  onDone,
}: {
  phone: string;
  verified: ResetVerified;
  onRestart: (error: unknown) => void;
  onDone: (deferred: boolean) => void;
}) {
  const t = useTranslations("auth");
  useReportAuthHolding(true);
  const supportsPasskey = useSyncExternalStore(noopSubscribe, isWebAuthnSupported, () => false);
  const [choice, setChoice] = useState<PasskeyChoice>("choose");
  // The password field takes the focus when the form appears: at once, or after a passkey account has chosen.
  const form = useApiForm({focus: verified.second_factor === "passkey" && choice === "choose" ? undefined : "new_password"});
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<SecondFactorMode>("totp");
  const [totp, setTotp] = useState("");
  const [recovery, setRecovery] = useState("");
  const [pending, setPending] = useState(false);
  // The proof of a passkey gives a new ticket, which replaces the one from the SMS step.
  const [ticket, setTicket] = useState(verified.ticket);
  const busy = useRef(false);
  const secondFactor = verified.second_factor;

  async function proveWithPasskey() {
    // The proof is a request that a 429 can refuse for a while, and each press would send it again (wp8-r3-6).
    if (busy.current || form.blocked) return;
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      setTicket(await passkeyResetProof(ticket));
      setChoice("proven");
    } catch (error) {
      if (isWebAuthnCancel(error)) return;
      if (hasCode(error, "ticket_invalid")) onRestart(error);
      else form.fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  async function submit(totpOverride?: string) {
    if (busy.current || form.blocked) return;
    if (!password) return form.setFieldError("new_password", t("fields.password.newRequired"));
    if (hasInvisiblePassword(password)) return form.setFieldError("new_password", t("fields.password.invisible"));
    let second: {totp_code?: string; recovery_code?: string} = {};
    if (secondFactor === "totp") {
      if (mode === "totp") {
        const value = totpOverride ?? totp;
        if (value.length !== OTP_LENGTH) return form.setFieldError("code", t("fields.totp.required"));
        second = {totp_code: value};
      } else {
        if (!isFullRecovery(recovery)) return form.setFieldError("code", t("fields.recovery.required"));
        second = {recovery_code: canonicalRecovery(recovery)};
      }
    }
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      await authApi.resetComplete({ticket, new_password: password, ...second, ...(choice === "lost" ? {defer_enforce: true} : {})});
      onDone(choice === "lost");
    } catch (error) {
      if (hasCode(error, "ticket_invalid")) onRestart(error);
      else if (hasCode(error, "totp_invalid", "totp_step_reused")) {
        if (mode === "totp") setTotp("");
        else setRecovery("");
        form.fail(error, {field: "code", message: mode === "recovery" ? t("fields.recovery.invalid") : undefined});
      } else form.fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  // The way back to the first step. This step holds the other language off (useReportAuthHolding), and that hint
  // promises "go back to the first step", so the control it names must be on both views (wp8-r11-3).
  // "I lost my passkey" costs 72 hours of password sign-in, so a mistaken press or a found device must not
  // force a new SMS: the choice can be taken back, and what was typed for the other way is dropped (wp8-r22-1).
  function backToChoice() {
    form.clear();
    setPassword("");
    setTotp("");
    setRecovery("");
    setMode("totp");
    setChoice("choose");
  }
  const startOver = (
    <div className="flex flex-wrap gap-2">
      {choice === "lost" ? (
        <Button size="sm" variant="ghost" isDisabled={pending} onPress={backToChoice}>
          {t("forgot.passkeyBack")}
        </Button>
      ) : null}
      <Button size="sm" variant="ghost" isDisabled={pending} onPress={() => onRestart(null)}>
        {t("forgot.change")}
      </Button>
    </div>
  );

  // useApiForm focuses its first target once per mount, so a second visit to the form (lost, back, lost again)
  // would leave the focus on BODY after the pressed button went away. Every view that shows the form needs it,
  // "proven" included: lost, Back, then a passkey proof is a second visit too (wp8-r23-1).
  const focusField = form.focusField;
  useEffect(() => {
    if (choice !== "choose") focusField("new_password");
  }, [choice, focusField]);

  // A passkey account chooses first; the password form appears once it has proved itself or gone without.
  if (secondFactor === "passkey" && choice === "choose") {
    return (
      <AuthCard title={t("forgot.newTitle")} description={t("forgot.passkeyText")} focusHeading>
        <div className="flex flex-col gap-3">
          <FormError
            error={form.formError}
            message={hasCode(form.formError, "passkey_invalid") ? t("forgot.passkeyInvalid") : undefined}
          />
          <OfflineNotice />
          {supportsPasskey ? (
            <PrimaryButton fullWidth isPending={pending} isDisabled={form.blocked} onPress={() => void proveWithPasskey()}>
              {t("forgot.passkeyUse")}
            </PrimaryButton>
          ) : null}
          <Button variant="secondary" fullWidth isDisabled={pending} onPress={() => setChoice("lost")}>
            {t("forgot.passkeyLost")}
          </Button>
          {startOver}
        </div>
      </AuthCard>
    );
  }

  return (
    <AuthCard title={t("forgot.newTitle")} description={t("forgot.newDescription")}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <AccountNameField phone={phone} />
        {choice === "lost" ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Description>{t("forgot.passkeyLostWarning")}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}
        {choice === "proven" ? <p className="text-sm text-(--success-text)">{t("forgot.passkeyProven")}</p> : null}
        <div className="flex flex-col gap-2">
          <PasswordField
            name="new_password"
            label={t("fields.password.newLabel")}
            autoComplete="new-password"
            value={password}
            {...form.bind("new_password", setPassword)}
            isDisabled={pending}
          />
          <PasswordMeter password={password} userInputs={[phone]} />
        </div>
        {secondFactor === "totp" ? (
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
            // The password is the other field of this form: a finished code submits only when it is already there.
            onComplete={(code) => (password ? void submit(code) : undefined)}
            canRecover
            isDisabled={pending}
            errorMessage={form.fieldMessage("code")}
            description={t("forgot.totpDescription")}
          />
        ) : null}
        <FormError error={form.formError} onRetry={() => void submit()} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {choice === "lost" ? t("forgot.submitDeferred") : t("forgot.submit2")}
        </SubmitButton>
      </AuthForm>
      {startOver}
    </AuthCard>
  );
}
