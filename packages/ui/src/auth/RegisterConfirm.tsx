"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {Alert, Button} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useRef, useState, type ReactNode} from "react";

import {AccountNameField} from "../forms/AccountNameField.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {OtpField, OTP_LENGTH} from "../forms/OtpField.tsx";
import {hasInvisiblePassword} from "../forms/invisible.ts";
import {PasswordField} from "../forms/PasswordField.tsx";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useReportAuthHolding} from "../forms/useAuthBusy.ts";
import {useApiForm} from "../forms/useApiForm.ts";
import {useResend} from "../forms/useResend.tsx";
import {AuthCard} from "./AuthCard.tsx";
import {authApi, type Locale} from "./authApi.ts";
import {PasswordMeter} from "./PasswordMeter.tsx";
import {useCompleteSignIn} from "./useCompleteSignIn.ts";

// The last step of registration and of an invite (10.4 step 2, 10.5 step 3): the SMS code, a password
// that is recommended and not required, the meter, and the call that creates the account. The two pages
// differ only in who the account is for (a typed number, or an invite token) and in the words.

export type Identity = {kind: "phone"; phone: string} | {kind: "invite"; token: string};
export type Challenge = {id: string; readyAt: number};

export function RegisterConfirm({
  identity,
  challenge,
  onChallenge,
  onRestart,
  onClosed,
  title,
  description,
  submitLabel,
  secondary,
  userInputs,
  smsAvailable = true,
}: {
  identity: Identity;
  challenge: Challenge;
  onChallenge: (challenge: Challenge) => void;
  /** `otp_expired` and `otp_locked`: the caller goes back to the step that asks for a code, showing the error. */
  onRestart: (error: unknown) => void;
  /** `registration_closed` or `invite_invalid` while submitting: the door shut in the meantime. */
  onClosed: (error: unknown) => void;
  title: ReactNode;
  description: ReactNode;
  submitLabel: string;
  /** A button under the form: "use a different number", "try another code". */
  secondary?: {label: string; onPress: () => void};
  /** What the password must not resemble, for the meter. */
  userInputs?: readonly string[];
  /** False when the API now says SMS is down: Resend is off, the code that was sent still works. */
  smsAvailable?: boolean;
}) {
  const t = useTranslations("auth");
  useReportAuthHolding(true);
  const locale = useLocale() as Locale;
  const form = useApiForm({focus: "code"});
  const finish = useCompleteSignIn();
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  const {timer: resendTimer, notice: resendNotice, resending} = useResend({
    form,
    busyRef: busy,
    readyAt: challenge.readyAt,
    disabled: pending,
    unavailable: !smsAvailable,
    send: async () => {
      const issued = await authApi.requestOtp(
        identity.kind === "phone"
          ? {purpose: "signup", phone: identity.phone, locale}
          : {purpose: "invite", invite_token: identity.token, locale},
      );
      setCode("");
      onChallenge({id: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
    },
    onFailure: (error) => {
      if (!hasCode(error, "registration_closed", "invite_invalid")) return false;
      onClosed(error);
      return true;
    },
    failOptions: (error) => (hasCode(error, "invalid_phone") ? {field: "code"} : {}),
  });

  async function submit() {
    if (busy.current || form.blocked) return;
    if (code.length !== OTP_LENGTH) return form.setFieldError("code", t("fields.otp.required"));
    if (hasInvisiblePassword(password)) return form.setFieldError("password", t("fields.password.invisible"));
    busy.current = true;
    setPending(true);
    form.clear();
    // A created account stays pending until the page changes: a second submit would reuse the spent
    // challenge, and the page would call a success a wrong code (wp8-r5-1).
    let leaving = false;
    try {
      // An empty password is left out of the body: the account is OTP-only (AUTH 5.6), and the warning
      // below has said what that costs.
      const common = {challenge_id: challenge.id, code, locale, ...(password ? {password} : {})};
      await authApi.register(identity.kind === "phone" ? {phone: identity.phone, ...common} : {invite_token: identity.token, ...common});
      leaving = finish();
    } catch (error) {
      if (hasCode(error, "otp_expired", "otp_locked")) onRestart(error);
      else if (hasCode(error, "registration_closed", "invite_invalid")) onClosed(error);
      // A weak password names `password` in `fields` and keeps the code (AUTH 5.6 checks the password
      // first, so the code was not spent). A wrong code goes under the code and empties it.
      else if (hasCode(error, "otp_invalid")) {
        setCode("");
        form.fail(error, {field: "code"});
      } else form.fail(error);
    } finally {
      if (!leaving) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthCard title={title} description={description}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        {identity.kind === "phone" ? <AccountNameField phone={identity.phone} /> : null}
        <OtpField
          name="code"
          label={t("fields.otp.label")}
          value={code}
          onChange={form.bind("code", setCode).onChange}
          // The code is one of two fields here, so completing it moves on to the password and does not submit.
          onComplete={() => form.focusField("password")}
          isDisabled={pending}
          errorMessage={form.fieldMessage("code")}
        />
        <div className="flex flex-col gap-2">
          <PasswordField
            name="password"
            label={t("fields.password.label")}
            autoComplete="new-password"
            value={password}
            {...form.bind("password", setPassword)}
            isDisabled={pending}
            description={t("register.passwordHint")}
          />
          <PasswordMeter password={password} userInputs={userInputs} />
        </div>
        {password === "" ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Description>{t("register.noPassword")}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}
        {/* This step holds a code the visitor already has, and the only text it can send is a Resend. So the line is
            the one that says the code still works, not the flow's advice for the first send (wp8-r18-2). */}
        <FormError error={form.formError} form={form} smsDown={t("resend.smsDown")} onRetry={() => void submit()} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {submitLabel}
        </SubmitButton>
      </AuthForm>
      <div className="flex flex-wrap items-center justify-between gap-2">
        {secondary ? (
          <Button size="sm" variant="ghost" isDisabled={pending || resending} onPress={secondary.onPress}>
            {secondary.label}
          </Button>
        ) : (
          <span />
        )}
        {resendTimer}
      </div>
      {resendNotice}
    </AuthCard>
  );
}
