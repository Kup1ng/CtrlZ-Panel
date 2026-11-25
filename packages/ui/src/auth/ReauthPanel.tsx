"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import type {Me} from "@ctrlz/api-client/session.ts";
import {isWebAuthnCancel, isWebAuthnSupported} from "@ctrlz/api-client/webauthn.ts";
import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {Tech} from "../data/Tech.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {EditorActions} from "../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {hasInvisiblePassword} from "../forms/invisible.ts";
import {OTP_LENGTH, OtpField} from "../forms/OtpField.tsx";
import {PasswordField} from "../forms/PasswordField.tsx";
import {ResendTimer} from "../forms/ResendTimer.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {canonicalRecovery, isFullRecovery} from "./codes.ts";
import {reauthApi, type ReauthOtpIssued, type ReauthProof} from "./reauthApi.ts";
import {canReauthWithPasskey, reauthKind} from "./reauthKind.ts";
import {SecondFactorField, type SecondFactorMode} from "./SecondFactorInput.tsx";
import {useAuthConfig} from "./useAuthConfig.ts";

// Spec 12.1 (T-307): proving the current factors again, in the row that needs it (and, wrapped by
// ReauthDialog, in a dialog when a call answers 403 `reauth_required`). The fields follow what the
// account has, by the table of AUTH 3.5:
//
//   password                    the password
//   password and authenticator  the password and a code, or a recovery code
//   authenticator only          a code, or a recovery code
//   neither                     "Send code", then the SMS code of that request
//   a live passkey              "Use a passkey" as another way, unless a review is pending (AUTH 7.7)
//
// The window itself is the server's. This component keeps nothing of it: `onDone` says the call went
// through, and a later `reauth_required` asks again.
//
// SMS never stands in for a password or an authenticator: that rule is the server's, and the code fields
// exist here only for an account with neither. This panel is the panel app's (the admin has its own fresh
// TOTP, spec 11.3), so its words are in the `account` namespace.

export type ReauthPanelProps = {
  me: Pick<Me, "user" | "security">;
  /** The proof went through. The panel stays busy until its owner removes it. */
  onDone: () => void;
  onCancel?: () => void;
  /** The text of the main button once there is something to send. */
  submitLabel?: string;
};

export function ReauthPanel({me, onDone, onCancel, submitLabel}: ReauthPanelProps) {
  const t = useTranslations("account");
  const a = useTranslations("auth");
  const kind = reauthKind(me);
  const askPassword = kind === "password" || kind === "password_totp";
  const askCode = kind === "password_totp" || kind === "totp";
  const config = useAuthConfig();
  const passkey = canReauthWithPasskey(me, config.passkeyEnabled) && isWebAuthnSupported();

  const form = useApiForm({focus: askPassword ? "password" : askCode ? "totp_code" : undefined});
  const {focusField} = form;
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [recovery, setRecovery] = useState("");
  const [mode, setMode] = useState<SecondFactorMode>("totp");
  const [otp, setOtp] = useState<{challengeId: string; readyAt: number} | null>(null);
  const [otpCode, setOtpCode] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  const done = useRef(false);
  const ceremony = useRef<AbortController | null>(null);

  // A passkey prompt that is still open when the panel goes away must not finish into a closed row.
  useEffect(() => () => ceremony.current?.abort(), []);

  // The field of the other way takes the focus after a switch, and the code field once a code has been sent.
  const shownMode = useRef(mode);
  useEffect(() => {
    if (shownMode.current === mode) return;
    shownMode.current = mode;
    focusField(mode === "totp" ? "totp_code" : "recovery_code");
  }, [mode, focusField]);
  const sentCode = otp?.challengeId;
  useEffect(() => {
    if (sentCode) focusField("otp_code");
  }, [sentCode, focusField]);

  async function run(call: () => Promise<void>, onError: (error: unknown) => void) {
    if (busy.current || form.blocked) return;
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      await call();
    } catch (error) {
      onError(error);
    } finally {
      if (!done.current) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  function finish() {
    done.current = true;
    onDone();
  }

  async function sendCode() {
    await run(
      async () => {
        const issued: ReauthOtpIssued = await reauthApi.requestOtp();
        setOtp({challengeId: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
        setOtpCode("");
      },
      (error) => void form.fail(error),
    );
  }

  async function submit(codeOverride?: string) {
    if (kind === "otp" && !otp) return sendCode();
    if (askPassword) {
      if (!password) return form.setFieldError("password", a("fields.password.required"));
      if (hasInvisiblePassword(password)) return form.setFieldError("password", a("fields.password.invisible"));
    }
    const code = mode === "recovery" ? canonicalRecovery(recovery) : (codeOverride ?? totp);
    if (askCode && mode === "recovery" && !isFullRecovery(code)) return form.setFieldError("code", a("fields.recovery.required"));
    if (askCode && mode === "totp" && code.length !== OTP_LENGTH) return form.setFieldError("code", a("fields.totp.required"));
    const sms = codeOverride ?? otpCode;
    if (kind === "otp" && sms.length !== OTP_LENGTH) return form.setFieldError("otp_code", a("fields.otp.required"));

    const second = mode === "recovery" ? {recovery_code: code} : {totp_code: code};
    const proof: ReauthProof =
      kind === "otp"
        ? {otp_challenge_id: otp!.challengeId, otp_code: sms}
        : kind === "totp"
          ? second
          : kind === "password"
            ? {password}
            : {password, ...second};

    await run(
      async () => {
        await reauthApi.prove(proof);
        finish();
      },
      (error) => {
        if (hasCode(error, "invalid_credentials")) {
          setPassword("");
          form.fail(error, {field: "password"});
        } else if (hasCode(error, "totp_invalid", "totp_step_reused")) {
          if (mode === "recovery") setRecovery("");
          else setTotp("");
          // A wrong recovery code is answered with the authenticator's code, whose text names an app (wp8-r24-1).
          form.fail(error, {field: "code", message: mode === "recovery" && hasCode(error, "totp_invalid") ? a("fields.recovery.invalid") : undefined});
        } else if (hasCode(error, "otp_invalid")) {
          setOtpCode("");
          form.fail(error, {field: "otp_code"});
        } else if (hasCode(error, "otp_expired", "otp_locked")) {
          // The code is dead: back to "Send code", with the reason.
          setOtp(null);
          setOtpCode("");
          form.fail(error);
        } else {
          form.fail(error);
        }
      },
    );
  }

  async function tryPasskey() {
    const controller = new AbortController();
    ceremony.current = controller;
    await run(
      async () => {
        await reauthApi.passkey(controller.signal);
        finish();
      },
      (error) => {
        // Closing the prompt is an answer, not a failure.
        if (isWebAuthnCancel(error) || controller.signal.aborted) return;
        form.fail(error);
      },
    );
  }

  const sendStage = kind === "otp" && !otp;
  const label = sendStage ? t("reauth.send") : (submitLabel ?? t("reauth.submit"));

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">
        {sendStage
          ? t.rich("reauth.textOtp", {phone: me.user.phone_masked, tech: (chunks) => <Tech>{chunks}</Tech>})
          : t("reauth.text")}
      </p>
      {askPassword ? (
        <PasswordField
          name="password"
          autoComplete="current-password"
          value={password}
          {...form.bind("password", setPassword)}
          isDisabled={pending}
        />
      ) : null}
      {askCode ? (
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
          onComplete={(code) => (!askPassword || password ? void submit(code) : undefined)}
          canRecover
          isDisabled={pending}
          errorMessage={form.fieldMessage("code")}
        />
      ) : null}
      {kind === "otp" && otp ? (
        <OtpField
          name="otp_code"
          label={a("fields.otp.label")}
          description={t.rich("reauth.otpSent", {phone: me.user.phone_masked, tech: (chunks) => <Tech>{chunks}</Tech>})}
          value={otpCode}
          onChange={form.bind("otp_code", setOtpCode).onChange}
          onComplete={(code) => void submit(code)}
          isDisabled={pending}
          errorMessage={form.fieldMessage("otp_code")}
        />
      ) : null}
      <FormError error={form.formError} smsDown={t("reauth.smsDown")} onRetry={() => void submit()} />
      <OfflineNotice />
      <EditorActions submitLabel={label} isPending={pending} retryIn={form.retryIn} onCancel={onCancel}>
        {passkey ? (
          <Button variant="outline" isDisabled={pending} onPress={() => void tryPasskey()}>
            {t("reauth.passkey")}
          </Button>
        ) : null}
        {kind === "otp" && otp ? (
          <ResendTimer key={otp.challengeId} readyAt={otp.readyAt} isDisabled={pending || form.blocked} onResend={() => void sendCode()} />
        ) : null}
      </EditorActions>
    </AuthForm>
  );
}
