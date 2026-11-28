"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {meKeys, useSession} from "@ctrlz/api-client/hooks/me.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Button} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {SectionError} from "../feedback/SectionError.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {OTP_LENGTH} from "../forms/OtpField.tsx";
import {hasInvisiblePassword} from "../forms/invisible.ts";
import {PasswordField} from "../forms/PasswordField.tsx";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {LoadingBlock} from "../forms/LoadingBlock.tsx";
import {LogoutDialog} from "../shell/LogoutDialog.tsx";
import {SessionBinding} from "../shell/SessionBinding.tsx";
import {AuthCard} from "./AuthCard.tsx";
import {authApi} from "./authApi.ts";
import {canonicalRecovery, isFullRecovery} from "./codes.ts";
import {PasswordMeter} from "./PasswordMeter.tsx";
import {SecondFactorField, type SecondFactorMode} from "./SecondFactorInput.tsx";

// Spec 10.7. For a `restricted` session (AUTH 3.5): the password was set by an administrator, or expired,
// and nothing but this page, /me and logout works until it is changed. The page is inside (auth), so there
// is no shell and no SessionGate (which would send a restricted session here and show its skeleton for
// ever); it mounts SessionBinding itself, so a refused refresh, another tab's logout and a page restored
// from the back/forward cache all end it like any other signed-in page.
//
// AUTH 4.4 waives the reauth window for this call only when the session was opened with the live one-time
// password. A session opened by an SMS code or a passkey, or one whose one-time password has run out, gets
// 403 `reauth_required`, and `/auth/reauth` is open to a restricted session. The page therefore asks for the
// current password (and the authenticator code, if the account has one) in place, opens the window, and sends
// the new password again, once (wp8-r1-3, r1-12). The reauth dialog of 12.1 belongs to WP9 and is not needed
// here: when WP9 builds the `ReauthPanel` this page may swap this block for it.
//
// `/auth/reauth` takes a recovery code in place of the authenticator code (AUTH 3.5), and the reauth stage offers
// that switch like the sign-in page does (wp8-r12-2). `/account/password` itself takes only the authenticator code, so
// before the server has asked for a reauth there is no switch, and a visitor who has lost the authenticator is told
// the way out (sign out, then Forgot Password with a recovery code) next to Sign out.

export function ChangePasswordPage() {
  const router = useRouter();
  const t = useTranslations("auth");
  const {status, me, error, retry} = useSession();

  // The page is for a restricted session only. Anyone else is somewhere else: signed in and free to go
  // on, or suspended. `anonymous` is left to SessionBinding, which has the refusal that proves it.
  useEffect(() => {
    if (status === "ready") router.replace("/profiles");
    else if (status === "suspended") router.replace("/suspended");
  }, [status, router]);

  return (
    <>
      <SessionBinding />
      {status === "error" ? (
        <SectionError error={error} onRetry={retry} />
      ) : status === "restricted" && me ? (
        <ChangePasswordForm needsTotp={me.security.totp_enabled} />
      ) : (
        <AuthCard title={t("changePassword.title")}>
          <LoadingBlock />
        </AuthCard>
      )}
    </>
  );
}

function ChangePasswordForm({needsTotp}: {needsTotp: boolean}) {
  const t = useTranslations("auth");
  const router = useRouter();
  const queryClient = useQueryClient();
  const form = useApiForm({focus: "new_password"});
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [mode, setMode] = useState<SecondFactorMode>("totp");
  const [recovery, setRecovery] = useState("");
  const [pending, setPending] = useState(false);
  // Log out asks first, like the shell's (T-109): the dialog is the shell's own and ends the session itself.
  const [logoutOpen, setLogoutOpen] = useState(false);
  // The server said `reauth_required`: the current password is asked for, here, before the change is sent again.
  const [needsReauth, setNeedsReauth] = useState(false);
  // The reauth went through and its ten minute window is open: the authenticator code was proved by it and is
  // not asked again, and a failure of the change itself (a weak password) does not repeat the reauth.
  const [fresh, setFresh] = useState(false);
  const [current, setCurrent] = useState("");
  const busy = useRef(false);
  const {focusField} = form;

  // The field appears with the answer of the server, so the focus goes to it then (a step the visitor caused).
  // `fresh` is a dependency because the field also comes back after the window has lapsed (wp8-r2-5).
  useEffect(() => {
    if (needsReauth && !fresh) focusField("reauth_password");
  }, [needsReauth, fresh, focusField]);

  const askCode = needsTotp && !fresh;
  // A recovery code is possible only where the API takes one: the reauth stage.
  const canRecover = askCode && needsReauth;
  const effectiveMode: SecondFactorMode = canRecover ? mode : "totp";

  // The field of the chosen way takes the focus after each switch (not at first: the new password has it).
  const shownMode = useRef(effectiveMode);
  useEffect(() => {
    if (shownMode.current === effectiveMode) return;
    shownMode.current = effectiveMode;
    focusField(effectiveMode === "totp" ? "totp_code" : "recovery_code");
  }, [effectiveMode, focusField]);

  async function submit(totpOverride?: string) {
    if (busy.current || form.blocked) return;
    if (!password) return form.setFieldError("new_password", t("fields.password.newRequired"));
    if (hasInvisiblePassword(password)) return form.setFieldError("new_password", t("fields.password.invisible"));
    const reauthing = needsReauth && !fresh;
    if (reauthing && !current) return form.setFieldError("reauth_password", t("fields.password.required"));
    if (reauthing && hasInvisiblePassword(current)) return form.setFieldError("reauth_password", t("fields.password.invisible"));
    const code = effectiveMode === "recovery" ? canonicalRecovery(recovery) : (totpOverride ?? totp);
    if (askCode && effectiveMode === "recovery" && !isFullRecovery(code)) return form.setFieldError("code", t("fields.recovery.required"));
    if (askCode && effectiveMode === "totp" && code.length !== OTP_LENGTH) return form.setFieldError("code", t("fields.totp.required"));
    busy.current = true;
    setPending(true);
    form.clear();
    let stage: "reauth" | "change" = "change";
    let windowOpen = fresh;
    let done = false;
    try {
      if (reauthing) {
        stage = "reauth";
        await authApi.reauth({
          password: current,
          ...(needsTotp ? (effectiveMode === "recovery" ? {recovery_code: code} : {totp_code: code}) : {}),
        });
        windowOpen = true;
        setFresh(true);
        stage = "change";
      }
      await authApi.changePassword({new_password: password, ...(needsTotp && !windowOpen ? {totp_code: code} : {})});
      // The session is no longer restricted: /me is asked again, and the shell finds a ready user (10.7).
      queryClient.removeQueries({queryKey: meKeys.all});
      done = true;
      router.replace("/profiles");
    } catch (error) {
      if (stage === "change" && hasCode(error, "reauth_required")) {
        // The server says there is no open window, whether this page never opened one or the ten minutes of
        // the one it opened have run out (AUTH 3.5; the page does not keep the time). Either way the answer
        // is the same: ask for the proof again, with its fields, instead of a message with no control
        // (wp8-r2-5, r2-8).
        setFresh(false);
        setNeedsReauth(true);
        setCurrent("");
        // The code of the first try is the one the reauth needs. After a lapsed window it was spent by that
        // reauth (the server refuses a step twice), so a fresh one is asked for.
        if (windowOpen) {
          setTotp("");
          setRecovery("");
        }
      } else if (stage === "reauth" && hasCode(error, "invalid_credentials")) {
        setCurrent("");
        form.fail(error, {field: "reauth_password", message: t("changePassword.reauth.invalid")});
      } else if (hasCode(error, "totp_invalid", "totp_step_reused")) {
        if (effectiveMode === "recovery") setRecovery("");
        else setTotp("");
        form.fail(error, {field: "code", message: effectiveMode === "recovery" ? t("fields.recovery.invalid") : undefined});
      } else {
        // A reauth names `password` for the current password, which this page calls reauth_password.
        form.fail(error, stage === "reauth" ? {rename: {password: "reauth_password"}} : {});
      }
    } finally {
      // A success stays pending until the page changes (wp8-r5-1).
      if (!done) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthCard title={t("changePassword.title")} description={t("changePassword.subtitle")}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <div className="flex flex-col gap-2">
          <PasswordField
            name="new_password"
            label={t("fields.password.newLabel")}
            autoComplete="new-password"
            value={password}
            {...form.bind("new_password", setPassword)}
            isDisabled={pending}
          />
          <PasswordMeter password={password} />
        </div>
        {needsReauth && !fresh ? (
          <PasswordField
            name="reauth_password"
            label={t("changePassword.reauth.passwordLabel")}
            autoComplete="current-password"
            value={current}
            {...form.bind("reauth_password", setCurrent)}
            isDisabled={pending}
            description={t("changePassword.reauth.text")}
          />
        ) : null}
        {askCode ? (
          <SecondFactorField
            mode={effectiveMode}
            onModeChange={(next) => {
              form.clear();
              setMode(next);
            }}
            totp={totp}
            onTotp={form.bind("code", setTotp).onChange}
            recovery={recovery}
            onRecovery={form.bind("code", setRecovery).onChange}
            onComplete={(code) => (password && (!needsReauth || current) ? void submit(code) : undefined)}
            canRecover={canRecover}
            isDisabled={pending}
            errorMessage={form.fieldMessage("code")}
            description={t("changePassword.totpHint")}
          />
        ) : null}
        <FormError error={form.formError} onRetry={() => void submit()} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {needsReauth && !fresh ? t("changePassword.reauth.submit") : t("changePassword.submit")}
        </SubmitButton>
      </AuthForm>
      <div className="flex flex-col items-center gap-2">
        {askCode ? <p className="text-muted text-center text-xs">{t("changePassword.lostAuthenticator")}</p> : null}
        <Button size="sm" variant="ghost" isDisabled={pending} onPress={() => setLogoutOpen(true)}>
          {t("logout")}
        </Button>
      </div>
      <LogoutDialog isOpen={logoutOpen} onOpenChange={setLogoutOpen} />
    </AuthCard>
  );
}
