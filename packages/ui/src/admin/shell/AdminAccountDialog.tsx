"use client";

import {adminAuthApi, refreshAdminMe} from "@ctrlz/api-client/admin/hooks/auth.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";
import {useAdminSession} from "@ctrlz/api-client/admin/session.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {toast} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {EditorActions} from "../../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {hasInvisiblePassword} from "../../forms/invisible.ts";
import {OTP_LENGTH, OtpField} from "../../forms/OtpField.tsx";
import {PasswordField} from "../../forms/PasswordField.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {PasswordMeter} from "../../auth/PasswordMeter.tsx";
import {ADMIN_RULE} from "../../auth/passwordStrength.ts";
import {keepFocus} from "../shared/restoreFocus.ts";

// Spec 13, the Account item of the user menu: a state-only Modal (a password is typed here, so nothing of it is
// in the address bar) with the current password, the new one, the strength meter on the admin rule, and the
// authenticator code whenever `AdminMe` says one is enrolled and the password is not a one-time one.
// `POST /me/password` (AUTH 10.3): the other sessions end and this one rotates.
//
// A missing or wrong code answers `invalid_credentials`, never `totp_invalid`: the API refuses to say that the password
// was right (api/admin-openapi.yaml still lists `totp_invalid` for the route, a Panel contract fix, Plan.md), so there
// is one neutral error and no branch for the other.

export function AdminAccountDialog({isOpen, onClose}: {isOpen: boolean; onClose: () => void}) {
  const t = useTranslations("admin");
  return (
    <DialogFrame isOpen={isOpen} onClose={onClose} title={t("account.title")}>
      {isOpen ? <AccountForm onClose={onClose} /> : null}
    </DialogFrame>
  );
}

function AccountForm({onClose}: {onClose: () => void}) {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  const queryClient = useQueryClient();
  const {me} = useAdminSession();
  // A one-time password is proof enough on its own (the shell is not shown for one, but the rule is the API's).
  const needsCode = me?.totp_enrolled === true && me.must_change_password === false;
  const form = useAdminForm({focus: "current_password"});
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);

  async function submit(override?: string) {
    if (busy.current || form.blocked) return;
    const totp = toAsciiDigits(override ?? code);
    if (!current) return form.setFieldError("current_password", a("fields.password.required"));
    if (!next) return form.setFieldError("new_password", a("fields.password.newRequired"));
    if (hasInvisiblePassword(current) || hasInvisiblePassword(next)) return form.setFieldError(hasInvisiblePassword(current) ? "current_password" : "new_password", a("fields.password.invisible"));
    if (needsCode && totp.length !== OTP_LENGTH) return form.setFieldError("totp_code", a("fields.totp.required"));
    busy.current = true;
    setPending(true);
    form.clear();
    let done = false;
    try {
      await adminAuthApi.changePassword({current_password: current, new_password: next, ...(needsCode ? {totp_code: totp} : {})});
      done = true;
      setCurrent("");
      setNext("");
      setCode("");
      toast.success(t("account.done"));
      void refreshAdminMe(queryClient);
      onClose();
    } catch (error) {
      // The password and the code are spent or wrong: both start again. A weak new password keeps the rest.
      if (hasCode(error, "invalid_credentials", "totp_step_reused")) {
        setCurrent("");
        setCode("");
      } else if (hasCode(error, "password_weak")) {
        setCode("");
      }
      form.fail(error, hasCode(error, "totp_step_reused") ? {field: "totp_code"} : {});
    } finally {
      if (!done) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("account.text")}</p>
      <PasswordField
        name="current_password"
        label={t("account.current")}
        autoComplete="current-password"
        value={current}
        {...form.bind("current_password", setCurrent)}
        isDisabled={pending}
      />
      <div className="flex flex-col gap-2">
        <PasswordField
          name="new_password"
          label={a("fields.password.newLabel")}
          autoComplete="new-password"
          value={next}
          {...form.bind("new_password", setNext)}
          isDisabled={pending}
        />
        <PasswordMeter password={next} rule={ADMIN_RULE} shortText={t("password.short")} />
      </div>
      {needsCode ? (
        <OtpField
          name="totp_code"
          label={a("fields.totp.label")}
          description={t("account.totpHint")}
          value={code}
          onChange={form.bind("totp_code", setCode).onChange}
          onComplete={(full) => (current && next ? void submit(full) : undefined)}
          isDisabled={pending}
          errorMessage={form.fieldMessage("totp_code")}
        />
      ) : null}
      <p className="text-muted text-xs">{t("account.sessionsNote")}</p>
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={t("account.submit")} isPending={pending} retryIn={form.retryIn} onCancel={onClose} />
    </AuthForm>
  );
}
