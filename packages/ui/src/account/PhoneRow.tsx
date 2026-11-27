"use client";

import {fieldErrors, hasCode} from "@ctrlz/api-client/errors.ts";
import type {Me} from "@ctrlz/api-client/session.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {ReauthPanel} from "../auth/ReauthPanel.tsx";
import {useRecoverable} from "../auth/ReauthDialog.tsx";
import {Tech} from "../data/Tech.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {EditorActions} from "../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {InlineEditRow} from "../forms/InlineEditRow.tsx";
import {OTP_LENGTH, OtpField} from "../forms/OtpField.tsx";
import {PhoneField} from "../forms/PhoneField.tsx";
import {ResendTimer} from "../forms/ResendTimer.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {toast} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {accountApi, refreshAccount} from "./accountApi.ts";

// Spec 12.2 (T-110, AUTH 5.6): changing the number takes the password or code again, the new number,
// and a code from each of the two numbers. A typo in one code lets the person retry just that one: the
// server keeps the other code's state, so only the field it names (`old_code` or `new_code`) is cleared.
// Both codes live five minutes, shown as a countdown from `expires_in_s`; after that, or when the number
// turns out to be taken, the person starts again from the number.

type Issued = {id: string; expiresAt: number; resendAt: number};

export function PhoneRow({me}: {me: Me}) {
  const t = useTranslations("account");
  return (
    <InlineEditRow
      id="phone"
      label={t("phone.label")}
      value={<Tech>{me.user.phone_masked}</Tech>}
      editAriaLabel={t("phone.editAria")}
      editor={({close}) => <PhoneEditor me={me} close={close} />}
    />
  );
}

function PhoneEditor({me, close}: {me: Me; close: () => void}) {
  const [stage, setStage] = useState<"reauth" | "number" | "codes">("reauth");
  const [phone, setPhone] = useState("");
  const [issued, setIssued] = useState<Issued | null>(null);
  // Why the person is back at the number (it was taken, the codes ran out): shown by the number step.
  const [notice, setNotice] = useState<unknown>(null);

  if (stage === "reauth") return <ReauthPanel me={me} onDone={() => setStage("number")} onCancel={close} />;
  if (stage === "number" || !issued) {
    return (
      <NumberStep
        phone={phone}
        onPhone={setPhone}
        notice={notice}
        onCancel={close}
        onIssued={(next) => {
          setNotice(null);
          setIssued(next);
          setStage("codes");
        }}
      />
    );
  }
  return (
    <CodesStep
      me={me}
      phone={phone}
      issued={issued}
      onReissued={setIssued}
      onCancel={close}
      onDone={close}
      onRestart={(why) => {
        setNotice(why);
        setIssued(null);
        setStage("number");
      }}
    />
  );
}

function NumberStep({
  phone,
  onPhone,
  notice,
  onIssued,
  onCancel,
}: {
  phone: string;
  onPhone: (value: string) => void;
  notice: unknown;
  onIssued: (issued: Issued) => void;
  onCancel: () => void;
}) {
  const t = useTranslations("account");
  const a = useTranslations("auth");
  const locale = useLocale() === "en" ? "en" : "fa";
  const recover = useRecoverable();
  const form = useApiForm({focus: "new_phone"});
  const [pending, setPending] = useState(false);
  const busy = useRef(false);

  async function submit() {
    if (busy.current || form.blocked) return;
    if (!phone.trim()) return form.setFieldError("new_phone", a("fields.phone.required"));
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      const answer = await recover(() => accountApi.startPhoneChange(phone, locale));
      onIssued({
        id: answer.request_id,
        expiresAt: Date.now() + answer.expires_in_s * 1000,
        resendAt: Date.now() + answer.resend_after_s * 1000,
      });
    } catch (error) {
      if (hasCode(error, "validation_failed") && fieldErrors(error).new_phone === "same_phone") {
        form.setFieldError("new_phone", t("phone.same"));
      } else if (hasCode(error, "invalid_phone", "phone_unavailable")) {
        form.fail(error, {field: "new_phone"});
      } else {
        form.fail(error);
      }
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("phone.text")}</p>
      <PhoneField
        name="new_phone"
        label={t("phone.newLabel")}
        value={phone}
        {...form.bind("new_phone", onPhone)}
        isDisabled={pending}
      />
      <FormError error={form.formError ?? notice} smsDown={t("phone.smsDown")} onRetry={() => void submit()} />
      <OfflineNotice />
      <EditorActions submitLabel={t("phone.sendCodes")} isPending={pending} retryIn={form.retryIn} onCancel={onCancel} />
    </AuthForm>
  );
}

function CodesStep({
  me,
  phone,
  issued,
  onReissued,
  onCancel,
  onDone,
  onRestart,
}: {
  me: Me;
  phone: string;
  issued: Issued;
  onReissued: (issued: Issued) => void;
  onCancel: () => void;
  onDone: () => void;
  onRestart: (why: unknown) => void;
}) {
  const t = useTranslations("account");
  const a = useTranslations("auth");
  const e = useTranslations("errors");
  const locale = useLocale() === "en" ? "en" : "fa";
  const queryClient = useQueryClient();
  const recover = useRecoverable();
  const form = useApiForm({focus: "old_code"});
  const {focusField} = form;
  const [oldCode, setOldCode] = useState("");
  const [newCode, setNewCode] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  const done = useRef(false);
  const left = useSecondsLeft(issued.expiresAt);
  const expired = left <= 0;

  async function submit(codes?: {old?: string; new?: string}) {
    if (busy.current || form.blocked || expired) return;
    const oldValue = codes?.old ?? oldCode;
    const newValue = codes?.new ?? newCode;
    const missing = oldValue.length !== OTP_LENGTH ? "old_code" : newValue.length !== OTP_LENGTH ? "new_code" : null;
    if (missing) return form.setFieldError(missing, a("fields.otp.required"));
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      await accountApi.confirmPhoneChange(issued.id, {old_code: oldValue, new_code: newValue});
      done.current = true;
      // The other sessions and the API tokens ended, and a passkey may have been left by someone else (AUTH 7.7).
      toast.success(me.security.passkeys > 0 ? t("phone.doneWithPasskeys") : t("phone.done"));
      await refreshAccount(queryClient);
      onDone();
    } catch (error) {
      if (hasCode(error, "phone_unavailable", "not_found")) {
        onRestart(error);
        return;
      }
      const named = fieldErrors(error);
      if (hasCode(error, "otp_invalid") && (named.old_code || named.new_code)) {
        // wp9-r1-3: the field's own code says what to do. A code that ran out or was locked cannot be fixed by
        // typing it again, so both fields are cleared and the line points at "Send new codes". A plain wrong
        // code clears only the code the server named; the other one is kept.
        const codes = [named.old_code, named.new_code];
        const gone = codes.includes("locked") || codes.includes("expired");
        if (gone || named.old_code) setOldCode("");
        if (gone || named.new_code) setNewCode("");
        form.setFieldError(
          named.old_code ? "old_code" : "new_code",
          codes.includes("locked") ? t("phone.codeLocked") : codes.includes("expired") ? t("phone.codeExpired") : e("otp_invalid"),
        );
      } else {
        form.fail(error);
      }
    } finally {
      if (!done.current) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  async function resend() {
    if (busy.current || form.blocked) return;
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      const answer = await recover(() => accountApi.startPhoneChange(phone, locale));
      onReissued({
        id: answer.request_id,
        expiresAt: Date.now() + answer.expires_in_s * 1000,
        resendAt: Date.now() + answer.resend_after_s * 1000,
      });
      setOldCode("");
      setNewCode("");
      focusField("old_code");
    } catch (error) {
      form.fail(error, {noWait: true});
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">
        {t.rich("phone.codesText", {
          old: me.user.phone_masked,
          new: phone,
          tech: (chunks) => <Tech>{chunks}</Tech>,
        })}
      </p>
      <OtpField
        name="old_code"
        label={t("phone.oldCode")}
        value={oldCode}
        onChange={form.bind("old_code", setOldCode).onChange}
        onComplete={(code) => (newCode.length === OTP_LENGTH ? void submit({old: code}) : focusField("new_code"))}
        isDisabled={pending || expired}
        errorMessage={form.fieldMessage("old_code")}
      />
      <OtpField
        name="new_code"
        label={t("phone.newCode")}
        value={newCode}
        onChange={form.bind("new_code", setNewCode).onChange}
        onComplete={(code) => (oldCode.length === OTP_LENGTH ? void submit({new: code}) : focusField("old_code"))}
        isDisabled={pending || expired}
        errorMessage={form.fieldMessage("new_code")}
      />
      <CodeLife left={left} />
      <FormError error={form.formError} smsDown={t("phone.smsDown")} onRetry={() => void submit()} />
      <OfflineNotice />
      <EditorActions
        submitLabel={t("phone.confirm")}
        isPending={pending}
        isDisabled={expired}
        retryIn={form.retryIn}
        onCancel={onCancel}
      >
        <ResendTimer
          key={issued.id}
          readyAt={issued.resendAt}
          isDisabled={pending || form.blocked}
          onResend={() => void resend()}
        />
      </EditorActions>
    </AuthForm>
  );
}

/** "Codes expire in 4:32", or the line that says they ran out. Not a live region: a count every second would drown a screen reader. */
function CodeLife({left}: {left: number}) {
  const t = useTranslations("account");
  const {number} = useAppFormat();
  if (left <= 0) {
    return (
      <p role="status" className="text-sm text-(--warning-text)">
        {t("phone.expired")}
      </p>
    );
  }
  const clock = `${number(Math.floor(left / 60))}:${number(left % 60, {minimumIntegerDigits: 2})}`;
  return (
    <p className="text-muted text-xs">
      {t.rich("phone.lifeLeft", {time: clock, tech: (chunks) => <Tech>{chunks}</Tech>})}
    </p>
  );
}

/** Whole seconds until `deadline`, from a deadline and not a count, so a throttled tab shows the right figure when it wakes. */
function useSecondsLeft(deadline: number): number {
  const [now, setNow] = useState(() => Date.now());
  const over = now >= deadline;
  useEffect(() => {
    if (over) return;
    const id = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(id);
  }, [over, deadline]);
  return Math.max(0, Math.ceil((deadline - now) / 1000));
}
