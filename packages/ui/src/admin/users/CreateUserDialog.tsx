"use client";

import {useCreateUser, userKeys} from "@ctrlz/api-client/admin/hooks/users.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {Alert} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {isLocale, type Locale} from "@ctrlz/i18n/locale.ts";
import {answerMayBeLost} from "../../account/accountApi.ts";
import {useLeaveGuard} from "../../dialog/useLeaveGuard.ts";
import {UrlModal} from "../../dialog/UrlModal.tsx";
import type {UrlDialog} from "../../dialog/useUrlDialog.ts";
import {useErrorText} from "../../feedback/errorText.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {EditorActions} from "../../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {PhoneField} from "../../forms/PhoneField.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useLocale, useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {stripDialogParam} from "../shared/dialogUrl.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {LocaleSegment} from "../shared/LocaleSegment.tsx";
import {OneTimeResult} from "../shared/OneTimeResult.tsx";
import {createButton, keepFocus} from "../shared/restoreFocus.ts";

// Spec 13.1. `POST /users {phone, locale}`: a user with a one-time password, which works with no SMS gateway. The form is
// bound to `?dialog=createUser`. On success the parameter leaves the address (in place, see dialogUrl.ts) and the
// one-time password is shown ONCE in a state-only panel: it is held in this component's state and in nothing else, and
// the mutation is reset so the cache keeps no copy.

export function CreateUserDialog({dialog}: {dialog: UrlDialog}) {
  const t = useTranslations("admin");
  const open = dialog.value === "createUser";
  const [result, setResult] = useState<{phone: string; password: string} | null>(null);
  // The POST is in flight: its answer carries a password that exists and cannot be shown again, so the dialog stays (gate-r32-6).
  const [busy, setBusy] = useState(false);

  return (
    <>
      <UrlModal dialog={dialog} isOpen={open} isLocked={busy} title={t("users.create.title")}>
        {open ? <CreateForm onClose={dialog.close} onBusy={setBusy} onCreated={(phone, password) => setResult({phone, password})} /> : null}
      </UrlModal>
      {result ? (
        <OneTimeResult
          title={t("users.result.title")}
          intro={t("users.result.intro")}
          values={[{id: "password", label: t("users.result.password"), value: result.password, copyLabel: t("users.result.copy")}]}
          onClose={() => setResult(null)}
          returnFocus={() => createButton(t("users.create.open"))}
        />
      ) : null}
    </>
  );
}

function CreateForm({
  onClose,
  onBusy,
  onCreated,
}: {
  onClose: () => void;
  onBusy: (busy: boolean) => void;
  onCreated: (phone: string, password: string) => void;
}) {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  const pageLocale = useLocale();
  const errorText = useErrorText();
  const create = useCreateUser();
  const queryClient = useQueryClient();
  const {send} = useCheckedWrite();
  const form = useAdminForm({focus: "phone"});
  const [phone, setPhone] = useState("");
  const [locale, setLocale] = useState<Locale>(isLocale(pageLocale) ? pageLocale : "fa");
  const [pending, setPending] = useState(false);
  // No answer came after the server may have committed: the user may exist with a password nobody saw (gate-r32-7).
  const [lost, setLost] = useState(false);
  const busy = useRef(false);
  // Back, a reload and a closed tab ask first while the call runs: leaving would drop the password the answer carries (gate-r32-6).
  useLeaveGuard(pending);

  async function submit() {
    if (busy.current || form.blocked) return;
    const number = phone.trim();
    if (!number) return form.setFieldError("phone", a("fields.phone.required"));
    busy.current = true;
    setPending(true);
    onBusy(true);
    setLost(false);
    form.clear();
    const page = window.location.pathname;
    let done = false;
    try {
      // A write that needs the fresh TOTP window opens the dialog and is repeated once (admin-fresh, gate-r32-3).
      const created = await send(() => create.mutateAsync({phone: number, locale}));
      done = true;
      // The secret moves into the result panel's state, and the mutation forgets it.
      onCreated(number, created.one_time_password);
      create.reset();
      // Only the page that made the call: the address of another page is not ours to rewrite.
      if (window.location.pathname === page) stripDialogParam("dialog");
    } catch (error) {
      // `phone_unavailable` is allowed to be specific (AUTH 10.6): the admin is told the number cannot be used.
      if (hasCode(error, "phone_unavailable", "invalid_phone")) form.fail(error, {field: "phone", message: errorText(error)});
      else if (answerMayBeLost(error)) {
        // Said, not offered as a plain Retry: a second press would meet phone_unavailable with no hint why.
        void queryClient.invalidateQueries({queryKey: userKeys.all});
        setLost(true);
      } else form.fail(error);
    } finally {
      if (!done) {
        busy.current = false;
        setPending(false);
      }
      // The lock is for the call only, answered or not: the parent outlives this form, and a lock left on after a created answer would hold
      // every later open of the dialog shut (gate-r33-12). The answer is already in the result panel's state by now.
      onBusy(false);
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("users.create.text")}</p>
      <PhoneField name="phone" autoComplete="off" value={phone} {...form.bind("phone", setPhone)} isDisabled={pending} />
      <LocaleSegment label={t("users.create.locale")} value={locale} onChange={setLocale} isDisabled={pending} />
      {lost ? (
        <Alert status="warning" data-testid="create-lost">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("users.create.lost")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={t("users.create.submit")} isPending={pending} retryIn={form.retryIn} onCancel={onClose} />
    </AuthForm>
  );
}
