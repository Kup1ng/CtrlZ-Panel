"use client";

import {INVITE_TTL_DEFAULT_HOURS, INVITE_TTL_MAX_HOURS, inviteKeys, useCreateInvite} from "@ctrlz/api-client/admin/hooks/invites.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {isLocale, type Locale} from "@ctrlz/i18n/locale.ts";
import {Alert, Switch} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
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
import {IntegerField} from "../shared/IntegerField.tsx";
import {LocaleSegment} from "../shared/LocaleSegment.tsx";
import {OneTimeResult} from "../shared/OneTimeResult.tsx";
import {createButton, keepFocus} from "../shared/restoreFocus.ts";

// Spec 13.2, T-330. `POST /invites {phone, locale, send_sms, ttl_hours}`. The form is bound to `?dialog=createInvite`; the
// code and the link come back once, so they are shown in a state-only panel after the parameter has left the address
// (see dialogUrl.ts), and the mutation is reset. `send_sms` works through the outbox queue, so it does not need to know
// whether a gateway is up right now: the invite exists either way and the admin can copy the link.

export function CreateInviteDialog({dialog}: {dialog: UrlDialog}) {
  const t = useTranslations("admin");
  const open = dialog.value === "createInvite";
  const [result, setResult] = useState<{code: string; link: string; texted: boolean} | null>(null);
  // The POST is in flight: its answer carries a code and a link that cannot be shown again, so the dialog stays (gate-r32-6).
  const [busy, setBusy] = useState(false);

  return (
    <>
      <UrlModal dialog={dialog} isOpen={open} isLocked={busy} title={t("invites.create.title")}>
        {open ? <CreateForm onClose={dialog.close} onBusy={setBusy} onCreated={setResult} /> : null}
      </UrlModal>
      {result ? (
        <OneTimeResult
          title={t("invites.result.title")}
          intro={result.texted ? t("invites.result.introTexted") : t("invites.result.intro")}
          values={[
            {id: "code", label: t("invites.result.code"), value: result.code, copyLabel: t("invites.result.copyCode")},
            {id: "link", label: t("invites.result.link"), value: result.link, copyLabel: t("invites.result.copyLink")},
          ]}
          onClose={() => setResult(null)}
          returnFocus={() => createButton(t("invites.create.open"))}
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
  onCreated: (result: {code: string; link: string; texted: boolean}) => void;
}) {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  const pageLocale = useLocale();
  const errorText = useErrorText();
  const create = useCreateInvite();
  const queryClient = useQueryClient();
  const {send} = useCheckedWrite();
  const form = useAdminForm({focus: "phone"});
  const [phone, setPhone] = useState("");
  const [locale, setLocale] = useState<Locale>(isLocale(pageLocale) ? pageLocale : "fa");
  const [sendSms, setSendSms] = useState(false);
  const [ttl, setTtl] = useState<number | undefined>(INVITE_TTL_DEFAULT_HOURS);
  const [pending, setPending] = useState(false);
  // No answer came after the server may have committed: the invite may exist with a code nobody saw (gate-r32-7).
  const [lost, setLost] = useState(false);
  const busy = useRef(false);
  // Back, a reload and a closed tab ask first while the call runs: leaving would drop the code the answer carries (gate-r32-6).
  useLeaveGuard(pending);

  async function submit() {
    if (busy.current || form.blocked) return;
    const number = phone.trim();
    if (!number) return form.setFieldError("phone", a("fields.phone.required"));
    if (ttl === undefined || !Number.isInteger(ttl) || ttl < 1 || ttl > INVITE_TTL_MAX_HOURS) {
      return form.setFieldError("ttl_hours", t("invites.create.ttlRange", {max: INVITE_TTL_MAX_HOURS}));
    }
    busy.current = true;
    setPending(true);
    onBusy(true);
    setLost(false);
    form.clear();
    const page = window.location.pathname;
    let done = false;
    try {
      // A write that needs the fresh TOTP window opens the dialog and is repeated once (admin-fresh, gate-r32-3).
      const created = await send(() => create.mutateAsync({phone: number, locale, send_sms: sendSms, ttl_hours: ttl}));
      done = true;
      onCreated({code: created.code, link: created.link, texted: sendSms});
      create.reset();
      // Only the page that made the call: the address of another page is not ours to rewrite.
      if (window.location.pathname === page) stripDialogParam("dialog");
    } catch (error) {
      if (hasCode(error, "phone_unavailable", "invalid_phone")) form.fail(error, {field: "phone", message: errorText(error)});
      else if (answerMayBeLost(error)) {
        // Said, not offered as a plain Retry: a second press would meet phone_unavailable with no hint why.
        void queryClient.invalidateQueries({queryKey: inviteKeys.all});
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
      <p className="text-muted text-sm">{t("invites.create.text")}</p>
      <PhoneField name="phone" autoComplete="off" value={phone} {...form.bind("phone", setPhone)} isDisabled={pending} />
      <LocaleSegment label={t("invites.create.locale")} value={locale} onChange={setLocale} isDisabled={pending} />
      <IntegerField
        name="ttl_hours"
        label={t("invites.create.ttl")}
        description={t("invites.create.ttlHint", {max: INVITE_TTL_MAX_HOURS})}
        value={ttl}
        onChange={(value) => {
          setTtl(value);
          form.clearField("ttl_hours");
        }}
        min={1}
        max={INVITE_TTL_MAX_HOURS}
        isDisabled={pending}
        error={form.fieldMessage("ttl_hours")}
        invalidMessage={t("invites.create.ttlRange", {max: INVITE_TTL_MAX_HOURS})}
      />
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 flex-col">
          <span className="text-sm font-medium">{t("invites.create.sendSms")}</span>
          <span className="text-muted text-xs">{t("invites.create.sendSmsHint")}</span>
        </div>
        <Switch name="send_sms" aria-label={t("invites.create.sendSms")} isSelected={sendSms} onChange={setSendSms} isDisabled={pending}>
          <Switch.Content>
            <Switch.Control>
              <Switch.Thumb />
            </Switch.Control>
          </Switch.Content>
        </Switch>
      </div>
      {lost ? (
        <Alert status="warning" data-testid="create-lost">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("invites.create.lost")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={t("invites.create.submit")} isPending={pending} retryIn={form.retryIn} onCancel={onClose} />
    </AuthForm>
  );
}
