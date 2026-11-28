"use client";

import type {Me} from "@ctrlz/api-client/session.ts";
import {ReauthPanel} from "../auth/ReauthPanel.tsx";
import {useRecoverable} from "../auth/ReauthDialog.tsx";
import {PasswordMeter} from "../auth/PasswordMeter.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {EditorActions} from "../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {InlineEditRow} from "../forms/InlineEditRow.tsx";
import {hasInvisiblePassword} from "../forms/invisible.ts";
import {PasswordField} from "../forms/PasswordField.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {toast} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {accountApi, refreshAccount} from "./accountApi.ts";

// Spec 12.2 (AUTH 3.7): reauth, then the new password with the strength meter. An account that signed
// up with an SMS code only has no password yet: the same row sets the first one, and says so. The server
// rotates this session, ends the others and the API tokens, and the toast says that.

export function PasswordRow({me}: {me: Me}) {
  const t = useTranslations("account");
  const has = me.user.has_password;
  return (
    <InlineEditRow
      id="password"
      label={has ? t("password.label") : t("password.setLabel")}
      value={has ? t("password.valueSet") : t("password.valueNone")}
      description={has ? undefined : t("password.noneHint")}
      editLabel={has ? t("password.change") : t("password.set")}
      editAriaLabel={has ? t("password.changeAria") : t("password.setAria")}
      editor={({close}) => <PasswordEditor me={me} close={close} />}
    />
  );
}

function PasswordEditor({me, close}: {me: Me; close: () => void}) {
  const [proved, setProved] = useState(false);
  if (!proved) return <ReauthPanel me={me} onDone={() => setProved(true)} onCancel={close} />;
  return <NewPasswordForm first={!me.user.has_password} close={close} />;
}

function NewPasswordForm({first, close}: {first: boolean; close: () => void}) {
  const t = useTranslations("account");
  const a = useTranslations("auth");
  const queryClient = useQueryClient();
  const recover = useRecoverable();
  const form = useApiForm({focus: "new_password"});
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  const done = useRef(false);

  async function submit() {
    if (busy.current || form.blocked) return;
    if (!password) return form.setFieldError("new_password", a("fields.password.newRequired"));
    if (hasInvisiblePassword(password)) return form.setFieldError("new_password", a("fields.password.invisible"));
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      // The window may have ended while the person typed: a 403 asks again and repeats this once.
      await recover(() => accountApi.changePassword(password));
      done.current = true;
      toast.success(first ? t("password.doneFirst") : t("password.done"));
      await refreshAccount(queryClient);
      close();
    } catch (error) {
      // The server names the field `password` where this form calls it `new_password`.
      form.fail(error, {rename: {password: "new_password"}});
    } finally {
      if (!done.current) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <div className="flex flex-col gap-2">
        <PasswordField
          name="new_password"
          label={a("fields.password.newLabel")}
          autoComplete="new-password"
          value={password}
          {...form.bind("new_password", setPassword)}
          isDisabled={pending}
        />
        <PasswordMeter password={password} />
      </div>
      <FormError error={form.formError} onRetry={() => void submit()} />
      <OfflineNotice />
      <EditorActions
        submitLabel={first ? t("password.saveFirst") : t("password.save")}
        isPending={pending}
        retryIn={form.retryIn}
        onCancel={close}
      />
    </AuthForm>
  );
}
