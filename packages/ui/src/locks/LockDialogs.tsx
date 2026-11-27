"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useLockProfile, useUnlockProfile} from "@ctrlz/api-client/hooks/profiles.ts";
import {needsLockPasswords, wrongLockPasswordIndex, type LockPasswords} from "@ctrlz/api-client/hooks/lockPasswords.ts";
import {Button, Description, Label, TextArea, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {useRecoverable} from "../auth/ReauthDialog.tsx";
import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError} from "../forms/FormError.tsx";
import {cleanProse, hasInvisiblePassword} from "../forms/invisible.ts";
import {PasswordField} from "../forms/PasswordField.tsx";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {checkLockMessage, checkLockPassword, checkUnlockPassword, type LockPasswordProblem} from "./lockPassword.ts";

// Spec p2 7 and 9.2, FE 9. The dialogs that hold a LOCK PASSWORD: lock a profile, unlock it, and give the passwords that an Endpoint
// change needs (p3 3.3). They are STATE-ONLY: the password lives in the state of the dialog and in the variables of one mutation, never
// in the address, a query key or storage (`ctrlz/no-secret-param`, FE 14.4), and the dialog's state goes with it when it closes.
//
// The password is the profile's own, chosen when it is locked, not the account's, so it is a write-only secret (`autoComplete="off"`: the
// browser's manager must not offer to save it as a login).
//
// Lock needs a live reauth (`reauth_required`): the dialog runs the call through `useRecoverable`, which opens the reauth dialog and
// repeats the call once. A page that mounts these dialogs is inside a `ReauthProvider` (the profile frame mounts one).

const PROBLEM_TEXT: Record<LockPasswordProblem, "required" | "too_short" | "too_long"> = {required: "required", too_short: "too_short", too_long: "too_long"};

type Profile = {id: string; name: string};

export function LockProfileDialog({isOpen, onClose, profile, onLocked}: {isOpen: boolean; onClose: () => void; profile: Profile; onLocked?: () => void}) {
  const t = useTranslations("profiles");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const lock = useLockProfile();
  const run = useRecoverable();
  const form = useApiForm({focus: "password"});
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const busy = useRef(false);

  const close = () => {
    setPassword("");
    setMessage("");
    form.clear();
    lock.reset();
    onClose();
  };

  async function submit() {
    if (busy.current || form.blocked) return;
    if (hasInvisiblePassword(password)) return form.setFieldError("password", e("fields.invalid"));
    const problem = checkLockPassword(password);
    if (problem) return form.setFieldError("password", e(`fields.${PROBLEM_TEXT[problem]}`));
    if (checkLockMessage(cleanProse(message))) return form.setFieldError("message", e("fields.too_long"));
    busy.current = true;
    form.clear();
    try {
      const text = cleanProse(message);
      await run(() => lock.mutateAsync({id: profile.id, password, ...(text ? {message: text} : {})}));
      setPassword("");
      setMessage("");
      onLocked?.();
      onClose();
    } catch (error) {
      form.fail(error);
    } finally {
      busy.current = false;
      // The profile frame keeps this dialog mounted, so the mutation observer would hold `variables.password` for the life of the page;
      // reset drops it after every attempt, whatever the answer (SL-r1-1).
      lock.reset();
    }
  }

  return (
    <DialogFrame isOpen={isOpen} onClose={close} isLocked={lock.isPending} title={t("lock.dialog.lockTitle", {name: profile.name})}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <p className="text-muted text-sm">{t("lock.dialog.lockText")}</p>
        <PasswordField
          label={t("lock.dialog.password")}
          value={password}
          autoComplete="off"
          isDisabled={lock.isPending}
          description={t("lock.dialog.passwordHint")}
          {...form.bind("password", setPassword)}
        />
        <TextField fullWidth isDisabled={lock.isPending} name="message" value={message} isInvalid={form.fieldMessage("message") !== undefined} onChange={(v) => form.bind("message", setMessage).onChange(v)}>
          <Label>{t("lock.dialog.message")}</Label>
          <TextArea rows={2} maxLength={256} />
          <Description>{t("lock.dialog.messageHint")}</Description>
        </TextField>
        <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        <div className="flex items-center justify-end gap-2">
          <Button variant="tertiary" isDisabled={lock.isPending} onPress={close}>
            {c("cancel")}
          </Button>
          <SubmitButton isPending={lock.isPending} retryIn={form.retryIn}>
            {t("lock.dialog.lock")}
          </SubmitButton>
        </div>
      </AuthForm>
    </DialogFrame>
  );
}

export function UnlockProfileDialog({isOpen, onClose, profile, onUnlocked}: {isOpen: boolean; onClose: () => void; profile: Profile; onUnlocked?: () => void}) {
  const t = useTranslations("profiles");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const unlock = useUnlockProfile();
  const form = useApiForm({focus: "password"});
  const [password, setPassword] = useState("");
  const busy = useRef(false);

  const close = () => {
    setPassword("");
    form.clear();
    unlock.reset();
    onClose();
  };

  async function submit() {
    if (busy.current || form.blocked) return;
    if (hasInvisiblePassword(password)) return form.setFieldError("password", e("fields.invalid"));
    const problem = checkUnlockPassword(password);
    if (problem) return form.setFieldError("password", e(`fields.${PROBLEM_TEXT[problem]}`));
    busy.current = true;
    form.clear();
    try {
      await unlock.mutateAsync({id: profile.id, password});
      setPassword("");
      onUnlocked?.();
      onClose();
    } catch (error) {
      // A wrong password is 401 `invalid_credentials`: it belongs under the field, and the five-in-fifteen limit shows as the wait of the button.
      // The sign-in text of invalid_credentials reads as an account problem; here it is the lock password that is wrong (lock.dialog.wrong).
      const wrong = hasCode(error, "invalid_credentials");
      form.fail(error, {field: "password", ...(wrong ? {message: t("lock.dialog.wrong", {name: profile.name})} : {})});
    } finally {
      busy.current = false;
      // The profile frame keeps this dialog mounted, so the mutation observer would hold `variables.password` for the life of the page;
      // reset drops it after every attempt, whatever the answer (SL-r1-1).
      unlock.reset();
    }
  }

  return (
    <DialogFrame isOpen={isOpen} onClose={close} isLocked={unlock.isPending} title={t("lock.dialog.unlockTitle", {name: profile.name})}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <p className="text-muted text-sm">{t("lock.dialog.unlockText")}</p>
        <PasswordField label={t("lock.dialog.password")} value={password} autoComplete="off" isDisabled={unlock.isPending} {...form.bind("password", setPassword)} />
        <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        <div className="flex items-center justify-end gap-2">
          <Button variant="tertiary" isDisabled={unlock.isPending} onPress={close}>
            {c("cancel")}
          </Button>
          <SubmitButton isPending={unlock.isPending} retryIn={form.retryIn}>
            {t("lock.dialog.unlock")}
          </SubmitButton>
        </div>
      </AuthForm>
    </DialogFrame>
  );
}

/**
 * The passwords an Endpoint, client, schedule or claim change needs (p3 3.3): one field for each locked profile the change takes away.
 * `onSubmit` sends the request again with `lock_passwords`; a wrong one (`invalid_credentials` with `/lock_passwords/<i>`) is shown under
 * the field of that profile, by the order the passwords were sent in.
 *
 * The refusal names no profile, so `profiles` can be a guess. With `optional` every field may stay empty (at least one is filled) and
 * only the filled ones are sent; the server ignores a password it does not need and does not charge it. When `onSubmit` answers
 * `"again"` the dialog stays open with what was typed, because the caller has asked for more profiles (`more`).
 */
export function LockPasswordsDialog({
  isOpen,
  onClose,
  profiles,
  optional = false,
  more = false,
  onSubmit,
}: {
  isOpen: boolean;
  onClose: () => void;
  profiles: Profile[];
  optional?: boolean;
  more?: boolean;
  /** Sends the request again with the passwords. A rejection is shown here. */
  onSubmit: (passwords: LockPasswords) => Promise<"again" | void>;
}) {
  const t = useTranslations("profiles");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const form = useApiForm({focus: profiles[0] ? `password-${profiles[0].id}` : undefined});
  const [values, setValues] = useState<Record<string, string>>({});
  const [pending, setPending] = useState(false);
  const busy = useRef(false);

  const close = () => {
    setValues({});
    form.clear();
    onClose();
  };

  async function submit() {
    if (busy.current || form.blocked) return;
    // The order of `sent` is the order the server counts a wrong password by.
    const sent = profiles.filter((p) => !optional || (values[p.id] ?? "") !== "");
    if (sent.length === 0) return form.setFieldError(`password-${profiles[0]?.id ?? ""}`, e("fields.required"));
    for (const p of sent) {
      if (hasInvisiblePassword(values[p.id] ?? "")) return form.setFieldError(`password-${p.id}`, e("fields.invalid"));
      const problem = checkUnlockPassword(values[p.id] ?? "");
      if (problem) return form.setFieldError(`password-${p.id}`, e(`fields.${PROBLEM_TEXT[problem]}`));
    }
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      const answer = await onSubmit(sent.map((p) => ({profile_id: p.id, password: values[p.id] ?? ""})));
      if (answer === "again") return;
      setValues({});
      onClose();
    } catch (error) {
      const wrong = wrongLockPasswordIndex(error);
      const target = wrong === null ? undefined : sent[wrong];
      if (target) form.setFieldError(`password-${target.id}`, t("lock.dialog.wrong", {name: target.name}));
      else form.fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  return (
    <DialogFrame isOpen={isOpen} onClose={close} isLocked={pending} title={t("lock.dialog.needTitle")}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <p className="text-muted text-sm">{t(more ? "lock.dialog.needMoreText" : optional ? "lock.dialog.needAnyText" : "lock.dialog.needText")}</p>
        {profiles.map((p) => (
          <PasswordField
            key={p.id}
            name={`password-${p.id}`}
            label={t("lock.dialog.passwordFor", {name: p.name})}
            value={values[p.id] ?? ""}
            autoComplete="off"
            isDisabled={pending}
            {...form.bind(`password-${p.id}`, (v: string) => setValues((prev) => ({...prev, [p.id]: v})))}
          />
        ))}
        {/* The server wants more than was typed and there is no other profile to ask for: the fix is in the fields in front of the person, not in unlocking the profile (S5-r3-10). */}
        <FormError
          error={form.formError}
          message={form.formError !== null && needsLockPasswords(form.formError) ? t("lock.dialog.needText") : undefined}
          form={form}
          onRetry={() => void submit()}
        />
        <div className="flex items-center justify-end gap-2">
          <Button variant="tertiary" isDisabled={pending} onPress={close}>
            {c("cancel")}
          </Button>
          <SubmitButton isPending={pending} retryIn={form.retryIn}>
            {t("lock.dialog.continue")}
          </SubmitButton>
        </div>
      </AuthForm>
    </DialogFrame>
  );
}
