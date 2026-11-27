"use client";

import {fieldErrors} from "@ctrlz/api-client/errors.ts";
import {
  useCreateApiToken,
  useDeleteApiToken,
  usePatchApiToken,
  type ApiToken,
  type ApiTokenCreated,
  type ApiTokenKind,
} from "@ctrlz/api-client/hooks/apiTokens.ts";
import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {AlertDialog, Button, Description, FieldError, Input, Label, Radio, RadioGroup, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState, type ReactNode} from "react";

import {useRecoverable} from "../auth/ReauthDialog.tsx";
import {TechCopyRow} from "../data/TechCopyRow.tsx";
import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {WipeScope} from "../dialog/WipeScope.tsx";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError} from "../forms/FormError.tsx";
import {cleanProse, nameLength} from "../forms/invisible.ts";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useApiForm, type ApiForm} from "../forms/useApiForm.ts";
import {SecretCopyNote} from "../setup/SecretCopyNote.tsx";
import {AllowedIpsField, type AllowedIpsHandle} from "./AllowedIpsField.tsx";
import {NAME_MAX, sameAllowed} from "./tokenModel.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// The dialogs of the API tokens page (spec p3 6.4, 10, Plan T-315). All three are STATE-ONLY: a token's value is in none of the addresses, and the one
// dialog that shows it holds it in its own state, which goes when the dialog does.
//
//   Create  name, type (Read or Write: fixed for good), Allowed IPs. Needs a live reauth (`reauth_required` opens the reauth dialog and the call is
//           repeated once). The answer holds the value ONCE: the same dialog turns into the value step, which cannot be dismissed by a stray click
//           or Escape (the value is not shown again), has a Copy button that writes through the one-time-secret writer, and wipes the clipboard when
//           it goes away.
//   Edit    name and Allowed IPs; the type is shown and cannot be changed. Needs reauth too.
//   Delete  a confirmation that says what stops working. A session is enough.

type NameFormValues = {name: string; allowed: string[]};

/** The words for a refusal of the allowed list, which the server names by place (`/allowed_ips/3`), and the entry the person typed. */
type AllowedWords = {invalid: string; max: string; entry: (entry: string) => string};

function allowedMessage(error: unknown, items: readonly string[], words: AllowedWords): string | undefined {
  const names = Object.keys(fieldErrors(error)).filter((name) => name.startsWith("/allowed_ips"));
  if (names.length === 0) return undefined;
  const entry = names.map((name) => /^\/allowed_ips\/(\d{1,2})$/.exec(name)).find(Boolean);
  const at = entry ? Number(entry[1]) : -1;
  if (at >= 0 && items[at] !== undefined) return words.entry(items[at]);
  return fieldErrors(error)["/allowed_ips"] === "exceeded" ? words.max : words.invalid;
}

/** What the failure of a create or an edit shows: a limit as its notice, the allowed list under its field, the rest through the form. */
function useFailure(form: ApiForm) {
  const t = useTranslations("api");
  const [cap, setCap] = useState<unknown>(null);
  const [allowed, setAllowed] = useState<string | undefined>();
  return {
    cap,
    allowed: allowed ?? undefined,
    clear: () => {
      setCap(null);
      setAllowed(undefined);
      form.clear();
    },
    clearAllowed: () => setAllowed(undefined),
    /** `items` is the list that was SENT: the server names an entry by its place in it, and the list in state may have moved on since. */
    fail: (error: unknown, items: readonly string[]) => {
      // A 422 on the allowed list is about the list (its field carries the words), even when its code is `exceeded`: the limit notice is for the caps of the account.
      const aboutList = Object.keys(fieldErrors(error)).some((name) => name.startsWith("/allowed_ips"));
      if (!aboutList && exceededCap(error)) {
        setCap(error);
        return;
      }
      setAllowed(allowedMessage(error, items, {invalid: t("allowed.problems.invalid"), max: t("allowed.problems.max", {max: 32}), entry: (entry) => t("allowed.problems.serverInvalid", {entry})}));
      form.fail(error, {rename: {"/name": "name", "/kind": "kind", "/allowed_ips": "allowed_ips"}});
    },
  };
}

function NameField({form, value, onChange, isDisabled}: {form: ApiForm; value: string; onChange: (value: string) => void; isDisabled: boolean}) {
  const t = useTranslations("api");
  const bound = form.bind("name", onChange);
  return (
    <TextField fullWidth isDisabled={isDisabled} name="name" value={value} isInvalid={bound.error !== undefined} onChange={bound.onChange}>
      <Label>{t("dialog.name")}</Label>
      <Input autoComplete="off" maxLength={NAME_MAX * 2} />
      <Description>{t("dialog.nameHint", {max: NAME_MAX})}</Description>
      <FieldError>{bound.error}</FieldError>
    </TextField>
  );
}

function checkName(raw: string): {name: string; problem: "required" | "too_long" | null} {
  const name = cleanProse(raw);
  if (name === "") return {name, problem: "required"};
  return {name, problem: nameLength(name) > NAME_MAX ? "too_long" : null};
}

// ---- Create ----

export function CreateTokenDialog({isOpen, onClose}: {isOpen: boolean; onClose: () => void}) {
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  // The form stays mounted while the dialog animates out, so a cancelled draft would come back at the next open: every closed-to-open step is a new form (S8-r1-6).
  const [opening, setOpening] = useState({open: isOpen, count: 0});
  if (opening.open !== isOpen) setOpening({open: isOpen, count: opening.count + (isOpen ? 1 : 0)});
  // The two steps are two bodies of one dialog: once the value is in state the form is gone and cannot send a second create.
  const close = () => {
    setCreated(null);
    onClose();
  };
  return created ? <ValueStep created={created} isOpen={isOpen} onClose={close} /> : <CreateStep key={opening.count} isOpen={isOpen} onClose={close} onCreated={setCreated} />;
}

function CreateStep({isOpen, onClose, onCreated}: {isOpen: boolean; onClose: () => void; onCreated: (created: ApiTokenCreated) => void}) {
  const t = useTranslations("api");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const create = useCreateApiToken();
  const run = useRecoverable();
  const form = useApiForm({focus: "name"});
  const [values, setValues] = useState<NameFormValues & {kind: ApiTokenKind}>({name: "", allowed: [], kind: "read"});
  const busy = useRef(false);
  const allowedField = useRef<AllowedIpsHandle>(null);
  const failure = useFailure(form);

  const close = () => {
    if (create.isPending) return;
    failure.clear();
    onClose();
  };

  async function submit() {
    if (busy.current || form.blocked) return;
    // An address typed and not added is part of the list (S8-r1-2): an empty list means any address, so dropping it would make the token wider than the person meant.
    const allowed = allowedField.current ? allowedField.current.flush() : values.allowed;
    const {name, problem} = checkName(values.name);
    if (problem) form.setFieldError("name", e(`fields.${problem}`));
    if (problem || allowed === null) return;
    busy.current = true;
    failure.clear();
    try {
      const result = await run(() => create.mutateAsync({name, kind: values.kind, ...(allowed.length > 0 ? {allowed_ips: allowed} : {})}));
      onCreated(result);
    } catch (error) {
      failure.fail(error, allowed);
    } finally {
      busy.current = false;
    }
  }

  return (
    <DialogFrame isOpen={isOpen} onClose={close} isLocked={create.isPending} title={t("create.title")}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <p className="text-muted text-sm">{t("create.text")}</p>
        <NameField form={form} value={values.name} isDisabled={create.isPending} onChange={(name) => setValues((v) => ({...v, name}))} />
        <RadioGroup
          name="kind"
          isDisabled={create.isPending}
          value={values.kind}
          onChange={(kind) => setValues((v) => ({...v, kind: kind === "write" ? "write" : "read"}))}
          className="flex flex-col gap-2"
        >
          <Label>{t("dialog.kind")}</Label>
          <KindOption value="read" name={t("kind.read")} hint={t("create.readHint")} />
          <KindOption value="write" name={t("kind.write")} hint={t("create.writeHint")} />
          <Description>{t("create.kindFixed")}</Description>
        </RadioGroup>
        <AllowedIpsField
          ref={allowedField}
          items={values.allowed}
          isDisabled={create.isPending}
          serverProblem={failure.allowed ?? form.fieldMessage("allowed_ips")}
          onChange={(allowed) => {
            failure.clearAllowed();
            setValues((v) => ({...v, allowed}));
          }}
        />
        <p className="text-muted text-xs">{t("create.lifetime")}</p>
        <CapacityNotice error={failure.cap} />
        <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        <div className="flex items-center justify-end gap-2">
          <Button variant="tertiary" isDisabled={create.isPending} onPress={close}>
            {c("cancel")}
          </Button>
          <SubmitButton isPending={create.isPending} retryIn={form.retryIn}>
            {t("create.submit")}
          </SubmitButton>
        </div>
      </AuthForm>
    </DialogFrame>
  );
}

function KindOption({value, name, hint}: {value: string; name: string; hint: string}) {
  return (
    <Radio value={value} className="w-full">
      <Radio.Control>
        <Radio.Indicator />
      </Radio.Control>
      <Radio.Content className="flex min-w-0 flex-1 flex-col">
        <Label className="block">{name}</Label>
        <span className="text-muted block text-xs">{hint}</span>
      </Radio.Content>
    </Radio>
  );
}

function ValueStep({created, isOpen, onClose}: {created: ApiTokenCreated; isOpen: boolean; onClose: () => void}) {
  const t = useTranslations("api");
  return (
    <WipeScope>
      <DialogFrame
        isOpen={isOpen}
        onClose={onClose}
        // The value is shown once: Escape, a click outside and the X would lose it for good, so only the button ends the step.
        isDismissable={false}
        isLocked
        title={t("value.title", {name: created.token.name})}
        footer={
          <PrimaryButton onPress={onClose} data-testid="token-value-done">
            {t("value.done")}
          </PrimaryButton>
        }
      >
        <div className="flex flex-col gap-3" data-testid="token-value">
          <p className="flex items-start gap-2 text-sm">
            <Icon name="warning" className="text-warning-soft-foreground mt-0.5 size-4 shrink-0" />
            <span>{t("value.once")}</span>
          </p>
          <TechCopyRow label={t("value.label", {name: created.token.name})} value={created.value} secret />
          <p className="text-muted text-xs">{t("value.use")}</p>
          <SecretCopyNote />
        </div>
      </DialogFrame>
    </WipeScope>
  );
}

// ---- Edit ----

export function EditTokenDialog({token, onClose}: {token: ApiToken | null; onClose: () => void}) {
  // Kept while the dialog animates out, and re-keyed per token and per opening: a cancelled draft must not come back, and above all must not be compared
  // with a list that was refetched since and then sent over it (S8-r1-6). While the dialog stays open a refetch changes `token` and not the key, so typing is not lost.
  const [shown, setShown] = useState<ApiToken | null>(null);
  const [opening, setOpening] = useState({open: token !== null, count: 0});
  const open = token !== null;
  if (opening.open !== open) setOpening({open, count: opening.count + (open ? 1 : 0)});
  if (token && token !== shown) setShown(token);
  if (!shown) return null;
  return <EditBody key={`${shown.id}:${opening.count}`} token={shown} isOpen={open} onClose={onClose} />;
}

function EditBody({token, isOpen, onClose}: {token: ApiToken; isOpen: boolean; onClose: () => void}) {
  const t = useTranslations("api");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const patch = usePatchApiToken();
  const run = useRecoverable();
  const form = useApiForm({focus: "name"});
  const [values, setValues] = useState<NameFormValues>({name: token.name, allowed: [...token.allowed_ips]});
  const busy = useRef(false);
  const allowedField = useRef<AllowedIpsHandle>(null);
  const failure = useFailure(form);

  const close = () => {
    if (patch.isPending) return;
    failure.clear();
    onClose();
  };

  async function submit() {
    if (busy.current || form.blocked) return;
    // An address typed and not added is part of the list, or the edit would close as "nothing changed" over a list the person believes is saved (S8-r1-2).
    const allowed = allowedField.current ? allowedField.current.flush() : values.allowed;
    const {name, problem} = checkName(values.name);
    if (problem) form.setFieldError("name", e(`fields.${problem}`));
    if (problem || allowed === null) return;
    const body = {
      ...(name !== token.name ? {name} : {}),
      ...(!sameAllowed(allowed, token.allowed_ips) ? {allowed_ips: allowed} : {}),
    };
    // Nothing changed: no reauth for nothing, the dialog just closes (the API refuses an empty edit as well).
    if (Object.keys(body).length === 0) return close();
    busy.current = true;
    failure.clear();
    try {
      await run(() => patch.mutateAsync({id: token.id, ...body}));
      toast.success(t("edit.saved"));
      onClose();
    } catch (error) {
      failure.fail(error, allowed);
    } finally {
      busy.current = false;
    }
  }

  return (
    <DialogFrame isOpen={isOpen} onClose={close} isLocked={patch.isPending} title={t("edit.title", {name: token.name})}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <NameField form={form} value={values.name} isDisabled={patch.isPending} onChange={(name) => setValues((v) => ({...v, name}))} />
        <p className="text-sm">
          <span className="text-muted">{t("dialog.kind")}: </span>
          {t(`kind.${token.kind}`)}
          <span className="text-muted block text-xs">{t("edit.kindFixed")}</span>
        </p>
        <AllowedIpsField
          ref={allowedField}
          items={values.allowed}
          isDisabled={patch.isPending}
          serverProblem={failure.allowed ?? form.fieldMessage("allowed_ips")}
          onChange={(allowed) => {
            failure.clearAllowed();
            setValues((v) => ({...v, allowed}));
          }}
        />
        <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        <div className="flex items-center justify-end gap-2">
          <Button variant="tertiary" isDisabled={patch.isPending} onPress={close}>
            {c("cancel")}
          </Button>
          <SubmitButton isPending={patch.isPending} retryIn={form.retryIn}>
            {c("save")}
          </SubmitButton>
        </div>
      </AuthForm>
    </DialogFrame>
  );
}

// ---- Delete ----

export function DeleteTokenDialog({token, onClose}: {token: ApiToken | null; onClose: () => void}) {
  const [shown, setShown] = useState<ApiToken | null>(null);
  if (token && token !== shown) setShown(token);
  if (!shown) return null;
  return <DeleteBody key={shown.id} token={shown} isOpen={token !== null} onClose={onClose} />;
}

function DeleteBody({token, isOpen, onClose}: {token: ApiToken; isOpen: boolean; onClose: () => void}) {
  const t = useTranslations("api");
  const c = useTranslations("common");
  const remove = useDeleteApiToken();
  const form = useApiForm();

  async function confirm() {
    form.clear();
    try {
      await remove.mutateAsync(token.id);
      toast.success(t("delete.done", {name: token.name}));
      onClose();
    } catch (error) {
      form.fail(error);
    }
  }

  const body: ReactNode = (
    <div className="flex flex-col gap-3">
      <p>{t("delete.text", {name: token.name})}</p>
      <FormError error={form.formError} form={form} onRetry={() => void confirm()} />
    </div>
  );
  return (
    <AlertDialog.Backdrop isOpen={isOpen} onOpenChange={(open) => !open && !remove.isPending && onClose()}>
      <AlertDialog.Container placement="center">
        <AlertDialog.Dialog className="sm:max-w-[400px]">
          <AlertDialog.CloseTrigger aria-label={c("close")} />
          <AlertDialog.Header>
            <AlertDialog.Icon status="danger">
              <Icon name="trash" className="size-5" />
            </AlertDialog.Icon>
            <AlertDialog.Heading>{t("delete.title", {name: token.name})}</AlertDialog.Heading>
          </AlertDialog.Header>
          <AlertDialog.Body>{body}</AlertDialog.Body>
          <AlertDialog.Footer>
            <Button slot="close" variant="tertiary" isDisabled={remove.isPending}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={remove.isPending} onPress={() => void confirm()}>
              {t("delete.confirm")}
            </Button>
          </AlertDialog.Footer>
        </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );
}
