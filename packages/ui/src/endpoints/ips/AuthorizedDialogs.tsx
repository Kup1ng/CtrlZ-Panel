"use client";

import {fieldErrors, hasCode} from "@ctrlz/api-client/errors.ts";
import {useAddAuthorizedIps, useDeleteAuthorizedIps, type AuthorizedIP} from "@ctrlz/api-client/hooks/clients.ts";
import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, Button, FieldError, Label, TextArea, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {useScreenFieldText} from "../../feedback/useScreenFieldText.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {useApiForm} from "../../forms/useApiForm.ts";
import {useOnlineStatus} from "../../forms/useOnlineStatus.ts";
import {Cancelled, useGuardedWrite} from "../useGuardedWrite.tsx";
import {MAX_CIDRS, parseCidrs} from "./ipModel.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// `ipDialog=add` (spec p3 5, 10, T-262): one box, "IP Address or Subnet", that also takes a list (up to 100, one to a line or separated by
// commas). Each entry is checked for its shape before a request; the server decides the rest (IPv4 /16 or narrower, IPv6 /32 or narrower,
// no repeats, the Endpoint's cap) and names the entry that it refused by its place (`/cidrs/<i>`), which this dialog turns into a line of text.

export function AddAuthorizedDialog({endpointId, onClose}: {endpointId: string; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const add = useAddAuthorizedIps();
  const form = useApiForm({focus: "cidrs", fieldNamespace: "profiles"});
  const fieldText = useScreenFieldText();
  const busy = useRef(false);
  const [text, setText] = useState("");
  const [pending, setPending] = useState(false);
  const [lines, setLines] = useState<string[]>([]);
  const parsed = parseCidrs(text);

  async function submit() {
    if (busy.current || form.blocked) return;
    if (parsed.items.length === 0) return form.setFieldError("cidrs", e("fields.required"));
    if (parsed.tooMany) return form.setFieldError("cidrs", t("ips.add.tooMany", {max: MAX_CIDRS}));
    const first = parsed.bad[0];
    if (first) return form.setFieldError("cidrs", t("ips.add.badEntry", {n: first.index + 1, text: first.text}));
    busy.current = true;
    setPending(true);
    form.clear();
    setLines([]);
    try {
      const made = await add.mutateAsync({endpointId, cidrs: parsed.items});
      toast.success(t("ips.add.done", {count: made.length}));
      onClose();
    } catch (error) {
      // An entry the server refused is named by its place; the others stay in the box for the next try.
      const named = Object.entries(fieldErrors(error))
        .map(([name, code]) => ({match: /^\/cidrs\/(\d+)$/.exec(name), code}))
        .filter((x): x is {match: RegExpExecArray; code: string} => x.match !== null);
      if (named.length > 0) setLines(named.map(({match, code}) => t("ips.add.refused", {n: Number(match[1]) + 1, text: parsed.items[Number(match[1])] ?? "", reason: code === "out_of_range" ? t("ips.add.outOfRange") : fieldText(code, "cidrs")})));
      else form.fail(error, {rename: {"/cidrs": "cidrs"}});
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={pending}
      title={t("ips.add.title")}
      footer={
        <>
          <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton isPending={pending} isDisabled={form.retryIn > 0} onPress={() => void submit()}>
            {t("ips.add.submit")}
          </PrimaryButton>
        </>
      }
    >
      <AuthForm form={form} onSubmit={() => void submit()}>
        <TextField fullWidth name="cidrs" value={text} isDisabled={pending} isInvalid={form.fieldMessage("cidrs") !== undefined || lines.length > 0} onChange={(v) => {
          setLines([]);
          form.bind("cidrs", setText).onChange(v);
        }}>
          <Label>{t("ips.add.field")}</Label>
          <TextArea rows={4} dir="ltr" autoComplete="off" spellCheck={false} autoCapitalize="none" placeholder={"203.0.113.7\n198.51.100.0/24"} />
          <p className="text-muted text-xs">{t("ips.add.hint", {max: MAX_CIDRS})}</p>
          <FieldError>{form.fieldMessage("cidrs")}</FieldError>
        </TextField>
        {lines.length > 0 ? (
          <ul role="alert" className="text-danger-soft-foreground flex flex-col gap-1 text-sm">
            {lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        ) : null}
        <CapacityNotice error={form.formError} />
        <FormError error={exceededCap(form.formError) ? null : form.formError} form={form} onRetry={() => void submit()} />
      </AuthForm>
    </DialogFrame>
  );
}

/** The delete of one or more authorized addresses (T-262, T-263): the rows are named, and the two protections are said before the button. */
export function DeleteAuthorizedDialog({endpoint, rows, wouldEmpty, onClose, onDone}: {endpoint: Endpoint; rows: AuthorizedIP[]; wouldEmpty: boolean; onClose: () => void; onDone: () => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const format = useAppFormat();
  const del = useDeleteAuthorizedIps();
  const guarded = useGuardedWrite();
  const form = useApiForm({fieldNamespace: "profiles"});
  const online = useOnlineStatus();
  const busy = useRef(false);
  const [pending, setPending] = useState(false);
  const [protectedMessage, setProtectedMessage] = useState<string | null>(null);
  const hasCurrent = rows.some((r) => r.is_current);
  const blocked = hasCurrent || wouldEmpty;

  async function submit() {
    if (busy.current || form.blocked || blocked) return;
    busy.current = true;
    setPending(true);
    form.clear();
    setProtectedMessage(null);
    try {
      await guarded.run((extra) => del.mutateAsync({endpointId: endpoint.id, ids: rows.map((r) => r.id), ...(extra.lock_passwords ? {lockPasswords: extra.lock_passwords} : {})}), [endpoint], {takesAll: endpoint.require_authorized_ips, reset: del.reset});
      toast.success(t("ips.delete.done", {count: rows.length}));
      onDone();
      onClose();
    } catch (error) {
      if (error instanceof Cancelled) return;
      // The answer names the protection by code, on the entries it refused: the page says it in words and keeps the dialog open.
      const codes = Object.values(fieldErrors(error));
      if (hasCode(error, "validation_failed") && codes.includes("current_address")) setProtectedMessage(e("fields.current_address"));
      else if (hasCode(error, "validation_failed") && codes.includes("last_authorized")) setProtectedMessage(e("fields.last_authorized"));
      else form.fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  const list = rows.slice(0, 5);
  return (
    <>
      <DialogFrame
        isOpen
        onClose={onClose}
        isLocked={pending}
        title={t("ips.delete.title", {count: rows.length})}
        footer={
          <>
            <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={pending} isDisabled={!online || blocked || form.retryIn > 0} onPress={() => void submit()}>
              {t("ips.delete.submit")}
            </Button>
          </>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          <div className="flex items-start gap-3">
            <span aria-hidden="true" className="bg-danger-soft text-danger-soft-foreground grid size-10 shrink-0 place-items-center rounded-full">
              <Icon name="warning" className="size-5" />
            </span>
            <p className="text-sm">{t("ips.delete.text", {count: rows.length})}</p>
          </div>
          <ul className="flex flex-col gap-1 text-sm">
            {list.map((r) => (
              <li key={r.id}>
                <Tech>{r.cidr}</Tech>
              </li>
            ))}
            {rows.length > list.length ? <li className="text-muted">{t("ips.delete.more", {count: format.number(rows.length - list.length)})}</li> : null}
          </ul>
          {hasCurrent ? <Alert status="warning" role="status"><Alert.Indicator /><Alert.Content><Alert.Title>{e("fields.current_address")}</Alert.Title></Alert.Content></Alert> : null}
          {wouldEmpty && !hasCurrent ? <Alert status="warning" role="status"><Alert.Indicator /><Alert.Content><Alert.Title>{e("fields.last_authorized")}</Alert.Title></Alert.Content></Alert> : null}
          {protectedMessage ? (
            <p role="alert" className="text-danger-soft-foreground text-sm">
              {protectedMessage}
            </p>
          ) : null}
          <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        </AuthForm>
      </DialogFrame>
      {guarded.dialogs}
    </>
  );
}
