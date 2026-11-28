"use client";

import {fieldErrors, hasCode} from "@ctrlz/api-client/errors.ts";
import {useCreateDdnsHost, useDdnsHosts, useDeleteDdnsHost, useIpClaims, type DdnsHost} from "@ctrlz/api-client/hooks/clients.ts";
import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Chip, FieldError, Input, Label, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {ListRow} from "../../data/ListRow.tsx";
import {RowList} from "../../data/ListRow.tsx";
import {Tech} from "../../data/Tech.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {cleanName} from "../../forms/invisible.ts";
import {useApiForm} from "../../forms/useApiForm.ts";
import {Cancelled, useGuardedWrite} from "../useGuardedWrite.tsx";
import {hostDeleteEmptiesStack} from "./ipModel.ts";

// The Dynamic DNS hosts of an Endpoint (spec p3 5, 9.2; the flag is `authorize_ddns` of the Edit dialog). A host name whose address the hub
// follows: each address it resolves to becomes an authorized one, and is never proof of a Plain DNS claim (4.5). Shown only while the Endpoint
// uses it; a few rows, so a plain list.

// An example host name is a Latin technical token in both languages, so it is no message: a Persian sentence in the box read as an instruction (S6-r1-6).
const EXAMPLE_HOST = "home.example.org";

export function DdnsSection({endpoint}: {endpoint: Endpoint}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const format = useAppFormat();
  const hosts = useDdnsHosts(endpoint.id);
  const create = useCreateDdnsHost();
  const form = useApiForm({fieldNamespace: "profiles"});
  const busy = useRef(false);
  const [name, setName] = useState("");
  const [deleting, setDeleting] = useState<DdnsHost | null>(null);

  async function add() {
    if (busy.current || form.blocked) return;
    const hostname = cleanName(name).toLowerCase();
    if (hostname === "") return form.setFieldError("hostname", e("fields.required"));
    busy.current = true;
    form.clear();
    try {
      await create.mutateAsync({endpointId: endpoint.id, hostname});
      setName("");
      toast.success(t("ips.ddns.added"));
    } catch (error) {
      form.fail(error, {rename: {"/hostname": "hostname"}});
    } finally {
      busy.current = false;
    }
  }

  return (
    <section aria-labelledby="ddns-title" className="flex flex-col gap-3" data-testid="ddns-section">
      <div>
        <h2 id="ddns-title" className="text-base font-medium">
          {t("ips.ddns.title")}
        </h2>
        <p className="text-muted text-sm">{t("ips.ddns.text")}</p>
      </div>
      <AuthForm form={form} onSubmit={() => void add()}>
        <div className="flex flex-wrap items-start gap-2">
          <TextField className="min-w-56 flex-1 sm:max-w-sm" name="hostname" value={name} isInvalid={form.fieldMessage("hostname") !== undefined} onChange={(v) => form.bind("hostname", setName).onChange(v)}>
            <Label>{t("ips.ddns.field")}</Label>
            <Input dir="ltr" autoComplete="off" spellCheck={false} autoCapitalize="none" placeholder={EXAMPLE_HOST} />
            <FieldError>{form.fieldMessage("hostname")}</FieldError>
          </TextField>
          <Button className="mt-6" variant="secondary" isPending={create.isPending} isDisabled={form.retryIn > 0} onPress={() => void add()}>
            {t("ips.ddns.add")}
          </Button>
        </div>
        <CapacityNotice error={form.formError} />
        <FormError error={exceededCap(form.formError) ? null : form.formError} form={form} onRetry={() => void add()} />
      </AuthForm>
      {hosts.isError && !hosts.data ? (
        <SectionError error={hosts.error} onRetry={() => void hosts.refetch()} />
      ) : (hosts.data ?? []).length === 0 ? (
        <p className="text-muted text-sm">{t("ips.ddns.empty")}</p>
      ) : (
        <RowList aria-label={t("ips.ddns.listLabel")}>
          {(hosts.data ?? []).map((h) => (
            <ListRow
              key={h.id}
              icon={<Icon name="globe" className="size-5" />}
              title={<Tech className="truncate text-sm">{h.hostname}</Tech>}
              subtitle={
                <>
                  {h.last_ips.length > 0 ? <Tech>{h.last_ips.join(", ")}</Tech> : <span>{t("ips.ddns.noAddress")}</span>}
                  <span> · {h.last_resolved_at ? t("ips.ddns.resolved", {when: format.relative(h.last_resolved_at)}) : t("ips.ddns.neverResolved")}</span>
                </>
              }
              counters={
                h.last_error ? (
                  <Chip size="sm" variant="soft" color="warning">
                    <Chip.Label>{t("ips.ddns.failing")}</Chip.Label>
                  </Chip>
                ) : undefined
              }
              trailing={
                <Button isIconOnly size="sm" variant="ghost" aria-label={t("ips.ddns.deleteAria", {name: h.hostname})} onPress={() => setDeleting(h)}>
                  <Icon name="trash" className="size-4" />
                </Button>
              }
            />
          ))}
        </RowList>
      )}
      {deleting ? <DeleteHostDialog endpoint={endpoint} host={deleting} onClose={() => setDeleting(null)} /> : null}
    </section>
  );
}

function DeleteHostDialog({endpoint, host, onClose}: {endpoint: Endpoint; host: DdnsHost; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const del = useDeleteDdnsHost();
  const claims = useIpClaims(endpoint.id);
  const guarded = useGuardedWrite();
  const form = useApiForm({fieldNamespace: "profiles"});
  const busy = useRef(false);
  const [pending, setPending] = useState(false);
  const [refused, setRefused] = useState<string | null>(null);

  async function submit() {
    if (busy.current || form.blocked) return;
    busy.current = true;
    setPending(true);
    form.clear();
    setRefused(null);
    try {
      await guarded.run((extra) => del.mutateAsync({endpointId: endpoint.id, hostId: host.id, ...(extra.lock_passwords ? {lockPasswords: extra.lock_passwords} : {})}), [endpoint], {takesAll: hostDeleteEmptiesStack(endpoint.require_authorized_ips, endpoint.legacy_dns, claims.data), reset: del.reset});
      toast.success(t("ips.ddns.deleted"));
      onClose();
    } catch (error) {
      if (error instanceof Cancelled) return;
      const codes = Object.values(fieldErrors(error));
      if (hasCode(error, "validation_failed") && codes.includes("current_address")) setRefused(e("fields.current_address"));
      else if (hasCode(error, "validation_failed") && codes.includes("last_authorized")) setRefused(e("fields.last_authorized"));
      else form.fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  return (
    <>
      <DialogFrame
        isOpen
        onClose={onClose}
        isLocked={pending}
        title={t("ips.ddns.deleteTitle", {name: host.hostname})}
        footer={
          <>
            <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={pending} isDisabled={form.retryIn > 0} onPress={() => void submit()}>
              {t("ips.ddns.deleteSubmit")}
            </Button>
          </>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          <p className="text-sm">{t("ips.ddns.deleteText")}</p>
          {refused ? (
            <p role="alert" className="text-danger-soft-foreground text-sm">
              {refused}
            </p>
          ) : null}
          <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        </AuthForm>
      </DialogFrame>
      {guarded.dialogs}
    </>
  );
}
