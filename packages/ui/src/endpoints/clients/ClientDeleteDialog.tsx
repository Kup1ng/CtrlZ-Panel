"use client";

import {useBatchClients, useClients, type Client} from "@ctrlz/api-client/hooks/clients.ts";
import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Checkbox, FieldError, Input, Label, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useDeferredValue, useRef, useState} from "react";

import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {useApiForm} from "../../forms/useApiForm.ts";
import {useOnlineStatus} from "../../forms/useOnlineStatus.ts";
import {Cancelled, useGuardedWrite, type WriteExtra} from "../useGuardedWrite.tsx";
import {DEFAULT_INACTIVE_DAYS, MAX_INACTIVE_DAYS, MIN_INACTIVE_DAYS, parseDays} from "./clientsModel.ts";

// The three deletes of the Clients page (spec p3 10, 9.3, T-258, T-259): the clients that were ticked (`ids`), the clients that have been
// quiet for N days (a `selector`, with their number shown BEFORE the button), and all of them (`selector: {all}`). The server takes at most
// 500 for a selector in one call and says `more`; the dialog calls again until it is false, with the lock passwords the first call needed
// kept in this function and nowhere else, so a long delete asks once. One confirmation box for each, because every one of them is final.

export type DeleteMode = {kind: "ids"; clients: Client[]} | {kind: "inactive"} | {kind: "all"};

export function ClientDeleteDialog({endpoint, mode, total, onClose, onDone}: {endpoint: Endpoint; mode: DeleteMode; total: number | undefined; onClose: () => void; onDone: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const format = useAppFormat();
  const batch = useBatchClients();
  const guarded = useGuardedWrite();
  const form = useApiForm({fieldNamespace: "profiles"});
  const online = useOnlineStatus();
  const busy = useRef(false);
  const [confirmed, setConfirmed] = useState(false);
  const [pending, setPending] = useState(false);
  const [deleted, setDeleted] = useState(0);
  const [daysText, setDaysText] = useState(String(DEFAULT_INACTIVE_DAYS));
  const days = parseDays(daysText);
  // The count under the box follows the typing, a moment behind it, so each digit is not a request.
  const askedDays = useDeferredValue(days);
  const inactive = useClients(mode.kind === "inactive" && askedDays !== null ? endpoint.id : undefined, askedDays !== null ? {inactive_days: askedDays} : {});
  const count = mode.kind === "ids" ? mode.clients.length : mode.kind === "all" ? total : askedDays === null || askedDays !== days ? undefined : inactive.count;
  const countKnown = count !== undefined;

  async function submit() {
    if (busy.current || form.blocked || !confirmed || !countKnown || count === 0) return;
    if (mode.kind === "inactive" && days === null) return;
    busy.current = true;
    setPending(true);
    setDeleted(0);
    form.clear();
    // The passwords of the first answer are kept for the repeats of one delete (500 clients at a time) and dropped with this call.
    let remembered: WriteExtra = {};
    const target = mode.kind === "ids" ? {ids: mode.clients.map((x) => x.id)} : mode.kind === "all" ? {selector: {all: true as const}} : {selector: {inactive_days: days!}};
    const involved = [endpoint, ...(mode.kind === "ids" ? mode.clients.map((x) => ({profile_id: x.profile_id ?? endpoint.profile_id, profile2_id: x.profile2_id})) : [])];
    let sum = 0;
    try {
      for (;;) {
        const answer = await guarded.run(
          (extra) => {
            remembered = {...remembered, ...extra};
            return batch.mutateAsync({endpointId: endpoint.id, op: "delete", ...target, ...remembered});
          },
          involved,
          {reset: batch.reset},
        );
        sum += answer.affected;
        setDeleted(sum);
        if (!answer.more || answer.affected === 0) break;
      }
      remembered = {};
      toast.success(t("clients.delete.done", {count: sum}));
      onDone();
      onClose();
    } catch (error) {
      remembered = {};
      if (!(error instanceof Cancelled)) form.fail(error);
      // Some were gone before it failed: the list is read again by the mutation's own refresh, and the dialog says how many.
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  const title = mode.kind === "ids" ? t("clients.delete.titleIds", {count: mode.clients.length}) : mode.kind === "inactive" ? t("clients.delete.titleInactive") : t("clients.delete.titleAll");
  const text =
    mode.kind === "ids"
      ? t("clients.delete.textIds", {count: mode.clients.length})
      : mode.kind === "inactive"
        ? countKnown
          ? t("clients.delete.textInactive", {count, days: days ?? 0})
          : t("clients.delete.counting")
        : countKnown
          ? t("clients.delete.textAll", {count})
          : t("clients.delete.counting");

  return (
    <>
      <DialogFrame
        isOpen
        onClose={onClose}
        isLocked={pending}
        title={title}
        footer={
          <>
            <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={pending} isDisabled={!online || !confirmed || !countKnown || count === 0 || form.retryIn > 0 || (mode.kind === "inactive" && days === null)} onPress={() => void submit()}>
              {t("clients.delete.submit")}
            </Button>
          </>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          {mode.kind === "inactive" ? (
            <TextField fullWidth name="days" value={daysText} isDisabled={pending} isInvalid={days === null} onChange={setDaysText}>
              <Label>{t("clients.delete.days")}</Label>
              <Input inputMode="numeric" autoComplete="off" dir="ltr" />
              <p className="text-muted text-xs">{t("clients.delete.daysHint", {min: format.number(MIN_INACTIVE_DAYS), max: format.number(MAX_INACTIVE_DAYS)})}</p>
              <FieldError>{days === null ? t("clients.delete.daysInvalid", {min: format.number(MIN_INACTIVE_DAYS), max: format.number(MAX_INACTIVE_DAYS)}) : ""}</FieldError>
            </TextField>
          ) : null}
          <div className="flex items-start gap-3">
            <span aria-hidden="true" className="bg-danger-soft text-danger-soft-foreground grid size-10 shrink-0 place-items-center rounded-full">
              <Icon name="warning" className="size-5" />
            </span>
            <p className="text-sm" role="status" data-testid="delete-count">
              {text}
            </p>
          </div>
          <p className="text-muted text-xs">{t("clients.delete.note")}</p>
          {pending && deleted > 0 ? (
            <p className="text-sm" role="status">
              {t("clients.delete.progress", {count: deleted})}
            </p>
          ) : null}
          <Checkbox isSelected={confirmed} onChange={setConfirmed} isDisabled={pending} name="confirm-delete-clients">
            <Checkbox.Content>
              <Checkbox.Control>
                <Checkbox.Indicator />
              </Checkbox.Control>
              <span className="text-sm">{t("clients.delete.confirm")}</span>
            </Checkbox.Content>
          </Checkbox>
          <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        </AuthForm>
      </DialogFrame>
      {guarded.dialogs}
    </>
  );
}
