"use client";

import {hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {useBatchEndpoints, useDeleteEndpoint, type Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useFreeDns} from "@ctrlz/api-client/hooks/freeDns.ts";
import {endpointKeys} from "@ctrlz/api-client/hooks/profileKeys.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, Button, Checkbox, toast} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError} from "../forms/FormError.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {useOnlineStatus} from "../forms/useOnlineStatus.ts";
import {heldIndexes} from "./endpointModel.ts";
import {Cancelled, useGuardedWrite} from "./useGuardedWrite.tsx";

// Spec p3 3.6 and 10 (T-233): a warning mark, the sentence that the devices of the Endpoint lose DNS, and a box to tick. The same dialog
// deletes one Endpoint (`deviceDialog=delete` + `deviceId`) and a selection (state of the list, since 500 ids do not belong in an address).
// An Endpoint that an administrator holds (D34) cannot be deleted: it is named before the button, and the button stays off while one is
// among them. `endpoint_held` after all (a hold that came in between, or a suspended address claim, which the payload does not show) names the
// Endpoints by the place of their id in the request, in words that do not say who holds them (S5-r2-6).

export function EndpointDeleteDialog({endpoints, onClose, onDeleted}: {endpoints: Endpoint[]; onClose: () => void; onDeleted?: () => boolean | void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const del = useDeleteEndpoint();
  const batch = useBatchEndpoints();
  const guarded = useGuardedWrite();
  const queryClient = useQueryClient();
  const form = useApiForm({fieldNamespace: "profiles"});
  const online = useOnlineStatus();
  const [confirmed, setConfirmed] = useState(false);
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  const one = endpoints.length === 1 ? endpoints[0]! : null;
  const held = endpoints.filter((e) => e.admin_hold);
  // T-557: what a Plain DNS device gets once its Endpoint is gone depends on the switch of free DNS; while it is not known nothing is said about it.
  const plain = endpoints.some((e) => e.legacy_dns);
  const free = useFreeDns({enabled: plain});
  const heldNow = isApiError(form.formError) && hasCode(form.formError, "endpoint_held") ? heldIndexes(form.formError.fields).map((i) => endpoints[i]?.name).filter((n): n is string => !!n) : null;

  async function submit() {
    if (busy.current || form.blocked || !confirmed || held.length > 0) return;
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      if (one) await guarded.run((extra) => del.mutateAsync({id: one.id, ...(extra.lock_passwords ? {lockPasswords: extra.lock_passwords} : {})}), endpoints, {takesAll: true, reset: del.reset});
      else await guarded.run((extra) => batch.mutateAsync({ids: endpoints.map((e) => e.id), op: "delete", ...extra}), endpoints, {takesAll: true, reset: batch.reset});
      toast.success(one ? t("dialogs.delete.done") : t("dialogs.delete.doneMany", {count: endpoints.length}));
      // A caller that left the page (the Endpoint's own, which is gone) says so, and the dialog does not touch the address after it.
      if (onDeleted?.() !== true) onClose();
    } catch (error) {
      if (!(error instanceof Cancelled)) {
        // A hold that came in after the list was read: read it again, so the dialog names the held Endpoint and the button stays off.
        if (hasCode(error, "endpoint_held")) void queryClient.invalidateQueries({queryKey: endpointKeys.all});
        form.fail(error);
      }
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
        title={one ? t("dialogs.delete.title", {name: one.name}) : t("dialogs.delete.batchTitle", {count: endpoints.length})}
        footer={
          <>
            <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={pending} isDisabled={!online || !confirmed || held.length > 0 || form.retryIn > 0} onPress={() => void submit()}>
              {t("dialogs.delete.submit")}
            </Button>
          </>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          <div className="flex items-start gap-3">
            <span aria-hidden="true" className="bg-danger-soft text-danger-soft-foreground grid size-10 shrink-0 place-items-center rounded-full">
              <Icon name="warning" className="size-5" />
            </span>
            <p className="text-sm">{one ? t("dialogs.delete.text", {name: one.name}) : t("dialogs.delete.batchText")}</p>
          </div>
          {plain && free.enabled !== null ? (
            <p className="text-muted text-sm" data-testid="delete-free-dns">
              {free.enabled ? t("dialogs.delete.freeDnsOn") : t("dialogs.delete.freeDnsOff")}
            </p>
          ) : null}
          {held.length > 0 ? (
            <Alert status="warning" role="status">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t("dialogs.delete.heldTitle")}</Alert.Title>
                <Alert.Description>{t("dialogs.delete.heldText", {names: held.map((e) => e.name).join(t("dialogs.delete.separator"))})}</Alert.Description>
              </Alert.Content>
            </Alert>
          ) : null}
          <Checkbox isSelected={confirmed} onChange={setConfirmed} isDisabled={pending} name="confirm-delete">
            <Checkbox.Content>
              <Checkbox.Control>
                <Checkbox.Indicator />
              </Checkbox.Control>
              <span className="text-sm">{t("dialogs.delete.confirm")}</span>
            </Checkbox.Content>
          </Checkbox>
          <FormError
            error={form.formError}
            message={heldNow && heldNow.length > 0 ? t("dialogs.delete.heldRefused", {names: heldNow.join(t("dialogs.delete.separator"))}) : undefined}
            form={form}
            onRetry={() => void submit()}
          />
        </AuthForm>
      </DialogFrame>
      {guarded.dialogs}
    </>
  );
}
