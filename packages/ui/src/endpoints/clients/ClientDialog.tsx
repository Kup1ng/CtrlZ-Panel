"use client";

import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {useCreateClient, usePatchClient, type Client} from "@ctrlz/api-client/hooks/clients.ts";
import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {Button, Description, FieldError, Input, Label, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {cleanProse, nameLength} from "../../forms/invisible.ts";
import {useApiForm} from "../../forms/useApiForm.ts";
import {SelectField, type Choice} from "../fields.tsx";
import {Cancelled, useGuardedWrite} from "../useGuardedWrite.tsx";
import {ANALYTICS_KEY, diffFields, fieldsOf, MAX_LABEL, MAX_TEXT, type ClientFields} from "./clientsModel.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// The Custom Client dialog (spec p3 10, T-258): `deviceDialog=client` makes one; a row's Edit changes one (state of the screen, since the
// client's id is not one of the dialog parameters). A client has an alias, a group, and optionally profiles of its own and an Analytics
// level that replace the Endpoint's for the traffic of that client. Empty means "as the Endpoint".

const SAME = "__endpoint__";

export function ClientDialog({endpoint, client, onClose}: {endpoint: Endpoint; client: Client | null; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const profiles = useProfiles();
  const create = useCreateClient();
  const patch = usePatchClient();
  const guarded = useGuardedWrite();
  const form = useApiForm({focus: client ? "alias" : "label", fieldNamespace: "profiles"});
  const busy = useRef(false);
  const [first] = useState(() => fieldsOf(client));
  const [label, setLabel] = useState("");
  const [fields, setFields] = useState<ClientFields>(first);
  const [pending, setPending] = useState(false);
  const set = <K extends keyof ClientFields>(key: K, value: ClientFields[K]) => setFields((prev) => ({...prev, [key]: value}));

  const profileChoices: Choice[] = (profiles.data ?? []).map((p) => ({id: p.id, textValue: p.name, label: p.locked ? t("dialogs.fields.profileLocked", {name: p.name}) : p.name}));
  const withSame = (own: string): Choice[] => [{id: SAME, textValue: own, label: own}, ...profileChoices];
  const second = withSame(t("clients.dialog.sameAsEndpoint")).filter((x) => x.id !== fields.profileId);
  const analyticsChoices: Choice[] = (Object.keys(ANALYTICS_KEY) as (keyof typeof ANALYTICS_KEY)[]).map((k) => ({id: k, textValue: t(`dialogs.fields.${ANALYTICS_KEY[k]}`), label: t(`dialogs.fields.${ANALYTICS_KEY[k]}`)}));
  analyticsChoices.unshift({id: SAME, textValue: t("clients.dialog.sameAsEndpoint"), label: t("clients.dialog.sameAsEndpoint")});

  async function submit() {
    if (busy.current || form.blocked) return;
    const cleanLabel = cleanProse(label).toLowerCase();
    const alias = cleanProse(fields.alias);
    const group = cleanProse(fields.group);
    if (!client && cleanLabel !== "" && nameLength(cleanLabel) > MAX_LABEL) return form.setFieldError("label", e("fields.too_long"));
    if (nameLength(alias) > MAX_TEXT) return form.setFieldError("alias", e("fields.too_long"));
    if (nameLength(group) > MAX_TEXT) return form.setFieldError("group", e("fields.too_long"));
    if (!client && cleanLabel === "" && alias === "") return form.setFieldError("label", e("fields.required"));
    if (fields.profile2Id && !fields.profileId) return form.setFieldError("profile2", e("fields.required"));
    const now: ClientFields = {...fields, alias, group};
    busy.current = true;
    setPending(true);
    form.clear();
    // Only the profiles that this client names matter to a lock: the Endpoint's own are asked when the write needs them (the 423 names none).
    const involved = [endpoint, {profile_id: first.profileId ?? endpoint.profile_id, profile2_id: first.profile2Id ?? undefined}, {profile_id: now.profileId ?? endpoint.profile_id, profile2_id: now.profile2Id ?? undefined}];
    try {
      if (client) {
        const body = diffFields(first, now);
        if (!body) return onClose();
        await guarded.run((extra) => patch.mutateAsync({endpointId: endpoint.id, clientId: client.id, ...body, ...extra}), involved, {reset: patch.reset});
        toast.success(t("clients.dialog.saved"));
      } else {
        await guarded.run(
          (extra) =>
            create.mutateAsync({
              endpointId: endpoint.id,
              ...(cleanLabel ? {label: cleanLabel} : {}),
              ...(alias ? {alias} : {}),
              ...(group ? {group_name: group} : {}),
              ...(now.profileId ? {profile_id: now.profileId} : {}),
              ...(now.profile2Id ? {profile2_id: now.profile2Id} : {}),
              ...(now.analytics ? {analytics_level: now.analytics} : {}),
              ...extra,
            }),
          involved,
          {reset: create.reset},
        );
        toast.success(t("clients.dialog.created"));
      }
      onClose();
    } catch (error) {
      if (!(error instanceof Cancelled)) form.fail(error, {rename: {"/label": "label", "/alias": "alias", "/group_name": "group", "/profile_id": "profile", "/profile2_id": "profile2", "/analytics_level": "analytics"}});
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
        title={client ? t("clients.dialog.editTitle", {name: client.alias ?? client.label}) : t("clients.dialog.createTitle")}
        footer={
          <>
            <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <PrimaryButton isPending={pending} isDisabled={form.retryIn > 0} onPress={() => void submit()}>
              {client ? t("clients.dialog.save") : t("clients.dialog.create")}
            </PrimaryButton>
          </>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          {client ? null : (
            <TextField fullWidth name="label" value={label} isDisabled={pending} isInvalid={form.fieldMessage("label") !== undefined} onChange={(v) => form.bind("label", setLabel).onChange(v)}>
              <Label>{t("clients.dialog.label")}</Label>
              <Input autoComplete="off" dir="ltr" autoCapitalize="none" spellCheck={false} />
              <Description>
                {t("clients.dialog.labelHint")} {t("clients.dialog.labelVisible")}
              </Description>
              <FieldError>{form.fieldMessage("label")}</FieldError>
            </TextField>
          )}
          <TextField fullWidth name="alias" value={fields.alias} isDisabled={pending} isInvalid={form.fieldMessage("alias") !== undefined} onChange={(v) => form.bind("alias", (x: string) => set("alias", x)).onChange(v)}>
            <Label>{t("clients.dialog.alias")}</Label>
            <Input autoComplete="off" dir="auto" />
            <FieldError>{form.fieldMessage("alias")}</FieldError>
          </TextField>
          <TextField fullWidth name="group" value={fields.group} isDisabled={pending} isInvalid={form.fieldMessage("group") !== undefined} onChange={(v) => form.bind("group", (x: string) => set("group", x)).onChange(v)}>
            <Label>{t("clients.dialog.group")}</Label>
            <Input autoComplete="off" dir="auto" />
            <FieldError>{form.fieldMessage("group")}</FieldError>
          </TextField>
          <SelectField
            label={t("dialogs.fields.profile")}
            name="profile"
            isDisabled={pending}
            error={form.fieldMessage("profile")}
            options={withSame(t("clients.dialog.sameAsEndpoint"))}
            value={fields.profileId ?? SAME}
            onChange={(v) => {
              form.clearField("profile");
              setFields((prev) => ({...prev, profileId: v === SAME ? null : v, profile2Id: v === SAME || prev.profile2Id === v ? null : prev.profile2Id}));
            }}
          />
          {fields.profileId ? (
            <SelectField
              label={t("dialogs.fields.profileTwo")}
              name="profile2"
              isDisabled={pending}
              error={form.fieldMessage("profile2")}
              options={second}
              value={fields.profile2Id ?? SAME}
              onChange={(v) => {
                form.clearField("profile2");
                set("profile2Id", v === SAME ? null : v);
              }}
            />
          ) : null}
          <SelectField
            label={t("dialogs.fields.analytics")}
            name="analytics"
            isDisabled={pending}
            error={form.fieldMessage("analytics")}
            options={analyticsChoices}
            value={fields.analytics ?? SAME}
            onChange={(v) => set("analytics", v === SAME ? null : (v as "none" | "some" | "full"))}
          />
          <CapacityNotice error={form.formError} />
          <FormError error={exceededCap(form.formError) ? null : form.formError} form={form} onRetry={() => void submit()} />
        </AuthForm>
      </DialogFrame>
      {guarded.dialogs}
    </>
  );
}
