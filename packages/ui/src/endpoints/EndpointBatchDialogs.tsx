"use client";

import {useBatchEndpoints, useGroups, type AdminState, type AnalyticsLevel, type Endpoint, type EndpointBatch} from "@ctrlz/api-client/hooks/endpoints.ts";
import {tooManyLockPasswords} from "@ctrlz/api-client/hooks/lockPasswords.ts";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {Alert, Button, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError} from "../forms/FormError.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {useOnlineStatus} from "../forms/useOnlineStatus.ts";
import {isDisabling} from "./endpointModel.ts";
import {SelectField, type Choice} from "./fields.tsx";
import {Cancelled, useGuardedWrite} from "./useGuardedWrite.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p3 10 (T-230): the header bar of the selection has Move, Edit and Delete (Delete is EndpointDeleteDialog). Both here are state of
// the list, not of the address: they act on a selection that can hold 500 ids. They send `POST /endpoints:batch`, ask for lock passwords
// and for the confirmation of lost destinations as every Endpoint write does (useGuardedWrite).

const KEEP = "__keep__";
const NONE = "__none__";

export function MoveEndpointsDialog({endpoints, onClose, onDone}: {endpoints: Endpoint[]; onClose: () => void; onDone: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const groups = useGroups();
  const batch = useBatchEndpoints();
  const guarded = useGuardedWrite();
  const form = useApiForm({fieldNamespace: "profiles"});
  const online = useOnlineStatus();
  // Nothing is chosen at first: a plain press on Move must not take every selected Endpoint out of its group.
  const [group, setGroup] = useState<string | null>(null);
  const busy = useRef(false);
  const choices: Choice[] = [
    {id: NONE, textValue: t("dialogs.fields.noGroup"), label: t("dialogs.fields.noGroup")},
    ...(groups.data ?? []).map((g) => ({id: g.id, textValue: g.name, label: g.name})),
  ];

  async function submit() {
    if (busy.current || form.blocked || group === null) return;
    busy.current = true;
    form.clear();
    try {
      const body: EndpointBatch = {ids: endpoints.map((e) => e.id), op: "move", ...(group === NONE ? {clear: ["group_id"]} : {group_id: group})};
      await guarded.run((extra) => batch.mutateAsync({...body, ...extra}), [], {reset: batch.reset});
      toast.success(t("dialogs.move.done", {count: endpoints.length}));
      onDone();
      onClose();
    } catch (error) {
      if (!(error instanceof Cancelled)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <>
      <DialogFrame
        isOpen
        onClose={onClose}
        isLocked={batch.isPending}
        title={t("dialogs.move.title", {count: endpoints.length})}
        footer={
          <>
            <Button variant="tertiary" isDisabled={batch.isPending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <PrimaryButton isPending={batch.isPending} isDisabled={!online || group === null || form.retryIn > 0} onPress={() => void submit()}>
              {t("dialogs.move.submit")}
            </PrimaryButton>
          </>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          <SelectField name="group" label={t("dialogs.move.group")} placeholder={t("dialogs.move.choose")} options={choices} value={group} isDisabled={batch.isPending} onChange={setGroup} />
          <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        </AuthForm>
      </DialogFrame>
      {guarded.dialogs}
    </>
  );
}

export function EditEndpointsDialog({endpoints, onClose, onDone}: {endpoints: Endpoint[]; onClose: () => void; onDone: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const profiles = useProfiles();
  const batch = useBatchEndpoints();
  const guarded = useGuardedWrite();
  const form = useApiForm({fieldNamespace: "profiles"});
  const online = useOnlineStatus();
  const [profile, setProfile] = useState(KEEP);
  const [profile2, setProfile2] = useState(KEEP);
  const [analytics, setAnalytics] = useState(KEEP);
  const [state, setState] = useState(KEEP);
  const busy = useRef(false);
  const keep: Choice = {id: KEEP, textValue: t("dialogs.batch.keep"), label: t("dialogs.batch.keep")};
  const profileChoices: Choice[] = (profiles.data ?? []).map((p) => ({id: p.id, textValue: p.name, label: p.locked ? t("dialogs.fields.profileLocked", {name: p.name}) : p.name}));

  async function submit() {
    if (busy.current || form.blocked) return;
    const set: NonNullable<EndpointBatch["set"]> = {};
    const clear: NonNullable<EndpointBatch["clear"]> = [];
    if (profile !== KEEP) set.profile_id = profile;
    if (profile2 === NONE) clear.push("profile2_id");
    else if (profile2 !== KEEP) set.profile2_id = profile2;
    if (analytics !== KEEP) set.analytics_level = analytics as AnalyticsLevel;
    if (state !== KEEP) set.admin_state = state as AdminState;
    if (Object.keys(set).length === 0 && clear.length === 0) return form.setFieldError("profile", t("dialogs.batch.nothing"));
    busy.current = true;
    form.clear();
    try {
      const body: EndpointBatch = {ids: endpoints.map((e) => e.id), op: "edit", ...(Object.keys(set).length ? {set} : {}), ...(clear.length ? {clear} : {})};
      await guarded.run((extra) => batch.mutateAsync({...body, ...extra}), endpoints, {takesAll: state !== KEEP && endpoints.some((e) => isDisabling(e.admin_state, state as AdminState)), reset: batch.reset});
      toast.success(t("dialogs.batch.done", {count: endpoints.length}));
      onDone();
      onClose();
    } catch (error) {
      if (!(error instanceof Cancelled)) form.fail(error, {rename: {"/set/profile_id": "profile", "/set/profile2_id": "profile2"}});
    } finally {
      busy.current = false;
    }
  }

  const tooMany = form.formError !== null && tooManyLockPasswords(form.formError);
  const hint = state === "enabled" ? t("dialogs.fields.statusHint.active") : undefined;
  return (
    <>
      <DialogFrame
        isOpen
        onClose={onClose}
        isLocked={batch.isPending}
        title={t("dialogs.batch.title", {count: endpoints.length})}
        footer={
          <>
            <Button variant="tertiary" isDisabled={batch.isPending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <PrimaryButton isPending={batch.isPending} isDisabled={!online || form.retryIn > 0} onPress={() => void submit()}>
              {t("dialogs.batch.submit")}
            </PrimaryButton>
          </>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          <p className="text-muted text-sm">{t("dialogs.batch.text")}</p>
          <SelectField
            name="profile"
            label={t("dialogs.fields.profile")}
            options={[keep, ...profileChoices]}
            value={profile}
            isDisabled={batch.isPending}
            error={form.fieldMessage("profile")}
            onChange={(v) => form.bind("profile", setProfile).onChange(v)}
          />
          <SelectField
            name="profile2"
            label={t("dialogs.fields.profileTwo")}
            options={[keep, {id: NONE, textValue: t("dialogs.batch.profileTwoNone"), label: t("dialogs.batch.profileTwoNone")}, ...profileChoices]}
            value={profile2}
            isDisabled={batch.isPending}
            error={form.fieldMessage("profile2")}
            onChange={(v) => form.bind("profile2", setProfile2).onChange(v)}
          />
          <SelectField
            name="analytics"
            label={t("dialogs.fields.analytics")}
            options={[
              keep,
              {id: "none", textValue: t("dialogs.fields.analyticsNone"), label: t("dialogs.fields.analyticsNone")},
              {id: "some", textValue: t("dialogs.fields.analyticsSome"), label: t("dialogs.fields.analyticsSome")},
              {id: "full", textValue: t("dialogs.fields.analyticsFull"), label: t("dialogs.fields.analyticsFull")},
            ]}
            value={analytics}
            isDisabled={batch.isPending}
            onChange={setAnalytics}
          />
          <SelectField
            name="status"
            label={t("dialogs.fields.status")}
            options={[
              keep,
              {id: "enabled", textValue: t("state.enabled"), label: t("state.enabled")},
              {id: "soft_disabled", textValue: t("state.soft_disabled"), label: t("state.soft_disabled")},
              {id: "hard_disabled", textValue: t("state.hard_disabled"), label: t("state.hard_disabled")},
            ]}
            value={state}
            isDisabled={batch.isPending}
            description={hint}
            onChange={setState}
          />
          {state === "soft_disabled" || state === "hard_disabled" ? (
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Description>{t(`dialogs.fields.statusHint.${state}`)}</Alert.Description>
              </Alert.Content>
            </Alert>
          ) : null}
          <CapacityNotice error={form.formError} />
          <FormError error={form.formError} message={tooMany ? t("dialogs.locks.tooMany") : undefined} form={form} onRetry={() => void submit()} />
        </AuthForm>
      </DialogFrame>
      {guarded.dialogs}
    </>
  );
}
