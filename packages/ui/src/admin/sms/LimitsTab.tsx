"use client";

import {limitsQueryOptions, useLimits, useSaveLimits, type SmsLimits} from "@ctrlz/api-client/admin/hooks/sms.ts";
import {Button, Card, Description, FieldError, Input, Label, Skeleton, TextField, toast} from "@heroui/react";
import {SectionError} from "../../feedback/SectionError.tsx";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";
import {useRef} from "react";

import {ConflictNote} from "../shared/ConflictNote.tsx";
import {IntegerField} from "../shared/IntegerField.tsx";
import {isMoney, normalizeMoney, sameMoney} from "../shared/money.ts";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerForm} from "../shared/useServerDraft.ts";
import {keepFocus, keepRetry} from "../shared/restoreFocus.ts";

// Spec 13.3, the Limits tab: a numeric field for each `SmsLimits` field. The bounds are the document's (a cap of 1 or more,
// a cooldown of 10 s to an hour, a soft threshold of 1 to 100 per cent, an outbox cap of 0 or more), and the page checks
// them before it asks, so a request is never a 400 the person could have seen. `PUT /sms/limits` replaces the whole object
// and needs the fresh TOTP window, so the form sends every field. The money cap is Rial as a decimal string and may be
// empty (no money cap).

const INT_MAX = 2_147_483_647;

type NumericName = Exclude<keyof SmsLimits, "sms_cost_cap_daily">;

const FIELDS: readonly {name: NumericName; min: number; max: number; group: "otp" | "sms"}[] = [
  {name: "otp_cap_phone", min: 1, max: INT_MAX, group: "otp"},
  {name: "otp_cap_phone_net", min: 1, max: INT_MAX, group: "otp"},
  {name: "otp_cap_ip", min: 1, max: INT_MAX, group: "otp"},
  {name: "otp_cap_net24", min: 1, max: INT_MAX, group: "otp"},
  {name: "otp_cap_phone_trusted", min: 1, max: INT_MAX, group: "otp"},
  {name: "otp_cap_net48", min: 1, max: INT_MAX, group: "otp"},
  {name: "otp_cap_global", min: 1, max: INT_MAX, group: "otp"},
  {name: "otp_cooldown_s", min: 10, max: 3600, group: "otp"},
  {name: "otp_soft_pct", min: 1, max: 100, group: "otp"},
  {name: "sms_outbox_cap_daily", min: 0, max: INT_MAX, group: "sms"},
];

export function LimitsTab() {
  const t = useTranslations("admin");
  const limits = useLimits();
  if (limits.isPending) return <Skeleton className="h-64 w-full rounded-(--radius-box)" />;
  if (!limits.data) return <SectionError error={limits.error} onRetry={keepRetry(() => limits.refetch())} />;
  return (
    <Card className="max-w-3xl gap-4 p-6" data-testid="sms-limits">
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("sms.limits.title")}</Card.Title>
        <Card.Description>{t("sms.limits.text")}</Card.Description>
      </Card.Header>
      <Card.Content>
        <RefreshFailed error={limits.error} onRetry={() => limits.refetch()} />
        <LimitsForm current={limits.data} />
      </Card.Content>
    </Card>
  );
}

// One flat object, a field each, so an edit of one limit is one key of the patch and every other limit is what the server holds
// now (wp10-r4-3): the PUT replaces the whole object, and a copy of the others from an earlier render would undo another admin.
type Draft = Record<NumericName, number | undefined> & {cap: string};

/** The form's fields as the server holds them. The money cap comes back as numeric(14,4), "250000.0000" (wp10-r3-3). */
function draftOf(current: SmsLimits): Draft {
  return {...(Object.fromEntries(FIELDS.map((f) => [f.name, current[f.name]])) as Record<NumericName, number>), cap: current.sms_cost_cap_daily ?? ""};
}

const sameDraft = (a: Draft, b: Draft) => FIELDS.every((f) => a[f.name] === b[f.name]) && sameMoney(a.cap, b.cap);

function LimitsForm({current}: {current: SmsLimits}) {
  const t = useTranslations("admin");
  const save = useSaveLimits();
  // The read, the fresh-code dialog and the PUT are one pending state (wp10-r7-2, wp10-r7-5).
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  // A shown number goes through the page's formatter and, like the field it names, without grouping (spec 4.4, wp10-r20-3).
  const format = useAppFormat();
  const {draft, edit, dirty, reset, saved, conflicts, serverValue, keepMine, takeServer} = useServerForm(draftOf(current), sameDraft);
  // A field another admin changed after this one edited it: Save waits for an answer, since the write would replace their value (wp10-r5-3).
  const conflicted = conflicts.length > 0;
  const {cap} = draft;
  const setCap = (value: string) => edit({cap: value});
  const busy = useRef(false);

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflicted) return;
    const body: Partial<Record<NumericName, number>> = {};
    for (const f of FIELDS) {
      const v = draft[f.name];
      if (v === undefined || !Number.isInteger(v) || v < f.min || v > f.max) {
        return form.setFieldError(f.name, f.max === INT_MAX ? t("sms.limits.rangeMin", {min: f.min}) : t("sms.limits.range", {min: f.min, max: f.max}));
      }
      body[f.name] = v;
    }
    const money = normalizeMoney(cap);
    if (!isMoney(money)) return form.setFieldError("sms_cost_cap_daily", t("sms.edit.costInvalid"));
    busy.current = true;
    form.clear();
    try {
      // The page does not refetch while it stays open, so the value this write replaces is read before every try of it, the
      // one after the fresh-code dialog included (wp10-r6-5, wp10-r7-5).
      const written = await write({options: limitsQueryOptions(), pick: draftOf, seen: draftOf(current), same: sameDraft}, () =>
        save.mutateAsync({...(body as Record<NumericName, number>), ...(money === "" ? {} : {sms_cost_cap_daily: money})} as SmsLimits),
      );
      if (!written) return;
      saved(draft);
      toast.success(t("sms.limits.saved"));
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  const group = (name: "otp" | "sms") => FIELDS.filter((f) => f.group === name);

  const note = (key: keyof Draft, value: string | number | undefined) =>
    conflicts.includes(key) ? (
      <ConflictNote
        name={key}
        value={typeof value === "number" ? format.number(value, {useGrouping: false}) : value}
        onKeep={() => keepMine(key)}
        onUseServer={() => {
          takeServer(key);
          form.clearField(key === "cap" ? "sms_cost_cap_daily" : key);
        }}
      />
    ) : null;

  function numberField(f: (typeof FIELDS)[number]) {
    return (
      <div key={f.name} className="flex flex-col gap-2">
      <IntegerField
        name={f.name}
        label={t(`sms.limits.fields.${f.name}.label`)}
        description={t(`sms.limits.fields.${f.name}.hint`)}
        value={draft[f.name]}
        onChange={(v) => {
          edit({[f.name]: v});
          form.clearField(f.name);
        }}
        min={f.min}
        max={f.max}
        isDisabled={pending}
        error={form.fieldMessage(f.name)}
        invalidMessage={f.max === INT_MAX ? t("sms.limits.rangeMin", {min: f.min}) : t("sms.limits.range", {min: f.min, max: f.max})}
      />
      {note(f.name, serverValue[f.name])}
      </div>
    );
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <fieldset className="flex flex-col gap-4" disabled={pending}>
        <legend className="mb-3 text-sm font-medium">{t("sms.limits.groups.otp")}</legend>
        <div className="grid gap-4 sm:grid-cols-2">{group("otp").map(numberField)}</div>
      </fieldset>
      <fieldset className="flex flex-col gap-4" disabled={pending}>
        <legend className="mb-3 text-sm font-medium">{t("sms.limits.groups.sms")}</legend>
        <div className="grid gap-4 sm:grid-cols-2">
          {group("sms").map(numberField)}
          <div className="flex flex-col gap-2">
          <TextField
            name="sms_cost_cap_daily"
            variant="secondary"
            fullWidth
            autoComplete="off"
            inputMode="decimal"
            isDisabled={pending}
            isInvalid={form.fieldMessage("sms_cost_cap_daily") !== undefined}
            value={cap}
            onChange={form.bind("sms_cost_cap_daily", setCap).onChange}
          >
            <Label>{t("sms.limits.fields.sms_cost_cap_daily.label")}</Label>
            <Input dir="ltr" className="text-start" />
            <Description>{t("sms.limits.fields.sms_cost_cap_daily.hint")}</Description>
            <FieldError>{form.fieldMessage("sms_cost_cap_daily")}</FieldError>
          </TextField>
          {note("cap", serverValue.cap)}
          </div>
        </div>
      </fieldset>
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <div className="flex flex-wrap justify-end gap-2">
        <Button
          variant="tertiary"
          isDisabled={!dirty || pending}
          onPress={() => {
            form.clear();
            reset();
          }}
        >
          {t("settings.cancel")}
        </Button>
        <Button type="submit" variant="primary" isPending={pending} isDisabled={!dirty || conflicted || form.retryIn > 0}>
          {form.retryIn > 0 ? t("settings.retryIn", {seconds: form.retryIn}) : t("sms.limits.submit")}
        </Button>
      </div>
    </AuthForm>
  );
}
