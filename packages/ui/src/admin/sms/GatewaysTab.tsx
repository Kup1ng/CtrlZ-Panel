"use client";

import {
  gatewaysQueryOptions,
  smsKeys,
  useGateways,
  useSaveGateway,
  useTemplates,
  useTestGateway,
  useOutbox,
  type LocaleCode,
  type SmsGatewayRequest,
  type SmsGatewayRow,
} from "@ctrlz/api-client/admin/hooks/sms.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useQueryClient} from "@tanstack/react-query";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {isLocale} from "@ctrlz/i18n/locale.ts";
import {Alert, Button, Card, Chip, FieldError, Input, Label, Skeleton, Spinner, TextField, toast} from "@heroui/react";
import {answerMayBeLost} from "../../account/accountApi.ts";
import {Tech} from "../../data/Tech.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {useLeaveGuard} from "../../dialog/useLeaveGuard.ts";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {EditorActions} from "../../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {hasInvisible} from "../../forms/invisible.ts";
import {NO_MANAGER} from "../../forms/noAutofill.ts";
import {PasswordField} from "../../forms/PasswordField.tsx";
import {PhoneField} from "../../forms/PhoneField.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerDraft} from "../shared/useServerDraft.ts";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useMemo, useRef, useState} from "react";

import {ConflictNote} from "../shared/ConflictNote.tsx";
import {FieldSelect} from "../shared/FieldSelect.tsx";
import {LocaleSegment} from "../shared/LocaleSegment.tsx";
import {isMoney, normalizeMoney, sameMoney} from "../shared/money.ts";
import {CREDENTIAL_FIELDS, providerLabel} from "./providers.ts";
import {OneTimeResult} from "../shared/OneTimeResult.tsx";
import {keepFocus, keepRetry} from "../shared/restoreFocus.ts";

// Spec 13.3, the Gateways tab: one card per provider with what the API knows of it (configured, the masked hint, the last
// success and the last error, a breaker that is open, the price), then Edit credentials and Test send. Credentials are
// write-only: the fields start empty, an empty field means unchanged, nothing is ever read back, and the dialog that
// holds them is state-only so a typed key is gone with it. Both writes need the fresh TOTP window.

const ROLE_COLOR = {primary: "accent", fallback: "default", disabled: "default"} as const;

export function GatewaysTab() {
  const t = useTranslations("admin");
  const gateways = useGateways();
  // The dialog holds the provider, not a copy of the row: the price it edits is the one the list holds now, so a read that finds
  // another admin's price (EditForm) shows it here (wp10-r8-3).
  const [editingProvider, setEditingProvider] = useState<string | null>(null);
  const [testing, setTesting] = useState<SmsGatewayRow | null>(null);
  // What the PUT that staged a pair returned, kept in this state and nowhere else: the fingerprint is shown once, joins no URL,
  // storage, toast or query, and goes when the panel closes (admin-r21-5).
  const [staged, setStaged] = useState<{provider: string; fingerprint: string} | null>(null);
  // The credentials PUT is in flight: its answer carries a fingerprint that cannot be asked for again, so the dialog stays shut to Escape
  // and a click outside, as the create dialogs of users and invites do (merge-r3-13, gate-r32-6).
  const [saving, setSaving] = useState(false);

  const editing = gateways.data?.find((g) => g.provider === editingProvider) ?? null;
  const setEditing = (row: SmsGatewayRow | null) => setEditingProvider(row?.provider ?? null);
  // A save closes only its own provider's dialog: the answer can come after another provider's dialog was opened.
  const closeEditing = (provider: string) => setEditingProvider((current) => (current === provider ? null : current));

  if (gateways.isPending) return <Skeleton className="h-40 w-full rounded-(--radius-box)" />;
  if (!gateways.data) return <SectionError error={gateways.error} onRetry={keepRetry(() => gateways.refetch())} />;
  if (gateways.data.length === 0) return <SectionEmpty icon="sms" title={t("sms.gateways.empty")} />;

  return (
    <>
      <RefreshFailed error={gateways.error} onRetry={() => gateways.refetch()} />
      <ul className="grid gap-4 lg:grid-cols-2" aria-label={t("sms.tabs.gateways")}>
        {gateways.data.map((g) => (
          <li key={g.provider}>
            <GatewayCard gateway={g} onEdit={() => setEditing(g)} onTest={() => setTesting(g)} />
          </li>
        ))}
      </ul>
      <DialogFrame isOpen={editing !== null} isLocked={saving} onClose={() => setEditing(null)} title={t("sms.edit.title", {provider: providerLabel(editing?.provider ?? "")})}>
        {editing ? (
          <EditForm
            gateway={editing}
            onClose={() => closeEditing(editing.provider)}
            onBusy={setSaving}
            onStaged={(fingerprint) => setStaged({provider: editing.provider, fingerprint})}
          />
        ) : null}
      </DialogFrame>
      <DialogFrame isOpen={testing !== null} onClose={() => setTesting(null)} title={t("sms.test.title", {provider: providerLabel(testing?.provider ?? "")})}>
        {testing ? <TestForm gateway={testing} onClose={() => setTesting(null)} /> : null}
      </DialogFrame>
      {staged ? <StagedResult staged={staged} onClose={() => setStaged(null)} /> : null}
    </>
  );
}

// The warning is true until the breaker's own end time, whatever the page's age. The stored time stays on the row after it
// has passed, a card stays mounted across refetches, and a clock read once at mount would keep "open until 14:10" on screen at
// 14:30 and send the admin after a gateway that has recovered (wp10-r6-4). So the clock is state that a timer set for the end
// time moves; every other render reads the same value, so rendering stays pure.
const MAX_TIMER_MS = 2 ** 31 - 1;

function useBreakerOpen(until: string | undefined): boolean {
  const end = until === undefined ? Number.NaN : Date.parse(until);
  const [now, setNow] = useState(() => Date.now());
  const open = end > now;
  useEffect(() => {
    if (!open) return;
    // At the end time, and a moment after it, so the clock read then is past it. A far end time is reached in several steps.
    const timer = setTimeout(() => setNow(Date.now()), Math.min(Math.max(end - Date.now(), 0) + 50, MAX_TIMER_MS));
    return () => clearTimeout(timer);
  }, [open, end, now]);
  return open;
}

function GatewayCard({gateway: g, onEdit, onTest}: {gateway: SmsGatewayRow; onEdit: () => void; onTest: () => void}) {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const breakerOpen = useBreakerOpen(g.breaker_open_until);
  // Credentials saved over the API wait for the owner's `ctrlz-admin sms confirm` at the server console and are not used until then (auth spec 10.8, D64).
  const awaiting = g.pending_confirmation === true;

  return (
    <Card className="h-full gap-4 p-5" data-testid={`gateway-${g.provider}`}>
      <Card.Header className="flex flex-row flex-wrap items-center justify-between gap-2">
        <Card.Title className="text-base">
          <Tech mono={false}>{providerLabel(g.provider)}</Tech>
        </Card.Title>
        <span className="flex flex-wrap items-center gap-1.5">
          <Chip size="sm" variant="soft" color={ROLE_COLOR[g.role]}>
            <Chip.Label>{t(`sms.role.${g.role}`)}</Chip.Label>
          </Chip>
          <Chip size="sm" variant="soft" color={g.configured ? "success" : "warning"}>
            <Chip.Label>{g.configured ? t("sms.gateways.configured") : t("sms.gateways.notConfigured")}</Chip.Label>
          </Chip>
          {awaiting ? (
            <Chip size="sm" variant="soft" color="warning" data-testid="gateway-pending">
              <Chip.Label>{t("sms.gateways.pending")}</Chip.Label>
            </Chip>
          ) : null}
        </span>
      </Card.Header>
      <Card.Content className="flex flex-col gap-3">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
          <Row label={t("sms.gateways.hint")}>{g.hint ? <Tech>{g.hint}</Tech> : "—"}</Row>
          <Row label={t("sms.gateways.cost")}>
            {g.cost_per_message ? t("sms.gateways.costValue", {amount: format.number(Number(g.cost_per_message), {maximumFractionDigits: 4})}) : "—"}
          </Row>
          <Row label={t("sms.gateways.lastOk")}>{g.last_ok_at ? format.dateTime(g.last_ok_at) : "—"}</Row>
          <Row label={t("sms.gateways.lastError")}>
            {g.last_error_at ? (
              <span className="flex flex-wrap items-center gap-x-2">
                {format.dateTime(g.last_error_at)}
                {g.last_error_code ? <Tech className="text-xs">{g.last_error_code}</Tech> : null}
              </span>
            ) : (
              "—"
            )}
          </Row>
        </dl>
        {awaiting ? (
          <Alert status="warning" data-testid="gateway-pending-text">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Description className="[overflow-wrap:anywhere]">
                {t.rich("sms.gateways.pendingText", {command: "ctrlz-admin sms pending", cmd: (chunks) => <Tech>{chunks}</Tech>})}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}
        {breakerOpen && g.breaker_open_until ? (
          <Alert status="warning" data-testid="breaker-open">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Description>{t("sms.gateways.breaker", {time: format.dateTime(g.breaker_open_until)})}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}
      </Card.Content>
      <Card.Footer className="flex flex-wrap justify-end gap-2">
        <Button size="sm" variant="secondary" onPress={onEdit}>
          {t("sms.gateways.edit")}
        </Button>
        <Button size="sm" variant="secondary" isDisabled={!g.configured} onPress={onTest}>
          {t("sms.gateways.test")}
        </Button>
      </Card.Footer>
    </Card>
  );
}

function Row({label, children}: {label: string; children: React.ReactNode}) {
  return (
    <>
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </>
  );
}

// The console's confirm line for a pair this session staged. The hint of the pair is chosen by the server and is not the one on the
// row (that describes the ACTIVE credentials), so the line carries H and the text says where the real one is read; the fingerprint
// is the one value only this response holds.
const HINT_PLACEHOLDER = "H";

function StagedResult({staged, onClose}: {staged: {provider: string; fingerprint: string}; onClose: () => void}) {
  const t = useTranslations("admin");
  return (
    <OneTimeResult
      title={t("sms.gateways.staged.title")}
      intro={t("sms.gateways.staged.intro", {provider: providerLabel(staged.provider), placeholder: HINT_PLACEHOLDER, pending: "ctrlz-admin sms pending"})}
      values={[
        {
          id: "sms-confirm",
          label: t("sms.gateways.staged.command"),
          value: `ctrlz-admin sms confirm ${staged.provider} --hint ${HINT_PLACEHOLDER} --fingerprint ${staged.fingerprint}`,
          copyLabel: t("sms.gateways.staged.copy"),
        },
      ]}
      onClose={onClose}
      returnFocus={() => document.querySelector<HTMLElement>(`[data-testid="gateway-${CSS.escape(staged.provider)}"] button`)}
    />
  );
}

// What `ctrlz-admin sms confirm` takes, and what the OpenAPI schema says (the first 8 bytes of a SHA-256 in hex). The answer comes from another
// process, and the value ends in a line that the owner copies into a shell at the server, so a string of any other shape is not used (merge-r3-14).
const FINGERPRINT = /^[0-9a-f]{16}$/;

function EditForm({
  gateway,
  onClose,
  onBusy,
  onStaged,
}: {
  gateway: SmsGatewayRow;
  onClose: () => void;
  onBusy: (busy: boolean) => void;
  onStaged: (fingerprint: string) => void;
}) {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  // The read of the price, the fresh-code dialog and the PUT are one pending state (wp10-r7-2, wp10-r8-1, wp10-r8-3).
  const {write, pending} = useCheckedWrite();
  const save = useSaveGateway();
  const fields = CREDENTIAL_FIELDS[gateway.provider];
  // The DOM names are not `username` and `password`: a manager reads the name too (noAutofill.ts). The form keys the values and
  // the messages by the provider's own field name.
  const domName = (field: string) => `gw_${gateway.provider}_${field}`;
  const form = useAdminForm({focus: fields[0] ? domName(fields[0].name) : "cost_per_message"});
  const [values, setValues] = useState<Record<string, string>>({});
  // The price is a draft of a value the server holds, and the daily money cap (the defence against SMS pumping) is counted from it,
  // so another admin's price must reach this form: the draft follows the server, and a price typed here that the server moved
  // under is a conflict that Save waits for (wp10-r8-3). The row is the list's live one, not a copy taken when the dialog opened.
  const {draft: cost, setDraft: setCost, conflict, serverValue, reset, keepMine} = useServerDraft(gateway.cost_per_message ?? "", sameMoney);
  const busy = useRef(false);
  const queryClient = useQueryClient();
  // No answer came after the server may have staged the pair: it waits at the console and the one value that confirms it is gone (merge-r3-13, gate-r32-7).
  const [lost, setLost] = useState(false);
  // Back, a reload and a closed tab ask first while a save of credentials runs: leaving would drop the fingerprint that the answer carries (gate-r32-6).
  const typedCredentials = fields.some((f) => (values[f.name] ?? "").trim() !== "");
  useLeaveGuard(pending && typedCredentials);

  async function submit() {
    if (busy.current || form.blocked || conflict) return;
    // A credential is never changed on the admin's behalf: what was pasted must be what is sealed, so a hidden character (a
    // key copied from a web page can carry one) is refused with a message and the key is pasted again.
    const hidden = fields.find((f) => hasInvisible(values[f.name] ?? ""));
    if (hidden) return form.setFieldError(hidden.name, a("fields.password.invisible"));
    const typed = fields.flatMap((f) => {
      const value = (values[f.name] ?? "").trim();
      return value === "" ? [] : [[f.name, value] as const];
    });
    // The shape is all the API checks: every field of the provider, or none of them.
    if (typed.length > 0 && typed.length < fields.length) {
      const missing = fields.find((f) => !typed.some(([name]) => name === f.name));
      return form.setFieldError(missing?.name ?? fields[0]!.name, a("fields.password.required"));
    }
    const price = normalizeMoney(cost);
    // The price is compared as an amount: the server writes it back with four decimals ("0.5000" for 0.5).
    const costChanged = !sameMoney(price, gateway.cost_per_message ?? "");
    if (costChanged && !isMoney(price)) return form.setFieldError("cost_per_message", t("sms.edit.costInvalid"));
    if (typed.length === 0 && !costChanged) return form.setFieldError(fields[0]?.name ?? "cost_per_message", t("sms.edit.nothing"));

    const body: SmsGatewayRequest = {
      ...(typed.length > 0 ? {credentials: Object.fromEntries(typed)} : {}),
      ...(costChanged ? {cost_per_message: price} : {}),
    };
    busy.current = true;
    onBusy(true);
    setLost(false);
    form.clear();
    let done = false;
    try {
      // Only a changed price is read first: a credential is write-only and cannot conflict. The read is made again after the
      // fresh-code dialog, and a price that moved meanwhile stops the write (the draft then shows the conflict).
      const guard = costChanged
        ? {options: gatewaysQueryOptions(), pick: (rows: SmsGatewayRow[]) => rows.find((row) => row.provider === gateway.provider)?.cost_per_message ?? "", seen: gateway.cost_per_message ?? "", same: sameMoney}
        : null;
      // The response of the PUT that staged a pair is the only place its fingerprint is ever sent (admin-r21-5): take it before the
      // mutation is reset, and let the parent show it.
      let fingerprint: string | undefined;
      const written = await write(guard, async () => {
        const row = await save.mutateAsync({provider: gateway.provider, body});
        fingerprint = row.pending_fingerprint;
        return row;
      });
      if (!written) return;
      done = true;
      // The typed secrets leave memory with the dialog; the mutation keeps no variables (gcTime 0) and is reset anyway.
      setValues({});
      save.reset();
      // New credentials are sealed but inactive until the owner confirms them at the console (D64): say so, a bare "saved" would hide it.
      toast.success(typed.length > 0 ? t("sms.edit.savedPending") : t("sms.edit.saved"));
      onClose();
      if (typed.length > 0) {
        if (fingerprint !== undefined && FINGERPRINT.test(fingerprint)) onStaged(fingerprint);
        // A pair is waiting and nothing here can confirm it: the owner must know before the dialog is gone.
        else toast.warning(t("sms.edit.noFingerprint"));
      }
    } catch (error) {
      if (typed.length > 0 && answerMayBeLost(error)) {
        // Said, not offered as a plain Retry: a second PUT would meet pending_exists with no way to confirm what it found.
        void queryClient.invalidateQueries({queryKey: smsKeys.gateways});
        setLost(true);
        return;
      }
      // The API names the pair `credentials`; the page has one field per member, so the line goes under the first (an unplaced name
      // would be shown as the bare "validation failed" of the whole form, which hides that a pair already waits for the console).
      if (!isHandledError(error)) form.fail(error, {rename: {credentials: fields[0] ? fields[0].name : "cost_per_message"}});
    } finally {
      if (!done) busy.current = false;
      // The lock is for the call only: the parent outlives this form, and a lock left on would hold every later open of a dialog shut (gate-r33-12).
      onBusy(false);
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("sms.edit.text")}</p>
      {fields.map((f) => {
        const hint = gateway.provider === "melipayamak" && f.name === "password" ? t("sms.edit.melipayamakPasswordHint") : undefined;
        const set = (value: string) => setValues((prev) => ({...prev, [f.name]: value}));
        const label = t(`sms.edit.fields.${f.name}` as never);
        return f.secret ? (
          <PasswordField
            key={f.name}
            name={domName(f.name)}
            label={label}
            autoComplete="off"
            value={values[f.name] ?? ""}
            {...form.bind(f.name, set)}
            isDisabled={pending}
            description={hint}
          />
        ) : (
          <TextField
            key={f.name}
            name={domName(f.name)}
            variant="secondary"
            fullWidth
            autoComplete="off"
            isDisabled={pending}
            isInvalid={form.fieldMessage(f.name) !== undefined}
            value={values[f.name] ?? ""}
            onChange={form.bind(f.name, set).onChange}
          >
            <Label>{label}</Label>
            <Input dir="ltr" className="text-start" spellCheck={false} autoCapitalize="none" autoCorrect="off" {...NO_MANAGER} />
            <FieldError>{form.fieldMessage(f.name)}</FieldError>
          </TextField>
        );
      })}
      {fields.length > 0 ? <p className="text-muted text-xs">{t("sms.edit.ipNote")}</p> : null}
      <TextField
        name="cost_per_message"
        variant="secondary"
        fullWidth
        autoComplete="off"
        inputMode="decimal"
        isDisabled={pending}
        isInvalid={form.fieldMessage("cost_per_message") !== undefined}
        value={cost}
        onChange={form.bind("cost_per_message", setCost).onChange}
      >
        <Label>{t("sms.edit.cost")}</Label>
        <Input dir="ltr" className="text-start" />
        <FieldError>{form.fieldMessage("cost_per_message")}</FieldError>
      </TextField>
      {conflict ? (
        <ConflictNote
          name="cost_per_message"
          value={<Tech>{serverValue}</Tech>}
          onKeep={keepMine}
          onUseServer={() => (reset(), form.clearField("cost_per_message"))}
        />
      ) : null}
      {lost ? (
        <Alert status="warning" data-testid="gateway-save-lost">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("sms.edit.lost", {pending: "ctrlz-admin sms pending", discard: "ctrlz-admin sms discard"})}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={t("sms.edit.submit")} isPending={pending} isDisabled={conflict} retryIn={form.retryIn} onCancel={onClose} />
    </AuthForm>
  );
}

function TestForm({gateway, onClose}: {gateway: SmsGatewayRow; onClose: () => void}) {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  const pageLocale = useLocale();
  const {write, pending} = useCheckedWrite();
  const test = useTestGateway();
  const templates = useTemplates();
  const form = useAdminForm({focus: "phone"});
  const [phone, setPhone] = useState("");
  const [template, setTemplate] = useState<string | null>(null);
  const [locale, setLocale] = useState<LocaleCode>(isLocale(pageLocale) ? pageLocale : "fa");
  const [outboxId, setOutboxId] = useState<string | undefined>(undefined);
  const busy = useRef(false);
  const outbox = useOutbox(outboxId);

  const keys = useMemo(() => [...new Set((templates.data ?? []).map((row) => row.key))], [templates.data]);
  const chosen = template ?? keys[0] ?? null;

  async function submit() {
    if (busy.current || form.blocked) return;
    const number = phone.trim();
    if (!number) return form.setFieldError("phone", a("fields.phone.required"));
    if (!chosen) return form.setFieldError("template", t("sms.test.noTemplate"));
    busy.current = true;
    form.clear();
    setOutboxId(undefined);
    try {
      // Nothing another admin edits is replaced, so there is no read; the write still goes through the one path (fresh-code dialog, pending, focus).
      let id: string | undefined;
      await write(null, async () => {
        id = await test.mutateAsync({provider: gateway.provider, body: {phone: number, template: chosen, locale}});
      });
      setOutboxId(id);
    } catch (error) {
      if (hasCode(error, "invalid_phone")) form.fail(error, {field: "phone"});
      else if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  const state = outbox.data?.state;

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("sms.test.text")}</p>
      <PhoneField name="phone" autoComplete="off" value={phone} {...form.bind("phone", setPhone)} isDisabled={pending} />
      <FieldSelect
        name="template"
        label={t("sms.test.template")}
        placeholder={t("sms.test.templatePlaceholder")}
        options={keys.map((k) => ({id: k, label: <Tech>{k}</Tech>, textValue: k}))}
        value={chosen}
        onChange={(value) => {
          setTemplate(value);
          form.clearField("template");
        }}
        error={form.fieldMessage("template")}
        isDisabled={pending || keys.length === 0}
      />
      <LocaleSegment label={t("sms.test.locale")} value={locale} onChange={setLocale} isDisabled={pending} />
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      {outboxId ? (
        <div role="status" aria-live="polite" data-testid="test-state">
          {state === "sent" ? (
            <Alert status="success">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Description>{t("sms.test.sent", {provider: providerLabel(gateway.provider)})}</Alert.Description>
              </Alert.Content>
            </Alert>
          ) : state === "failed" ? (
            <Alert status="danger">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Description>
                  {t("sms.test.failed")} {outbox.data?.last_error ? <Tech className="text-xs">{outbox.data.last_error}</Tech> : null}
                </Alert.Description>
              </Alert.Content>
            </Alert>
          ) : outbox.error ? (
            <FormError error={outbox.error} onRetry={keepRetry(() => outbox.refetch())} />
          ) : (
            <p className="text-muted flex items-center gap-2 text-sm">
              <Spinner size="sm" />
              {t("sms.test.waiting")}
            </p>
          )}
        </div>
      ) : null}
      <EditorActions submitLabel={t("sms.test.submit")} isPending={pending} retryIn={form.retryIn} onCancel={onClose} cancelLabel={outboxId ? t("sms.test.close") : undefined} />
    </AuthForm>
  );
}
