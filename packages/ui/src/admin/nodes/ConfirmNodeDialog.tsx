"use client";

import {useConfirmEnrollment, useEnrollments, type NodeEnrollmentRow} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Checkbox, Description, FieldError, Input, Label, Skeleton, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {UrlModal} from "../../dialog/UrlModal.tsx";
import type {UrlDialog} from "../../dialog/useUrlDialog.ts";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {cleanName, nameLength} from "../../forms/invisible.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {keepFocus} from "../shared/restoreFocus.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {Facts} from "./NodeCard.tsx";
import {checkFingerprint, groupFingerprint, normaliseFingerprint, type FingerprintCheck} from "./nodeParts.ts";

// p4-nodes 4.2 step 4, T-340 (R19): the confirmation of a host's fingerprint, bound to `?dialog=confirmNode&enrollmentId=<id>`. A link opens
// it, Back closes it, a reload keeps it. The admin types the fingerprint the host's own console shows and the page compares it with the
// record as they type; Confirm stays off until the two are equal, the four addresses are ticked as compared, and the node has a name.
// The route compares again (`fingerprint_mismatch`), so a page that was altered still cannot confirm another host. Nothing here is secret:
// the id is a record id, and the fingerprint is the public hash of a key.

const NAME_MAX = 64;
const CHECK_ICON = {empty: "info", partial: "info", mismatch: "warning", match: "check"} as const;

export function ConfirmNodeDialog({dialog, enrollmentId, onClose}: {dialog: UrlDialog; enrollmentId: string | null; onClose: () => void}) {
  const t = useTranslations("nodes");
  const open = dialog.value === "confirmNode" && enrollmentId !== null;
  const [busy, setBusy] = useState(false);
  return (
    <UrlModal dialog={{isOpen: open, close: onClose}} isOpen={open} isLocked={busy} title={t("enrol.confirm.title")}>
      {open ? <Body id={enrollmentId} onClose={onClose} onBusy={setBusy} /> : null}
    </UrlModal>
  );
}

function Body({id, onClose, onBusy}: {id: string; onClose: () => void; onBusy: (busy: boolean) => void}) {
  const t = useTranslations("nodes");
  const c = useTranslations("common");
  const list = useEnrollments();
  if (list.isPending) return <Skeleton className="h-64 w-full rounded-(--radius-box)" />;
  const row = list.data?.pages.flatMap((p) => p.items).find((e) => e.id === id);
  if (!row) {
    return (
      <div className="flex flex-col gap-3" data-testid="confirm-missing">
        <p className="font-medium">{t("enrol.confirm.missingTitle")}</p>
        <p className="text-muted text-sm">{t("enrol.confirm.missing")}</p>
        <Button variant="tertiary" className="self-end" onPress={onClose}>
          {c("back")}
        </Button>
      </div>
    );
  }
  if (row.state !== "pending_approval") {
    return (
      <div className="flex flex-col gap-3" data-testid="confirm-closed">
        <p>{t("enrol.confirm.closed", {state: t(`enrol.list.state.${row.state}`)})}</p>
        <Button variant="tertiary" className="self-end" onPress={onClose}>
          {c("back")}
        </Button>
      </div>
    );
  }
  return <ConfirmForm row={row} onClose={onClose} onBusy={onBusy} />;
}

function ConfirmForm({row, onClose, onBusy}: {row: NodeEnrollmentRow; onClose: () => void; onBusy: (busy: boolean) => void}) {
  const t = useTranslations("nodes");
  const c = useTranslations("common");
  const a = useTranslations("admin");
  const format = useAppFormat();
  const confirm = useConfirmEnrollment();
  const {send, pending} = useCheckedWrite();
  const form = useAdminForm({focus: "typed_fingerprint"});
  const [typed, setTyped] = useState("");
  const [compared, setCompared] = useState(false);
  // The host's own name until the admin types another: derived from the record, never copied into state.
  const [typedName, setTypedName] = useState<string | null>(null);
  const name = typedName ?? (row.hostname ?? "").slice(0, NAME_MAX);
  const busy = useRef(false);

  const check = checkFingerprint(typed, row.key_fingerprint);
  const trimmed = cleanName(name);
  const ready = check === "match" && compared && trimmed !== "" && nameLength(trimmed) <= NAME_MAX;

  async function submit() {
    if (busy.current || form.blocked || !ready) return;
    busy.current = true;
    onBusy(true);
    form.clear();
    try {
      await send(() => confirm.mutateAsync({id: row.id, fingerprint: normaliseFingerprint(typed), name: trimmed}));
      toast.success(t("enrol.confirm.done"));
      // No leave guard is on this form (its answer holds nothing that cannot be read again), so closing by Back does not meet the guard's own history entry.
      onClose();
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
      onBusy(false);
    }
  }

  const addresses: {id: string; label: string; ip: string | undefined}[] = [
    {id: "dns-bind", label: t("enrol.form.dnsBind"), ip: row.dns_bind_ip},
    {id: "dns-advertised", label: t("enrol.form.dnsAdvertised"), ip: row.dns_advertised_ip},
    {id: "proxy-bind", label: t("enrol.form.proxyBind"), ip: row.proxy_bind_ip},
    {id: "proxy-advertised", label: t("enrol.form.proxyAdvertised"), ip: row.proxy_advertised_ip},
  ];

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("enrol.confirm.text")}</p>
      <section aria-label={t("enrol.confirm.record")} className="bg-surface-secondary flex flex-col gap-3 rounded-(--radius-box) p-4" data-testid="confirm-record">
        <div className="flex flex-col gap-1">
          <span className="text-muted text-xs">{t("enrol.confirm.fingerprint")}</span>
          <div dir="ltr" translate="no" className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-sm" data-testid="record-fingerprint">
            {groupFingerprint(row.key_fingerprint ?? "").map((g, i) => (
              <span key={i}>{g}</span>
            ))}
          </div>
        </div>
        <Facts
          rows={[
            ...addresses.map((x) => ({id: x.id, label: x.label, value: x.ip ? <Tech>{x.ip}</Tech> : t("nodes.noAddress")})),
            {id: "host", label: t("enrol.confirm.host"), value: row.hostname ? <Tech mono={false}>{row.hostname}</Tech> : t("enrol.list.unnamed")},
            {id: "os", label: t("enrol.confirm.os"), value: row.os_release ? <Tech mono={false}>{row.os_release}</Tech> : "-"},
            {id: "version", label: t("enrol.confirm.version"), value: row.node_version ? <Tech>{row.node_version}</Tech> : "-"},
            {id: "source", label: t("enrol.confirm.source"), value: row.enrolled_from ? <Tech>{row.enrolled_from}</Tech> : "-"},
            {id: "when", label: t("enrol.confirm.when"), value: row.enrolled_at ? format.dateTime(row.enrolled_at) : "-"},
          ]}
        />
      </section>

      <TextField
        name="typed_fingerprint"
        variant="secondary"
        fullWidth
        autoComplete="off"
        isDisabled={pending}
        isInvalid={check === "mismatch"}
        value={typed}
        onChange={(value) => {
          setTyped(value);
          form.clear();
        }}
      >
        <Label>{t("enrol.confirm.typed")}</Label>
        <Input dir="ltr" spellCheck={false} autoCapitalize="none" className="text-start font-mono" />
        <Description>{t("enrol.confirm.typedHint")}</Description>
        <FieldError />
      </TextField>
      <Comparison check={check} />

      <Checkbox name="compared" isSelected={compared} isDisabled={pending} onChange={setCompared}>
        <Checkbox.Content>
          <Checkbox.Control>
            <Checkbox.Indicator />
          </Checkbox.Control>
          {t("enrol.confirm.addresses")}
        </Checkbox.Content>
      </Checkbox>

      <TextField name="node_name" variant="secondary" fullWidth autoComplete="off" isDisabled={pending} isInvalid={name !== "" && trimmed === ""} value={name} onChange={setTypedName}>
        <Label>{t("enrol.confirm.name")}</Label>
        <Input maxLength={NAME_MAX} />
        <Description>{t("enrol.confirm.nameHint")}</Description>
        <FieldError>{t("enrol.confirm.nameRequired")}</FieldError>
      </TextField>

      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
          {c("cancel")}
        </Button>
        <PrimaryButton type="submit" isPending={pending} isDisabled={!ready || form.retryIn > 0} data-testid="confirm-node-submit">
          {form.retryIn > 0 ? a("settings.retryIn", {seconds: form.retryIn}) : t("enrol.confirm.submit")}
        </PrimaryButton>
      </div>
    </AuthForm>
  );
}

/** What the typed fingerprint is so far, in words and an icon, so the colour is never the only thing that says it. A live region: a typist hears the change. */
function Comparison({check}: {check: FingerprintCheck}) {
  const t = useTranslations("nodes");
  return (
    <p role="status" aria-live="polite" className="flex items-start gap-2 text-sm" data-testid="fingerprint-check" data-check={check}>
      <Icon name={CHECK_ICON[check]} className="mt-0.5 size-4 shrink-0" />
      <span className={check === "mismatch" ? "text-(--danger-text)" : undefined}>{t(`enrol.confirm.check.${check}`)}</span>
    </p>
  );
}
