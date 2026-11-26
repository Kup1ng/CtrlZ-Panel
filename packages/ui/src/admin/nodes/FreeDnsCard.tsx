"use client";

import {FREE_QPS_MIN, FREE_QPS_SCHEMA_MAX, freeDnsQueryOptions, useFreeDns, useSaveFreeDns, type FreeDnsSettings} from "@ctrlz/api-client/admin/hooks/freeDns.ts";
import {useNodes} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {globalPairAddresses, usePairs} from "@ctrlz/api-client/admin/hooks/pairs.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Card, Skeleton, Switch, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef} from "react";

import {Tech} from "../../data/Tech.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {ConflictNote} from "../shared/ConflictNote.tsx";
import {IntegerField} from "../shared/IntegerField.tsx";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {keepFocus, keepRetry} from "../shared/restoreFocus.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerForm} from "../shared/useServerDraft.ts";
import {PlainCopyButton} from "./PlainCopyButton.tsx";

// T-556. What free DNS gives out and the switch that stops it. The addresses are the advertised DNS addresses of the global pair, the
// primary first, each with a copy button. The switch and `qps` are one form: the write needs the fresh TOTP window (the dialog opens
// and the call is repeated once, `useCheckedWrite`), and a value that another admin changed while this one was editing stops the
// write and is said (for `qps`; a switch that both admins moved is the same value, so it has no conflict of its own). The warning that free DNS users get no notice stays on the card, because the admin reads it before every save.

type Draft = {enabled: boolean; qps: number | undefined};
const draftOf = (s: FreeDnsSettings): Draft => ({enabled: s.enabled, qps: s.qps});
const sameDraft = (a: Draft, b: Draft) => a.enabled === b.enabled && a.qps === b.qps;

export function FreeDnsCard() {
  const t = useTranslations("nodes");
  const settings = useFreeDns();
  return (
    <Card className="max-w-3xl gap-4 p-6" data-testid="free-dns">
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("freeDns.title")}</Card.Title>
        <Card.Description>{t("freeDns.text")}</Card.Description>
      </Card.Header>
      <Card.Content className="flex flex-col gap-5">
        <Addresses />
        {settings.isPending ? (
          <div role="status" aria-busy="true" aria-label={t("freeDns.loadingLabel")}>
            <Skeleton className="h-28 w-full rounded-(--radius-box)" />
          </div>
        ) : !settings.data ? (
          <SectionError error={settings.error} onRetry={keepRetry(() => settings.refetch())} />
        ) : (
          <>
            <RefreshFailed error={settings.error} onRetry={() => settings.refetch()} />
            <Editor current={settings.data} />
          </>
        )}
        <div role="note" className="bg-surface-secondary flex items-start gap-3 rounded-(--radius-box) p-4 text-sm" data-testid="free-dns-warning">
          <Icon name="warning" className="mt-0.5 size-4 shrink-0" />
          <div className="flex flex-col gap-0.5">
            <span className="font-medium">{t("freeDns.warning.title")}</span>
            <span className="text-muted">{t("freeDns.warning.text")}</span>
          </div>
        </div>
      </Card.Content>
    </Card>
  );
}

function Addresses() {
  const t = useTranslations("nodes");
  const pairs = usePairs();
  const nodes = useNodes();
  const failed = pairs.error ?? nodes.error;
  const loading = pairs.isPending || nodes.isPending;
  const pairList = pairs.data?.pages.flatMap((p) => p.items) ?? [];
  const all = globalPairAddresses(pairList, nodes.data?.pages.flatMap((p) => p.items) ?? []);
  // A revoked member is still advertised, so it is shown as a warning and never as an address to hand out (PG-r3-3).
  const addresses = all.filter((a) => !a.revoked);
  const revoked = all.filter((a) => a.revoked);
  const ready = !loading && !(failed && (!pairs.data || !nodes.data));
  const hasGlobal = pairList.some((p) => p.is_global);

  return (
    <section aria-labelledby="free-dns-addresses" className="flex flex-col gap-2" data-testid="free-dns-addresses">
      <h3 id="free-dns-addresses" className="text-sm font-medium">
        {t("freeDns.addresses.title")}
      </h3>
      {loading ? (
        <Skeleton className="h-16 w-full rounded-(--radius-box)" />
      ) : failed && (!pairs.data || !nodes.data) ? (
        <SectionError error={failed} onRetry={keepRetry(() => Promise.all([pairs.refetch(), nodes.refetch()]))} />
      ) : addresses.length === 0 ? (
        <p className="text-muted text-sm" data-testid="free-dns-no-address">
          {t(hasGlobal && revoked.length > 0 ? "freeDns.addresses.noneActive" : "freeDns.addresses.none")}
        </p>
      ) : null}
      {ready && revoked.length > 0 ? (
        <ul className="flex flex-col gap-2" data-testid="free-dns-revoked">
          {revoked.map((a) => (
            <li key={a.role} className="bg-surface-secondary flex flex-wrap items-start gap-2 rounded-(--radius-box) px-4 py-3" data-testid={`free-address-revoked-${a.role}`}>
              <Icon name="error" className="mt-0.5 size-4 shrink-0" />
              <div className="flex min-w-0 flex-col gap-0.5 text-sm">
                <span className="text-muted text-xs">
                  {t(`freeDns.addresses.${a.role}`)}, {t("health.revoked")}
                </span>
                <span>
                  <Tech className="[overflow-wrap:anywhere]">{a.ip}</Tech> ({a.name})
                </span>
                <span role="note">
                  {t("pair.advertised.revokedMember")}{" "}
                  <Link href="/runbook#compromise" className="underline underline-offset-2">
                    {t("givenUp.runbook")}
                  </Link>
                </span>
              </div>
            </li>
          ))}
        </ul>
      ) : null}
      {ready && addresses.length > 0 ? (
        <ul className="flex flex-col gap-2">
          {addresses.map((a) => (
            <li key={a.role} className="bg-surface-secondary flex flex-wrap items-center justify-between gap-2 rounded-(--radius-box) px-4 py-3" data-testid={`free-address-${a.role}`}>
              <div className="flex min-w-0 flex-col">
                <span className="text-muted text-xs">{t(`freeDns.addresses.${a.role}`)}</span>
                <Tech className="text-base [overflow-wrap:anywhere]">{a.ip}</Tech>
              </div>
              <PlainCopyButton text={a.ip} label={t("freeDns.addresses.copy", {role: t(`freeDns.addresses.${a.role}`)})} />
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function Editor({current}: {current: FreeDnsSettings}) {
  const t = useTranslations("nodes");
  const a = useTranslations("admin");
  const format = useAppFormat();
  const save = useSaveFreeDns();
  // The read, the fresh-code dialog and the PUT are one pending state (wp10-r7-2, wp10-r7-5).
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  const {draft, edit, dirty, reset, saved, conflicts, serverValue, keepMine, takeServer} = useServerForm<Draft>(draftOf(current), sameDraft);
  const conflicted = conflicts.length > 0;
  const busy = useRef(false);
  const range = t("freeDns.qps.range", {min: format.number(FREE_QPS_MIN, {useGrouping: false})});

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflicted) return;
    const {enabled, qps} = draft;
    if (qps === undefined || !Number.isInteger(qps) || qps < FREE_QPS_MIN || qps > FREE_QPS_SCHEMA_MAX) return form.setFieldError("qps", range);
    busy.current = true;
    form.clear();
    try {
      // The page does not refetch while it stays open, so the value this write replaces is read before every try of it, the one after
      // the fresh-code dialog included. A route answer of `qps_out_of_range` (the ceiling the server holds is the one that counts) shows
      // as the form's own error, with the text of the code.
      const written = await write({options: freeDnsQueryOptions(), pick: draftOf, seen: draftOf(current), same: sameDraft}, () => save.mutateAsync({enabled, qps}));
      if (!written) return;
      saved({enabled, qps});
      toast.success(t("freeDns.saved"));
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 flex-col">
          <span className="text-sm font-medium">{t("freeDns.enabled")}</span>
          <span className="text-muted text-xs">{t("freeDns.enabledHint")}</span>
        </div>
        <Switch
          name="enabled"
          aria-label={t("freeDns.enabled")}
          isSelected={draft.enabled}
          isDisabled={pending}
          onChange={(value) => {
            edit({enabled: value});
            form.clear();
          }}
        >
          <Switch.Content>
            <Switch.Control>
              <Switch.Thumb />
            </Switch.Control>
          </Switch.Content>
        </Switch>
      </div>
      {/* A boolean cannot be in conflict: when another admin changes it and this one has edited it, the two values are the same one. */}

      <IntegerField
        name="qps"
        label={t("freeDns.qps.label")}
        description={t("freeDns.qps.hint", {min: format.number(FREE_QPS_MIN, {useGrouping: false})})}
        value={draft.qps}
        onChange={(value) => {
          edit({qps: value});
          form.clearField("qps");
        }}
        min={FREE_QPS_MIN}
        max={FREE_QPS_SCHEMA_MAX}
        isDisabled={pending}
        error={form.fieldMessage("qps")}
        invalidMessage={range}
        className="max-w-64"
      />
      {conflicts.includes("qps") ? (
        <ConflictNote
          name="qps"
          value={serverValue.qps === undefined ? "" : format.number(serverValue.qps, {useGrouping: false})}
          onKeep={() => keepMine("qps")}
          onUseServer={() => {
            takeServer("qps");
            form.clearField("qps");
          }}
        />
      ) : null}

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
          {a("settings.cancel")}
        </Button>
        <PrimaryButton type="submit" isPending={pending} isDisabled={!dirty || conflicted || form.retryIn > 0}>
          {form.retryIn > 0 ? a("settings.retryIn", {seconds: form.retryIn}) : t("freeDns.submit")}
        </PrimaryButton>
      </div>
    </AuthForm>
  );
}
