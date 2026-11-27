"use client";

import {useIpClaims, useReleaseIpClaim, type IPClaim} from "@ctrlz/api-client/hooks/clients.ts";
import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, Button, Chip, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {ListRow, ListRowSkeleton, RowList} from "../../data/ListRow.tsx";
import {Tech} from "../../data/Tech.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {useDeviceDialog} from "../../dialog/useDeviceDialog.ts";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {useApiForm} from "../../forms/useApiForm.ts";
import {Cancelled, useGuardedWrite} from "../useGuardedWrite.tsx";
import {canProve, releaseEmptiesStack} from "./ipModel.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// The Plain DNS addresses of an Endpoint (spec p3 4, 10; T-262, T-267, T-268): the claims, each with its state in words, whether it is proven,
// the date its grace ends, a Prove button where proof can change something, and Release. Plain DNS has to be on for a claim to be served,
// and the section says so when it is off.

const STATE_COLOR = {active: "success", pending_proof: "warning", grace: "warning", suspended: "danger"} as const;

export function ClaimsSection({endpoint, onClaim, onProve}: {endpoint: Endpoint; onClaim: () => void; onProve: (id: string) => void}) {
  const t = useTranslations("endpoints");
  const format = useAppFormat();
  const claims = useIpClaims(endpoint.id);
  const devices = useDeviceDialog();
  const [releasing, setReleasing] = useState<IPClaim | null>(null);
  const rows = claims.data ?? [];

  let body;
  if (claims.isError && !claims.data) body = <SectionError error={claims.error} onRetry={() => void claims.refetch()} />;
  else if (!claims.data)
    body = (
      <div role="status" aria-label={t("ips.claims.loading")}>
        <ListRowSkeleton />
      </div>
    );
  else if (rows.length === 0)
    body = (
      <SectionEmpty
        icon="globe"
        title={t("ips.claims.empty")}
        description={t("ips.claims.emptyText")}
        action={
          <PrimaryButton onPress={onClaim}>
            <Icon name="plus" className="size-4" />
            {t("ips.claims.add")}
          </PrimaryButton>
        }
      />
    );
  else
    body = (
      <RowList aria-label={t("ips.claims.listLabel")}>
        {rows.map((claim) => (
          <ListRow
            key={claim.id}
            roomy
            icon={<Icon name="globe" className="size-5" />}
            title={<Tech className="truncate text-sm">{claim.cidr}</Tech>}
            subtitle={
              <>
                <span>{t(`ips.claims.source.${claim.source}`)}</span>
                {claim.last_seen_at ? <span> · {t("ips.claims.lastSeen", {when: format.relative(claim.last_seen_at)})}</span> : null}
              </>
            }
            counters={
              <div className="flex flex-wrap items-center gap-2">
                <Chip size="sm" variant="soft" color={STATE_COLOR[claim.state]}>
                  <Chip.Label>{t(`ips.claims.state.${claim.state}`)}</Chip.Label>
                </Chip>
                <Chip size="sm" variant="soft">
                  <Chip.Label>{claim.proven ? t("ips.claims.proven") : t("ips.claims.unproven")}</Chip.Label>
                </Chip>
                {claim.state === "grace" && claim.grace_until ? (
                  <span className="text-warning-soft-foreground text-xs">{t("ips.claims.graceUntil", {date: format.date(claim.grace_until)})}</span>
                ) : null}
                {claim.needs_admin ? <span className="text-muted text-xs">{t("ips.claims.needsAdmin")}</span> : null}
              </div>
            }
            trailing={
              <div className="flex items-center gap-1">
                {canProve(claim) ? (
                  <Button size="sm" variant="outline" aria-label={t("ips.claims.proveAria", {cidr: claim.cidr})} onPress={() => onProve(claim.id)}>
                    {t("ips.claims.prove")}
                  </Button>
                ) : null}
                <Button isIconOnly size="sm" variant="ghost" isDisabled={claim.state === "suspended"} aria-label={t("ips.claims.releaseAria", {cidr: claim.cidr})} onPress={() => setReleasing(claim)}>
                  <Icon name="trash" className="size-4" />
                </Button>
              </div>
            }
          />
        ))}
      </RowList>
    );

  return (
    <section aria-labelledby="claims-title" className="flex flex-col gap-3" data-testid="claims-section">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1">
          <h2 id="claims-title" className="text-base font-medium">
            {t("ips.claims.title")}
          </h2>
          <p className="text-muted text-sm">{t("ips.claims.text")}</p>
        </div>
        {rows.length > 0 ? (
          <PrimaryButton size="sm" onPress={onClaim}>
            <Icon name="plus" className="size-4" />
            {t("ips.claims.add")}
          </PrimaryButton>
        ) : null}
      </div>
      {!endpoint.legacy_dns ? (
        <Alert status="warning" role="status">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t("ips.claims.legacyOffTitle")}</Alert.Title>
            <Alert.Description>
              {t("ips.claims.legacyOff")}
            </Alert.Description>
            <Button size="sm" variant="outline" className="mt-2" onPress={() => devices.open("edit", endpoint.id)}>
              {t("ips.claims.legacyOffLink")}
            </Button>
          </Alert.Content>
        </Alert>
      ) : null}
      {rows.some((c) => c.state === "grace") ? (
        <Alert status="warning" role="status">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("ips.claims.graceNote")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      {body}
      {releasing ? <ReleaseDialog endpoint={endpoint} claim={releasing} onClose={() => setReleasing(null)} /> : null}
    </section>
  );
}

function ReleaseDialog({endpoint, claim, onClose}: {endpoint: Endpoint; claim: IPClaim; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const release = useReleaseIpClaim();
  const guarded = useGuardedWrite();
  const form = useApiForm({fieldNamespace: "profiles"});
  const busy = useRef(false);
  const [pending, setPending] = useState(false);

  async function submit() {
    if (busy.current || form.blocked) return;
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      await guarded.run((extra) => release.mutateAsync({endpointId: endpoint.id, claimId: claim.id, ...(extra.lock_passwords ? {lockPasswords: extra.lock_passwords} : {})}), [endpoint], {takesAll: releaseEmptiesStack(endpoint.legacy_dns, claim), reset: release.reset});
      toast.success(t("ips.claims.released"));
      onClose();
    } catch (error) {
      if (!(error instanceof Cancelled)) form.fail(error);
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
        title={t("ips.claims.releaseTitle", {cidr: claim.cidr})}
        footer={
          <>
            <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={pending} isDisabled={form.retryIn > 0} onPress={() => void submit()}>
              {t("ips.claims.releaseSubmit")}
            </Button>
          </>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          <p className="text-sm">{t("ips.claims.releaseText")}</p>
          <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        </AuthForm>
      </DialogFrame>
      {guarded.dialogs}
    </>
  );
}
