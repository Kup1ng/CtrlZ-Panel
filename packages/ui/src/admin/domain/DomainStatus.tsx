"use client";

import type {DomainSettings} from "@ctrlz/api-client/admin/hooks/domain.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, Card} from "@heroui/react";
import {useTranslations} from "next-intl";

import {Tech} from "../../data/Tech.tsx";
import {Facts, NotReported} from "../nodes/NodeCard.tsx";
import {PlainCopyButton} from "../nodes/PlainCopyButton.tsx";
import {transitionRunning} from "./domainParts.ts";

// T-344, p4-nodes 10.4. What the domain is now and whether it is in force. The zone, the panel host and the admin host are what the panel
// asks for; the web tier and Caddy change only when the apply step is run on the server (`apply_pending` says it has not been, and the old
// hosts serve until then). The step is one command, and it is shown with a copy button: it holds no secret, so the plain copy is the one
// used. While a transition runs, the nodes serve both zones and the page says until when.

/** The one host step of 10.4, run from the deploy folder on the server that runs the compose project. */
export const APPLY_COMMAND = "scripts/domain-apply.sh";

export function DomainStatus({settings}: {settings: DomainSettings}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const running = transitionRunning(settings);
  const hostRow = (requested: string | undefined, applied: string | undefined) => {
    if (!requested && !applied) return <NotReported text={t("domain.status.notSet")} />;
    return (
      <span className="flex flex-col gap-0.5">
        {requested ? <Tech>{requested}</Tech> : <span className="text-muted">{t("domain.status.noRequest")}</span>}
        {applied && applied !== requested ? (
          <span className="text-muted text-xs">
            {t.rich("domain.status.serving", {host: applied, tech: (chunks) => <Tech>{chunks}</Tech>})}
          </span>
        ) : null}
      </span>
    );
  };
  return (
    <Card className="max-w-3xl gap-4 p-6" data-testid="domain-status" data-apply-pending={settings.apply_pending}>
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("domain.status.title")}</Card.Title>
        <Card.Description>{t("domain.status.text")}</Card.Description>
      </Card.Header>
      <Card.Content className="flex flex-col gap-5">
        <Facts
          rows={[
            {id: "zone", label: t("domain.form.dns_zone"), value: settings.dns_zone ? <Tech>{settings.dns_zone}</Tech> : <NotReported text={t("domain.status.notSet")} />},
            {id: "panel", label: t("domain.form.panel_host"), value: hostRow(settings.panel_host, settings.applied_panel_host)},
            {id: "admin", label: t("domain.form.admin_host"), value: hostRow(settings.admin_host, settings.applied_admin_host)},
            ...(running && settings.prev_dns_zone
              ? [
                  {
                    id: "zones",
                    label: t("domain.status.transition"),
                    value: (
                      <span className="flex flex-col gap-0.5" data-testid="domain-transition">
                        <span>{t.rich("domain.status.both", {old: settings.prev_dns_zone, current: settings.dns_zone ?? "", tech: (chunks) => <Tech>{chunks}</Tech>})}</span>
                        {settings.transition_until ? <span className="text-muted text-xs">{t("domain.status.until", {when: format.dateTime(settings.transition_until)})}</span> : null}
                      </span>
                    ),
                  },
                ]
              : []),
          ]}
        />

        {settings.apply_pending ? (
          <Alert status="warning" data-testid="domain-apply-pending">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t("domain.apply.pending.title")}</Alert.Title>
              <Alert.Description>{t("domain.apply.pending.text")}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : (
          <p className="flex items-start gap-2 text-sm" data-testid="domain-apply-done">
            <Icon name="check" className="mt-0.5 size-4 shrink-0" />
            <span>{t("domain.apply.done")}</span>
          </p>
        )}

        <div className="bg-surface-secondary flex flex-col gap-2 rounded-(--radius-box) p-4" data-testid="domain-apply-command">
          <span className="text-sm font-medium">{t("domain.apply.command.title")}</span>
          <span className="text-muted text-xs">{t("domain.apply.command.text")}</span>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Tech className="text-sm [overflow-wrap:anywhere]">{APPLY_COMMAND}</Tech>
            <PlainCopyButton text={APPLY_COMMAND} label={t("domain.apply.command.copy")} />
          </div>
          <span className="text-muted text-xs">{t("domain.apply.command.again")}</span>
        </div>

        <p className="text-muted flex items-start gap-2 text-sm">
          <Icon name="info" className="mt-0.5 size-4 shrink-0" />
          <span>
            {t.rich("domain.status.passkey", {
              link: (chunks) => (
                <Link href="/settings" className="text-foreground underline underline-offset-2" data-testid="domain-passkey-link">
                  {chunks}
                </Link>
              ),
            })}
          </span>
        </p>
      </Card.Content>
    </Card>
  );
}
