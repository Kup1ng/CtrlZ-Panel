"use client";

// /status (spec p3 10, Plan T-125): a page of the panel itself, reached from the logo menu. P3 renders what it can truthfully measure, which is whether
// this panel answers (api-client hooks/status.ts: a public probe every 30 seconds while a person is there, and a button that asks now). The health
// of the DNS pair and the analytics ingest belong to P4 and P5, which add their rows here; until then those rows say "not reported" in words and
// show no colour and no number, so the page never claims a health it has not measured. Status is always an icon and a word, never colour alone.

import {usePanelProbe} from "@ctrlz/api-client/hooks/status.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {Button, Card, Chip, Skeleton} from "@heroui/react";
import {useTranslations} from "next-intl";

import {PageHeader} from "../shell/PageHeader.tsx";

type Level = "ok" | "degraded" | "down" | "unknown";

const LEVEL: Record<Level, {color: "success" | "warning" | "danger" | "default"; icon: GeneralIconName}> = {
  ok: {color: "success", icon: "check"},
  degraded: {color: "warning", icon: "warning"},
  down: {color: "danger", icon: "error"},
  unknown: {color: "default", icon: "info"},
};

export function StatusScreen() {
  const t = useTranslations("api");
  const f = useAppFormat();
  const probe = usePanelProbe();
  const data = probe.data;
  const level: Level = !data ? "unknown" : !data.reachable ? "down" : data.degraded ? "degraded" : "ok";

  return (
    <div data-screen="status">
      <PageHeader icon="statistics" title={t("statusPage.title")} subtitle={t("statusPage.subtitle")} helpKey="status" />
      <div className="flex w-full max-w-3xl flex-col gap-4 pb-8">
        <Card className="gap-4 p-4" data-testid="status-summary">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-3">
              <span aria-hidden="true" className="tile-11 bg-default text-foreground grid size-11 shrink-0 place-items-center text-xl">
                <Icon name={LEVEL[level].icon} className="size-5" />
              </span>
              <div className="flex min-w-0 flex-col gap-0.5">
                {/* Only the level is announced, and only when it changes: the time below changes on every probe (every 30 s), and a reader would speak it over whatever the person is reading (S8-r2-3). */}
                <div role="status" aria-live="polite">
                  <h2 className="text-base font-semibold">{t(`statusPage.summary.${level}`)}</h2>
                </div>
                <p className="text-muted text-xs">
                  {data ? t("statusPage.checked", {when: f.dateTime(data.at)}) : t("statusPage.checking")}
                </p>
              </div>
            </div>
            <Button variant="secondary" isPending={probe.isFetching} onPress={() => void probe.refetch()}>
              {t("statusPage.checkNow")}
            </Button>
          </div>
        </Card>

        <ul aria-label={t("statusPage.list")} className="flex flex-col gap-2">
          <Row
            id="panel"
            name={t("statusPage.rows.panel.name")}
            text={t("statusPage.rows.panel.text")}
            level={level}
            detail={data?.reachable ? t("statusPage.rows.panel.ms", {ms: f.number(data.ms)}) : undefined}
            loading={probe.isPending}
          />
          <Row id="dns" name={t("statusPage.rows.dns.name")} text={t("statusPage.rows.dns.text")} level="unknown" />
          <Row id="analytics" name={t("statusPage.rows.analytics.name")} text={t("statusPage.rows.analytics.text")} level="unknown" />
        </ul>
        <p className="text-muted text-xs">{t("statusPage.note")}</p>
      </div>
    </div>
  );
}

function Row({id, name, text, level, detail, loading = false}: {id: string; name: string; text: string; level: Level; detail?: string; loading?: boolean}) {
  const t = useTranslations("api");
  const chip = LEVEL[level];
  return (
    <li data-status-row={id} data-level={level} className="bg-surface flex flex-wrap items-center gap-x-4 gap-y-2 rounded-(--radius-box) px-4 py-3">
      <div className="flex min-w-0 flex-1 basis-56 flex-col gap-0.5">
        <span className="text-sm font-medium">{name}</span>
        <span className="text-muted text-xs">{text}</span>
      </div>
      {detail ? <span className="text-muted text-xs tabular-nums">{detail}</span> : null}
      {loading ? (
        <Skeleton aria-hidden className="h-6 w-20 rounded-full" />
      ) : (
        <Chip size="sm" color={chip.color} variant="soft" data-testid="status-chip">
          <Icon name={chip.icon} className="size-3.5" />
          {t(`statusPage.level.${level}`)}
        </Chip>
      )}
    </li>
  );
}
