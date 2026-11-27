"use client";

import {STATS_DAYS, useStats, type SmsStats} from "@ctrlz/api-client/admin/hooks/sms.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {reactAriaLocale} from "@ctrlz/i18n/locale.ts";
import {Skeleton} from "@heroui/react";
import {DataGrid, NumberValue, type DataGridColumn} from "@heroui-pro/react";
import {KPI} from "@heroui-pro/react/kpi";
import {Tech} from "../../data/Tech.tsx";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {useTranslations} from "next-intl";
import {useMemo} from "react";

import {providerLabel} from "./providers.ts";
import {keepRetry} from "../shared/restoreFocus.ts";

// Spec 13.3, the Stats tab: per-day counts and cost, per-gateway accepted and failed. A KPI row of the totals and two
// small tables, no chart in P1. The figures hold no phone number and no text (the API leaves both out). Money is Rial as a
// decimal string; summing it as a number is safe at these sizes (ten digits, four decimals, 90 days).

type Day = SmsStats["days"][number];
type GatewayStat = SmsStats["gateways"][number];

export function StatsTab() {
  const t = useTranslations("admin");
  const stats = useStats();
  if (stats.isPending) return <Skeleton className="h-48 w-full rounded-(--radius-box)" />;
  if (stats.error || !stats.data) return <SectionError error={stats.error} onRetry={keepRetry(() => stats.refetch())} />;
  if (stats.data.days.length === 0 && stats.data.gateways.length === 0) {
    return <SectionEmpty icon="sms" title={t("sms.stats.empty")} description={t("sms.stats.emptyText", {days: STATS_DAYS})} />;
  }
  return <Stats stats={stats.data} />;
}

function Stats({stats}: {stats: SmsStats}) {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const numberLocale = reactAriaLocale[format.locale];

  const totals = useMemo(
    () => ({
      otp: stats.days.reduce((sum, d) => sum + d.otp_count, 0),
      outbox: stats.days.reduce((sum, d) => sum + d.outbox_count, 0),
      cost: stats.days.reduce((sum, d) => sum + Number(d.cost), 0),
      accepted: stats.gateways.reduce((sum, g) => sum + g.accepted, 0),
      failed: stats.gateways.reduce((sum, g) => sum + g.failed, 0),
    }),
    [stats],
  );

  const dayColumns = useMemo<DataGridColumn<Day>[]>(
    () => [
      {id: "day", isRowHeader: true, header: t("sms.stats.columns.day"), minWidth: 130, cell: (d) => <span className="text-sm">{format.date(`${d.day}T00:00:00Z`)}</span>},
      {id: "otp", header: t("sms.stats.columns.otp"), align: "end", minWidth: 90, cell: (d) => <span className="text-sm tabular-nums">{format.number(d.otp_count)}</span>},
      {id: "outbox", header: t("sms.stats.columns.outbox"), align: "end", minWidth: 90, cell: (d) => <span className="text-sm tabular-nums">{format.number(d.outbox_count)}</span>},
      {id: "cost", header: t("sms.stats.columns.cost"), align: "end", minWidth: 120, cell: (d) => <span className="text-sm tabular-nums">{format.number(Number(d.cost), {maximumFractionDigits: 4})}</span>},
    ],
    [t, format],
  );

  const gatewayColumns = useMemo<DataGridColumn<GatewayStat>[]>(
    () => [
      {id: "provider", isRowHeader: true, header: t("sms.stats.columns.provider"), minWidth: 150, cell: (g) => <Tech mono={false} className="text-sm">{providerLabel(g.provider)}</Tech>},
      {id: "accepted", header: t("sms.stats.columns.accepted"), align: "end", minWidth: 100, cell: (g) => <span className="text-sm tabular-nums">{format.number(g.accepted)}</span>},
      {id: "failed", header: t("sms.stats.columns.failed"), align: "end", minWidth: 100, cell: (g) => <span className="text-sm tabular-nums">{format.number(g.failed)}</span>},
    ],
    [t, format],
  );

  const kpis = [
    {id: "otp", title: t("sms.stats.kpi.otp"), value: totals.otp},
    {id: "outbox", title: t("sms.stats.kpi.outbox"), value: totals.outbox},
    {id: "cost", title: t("sms.stats.kpi.cost"), value: totals.cost},
    {id: "accepted", title: t("sms.stats.kpi.accepted"), value: totals.accepted},
    {id: "failed", title: t("sms.stats.kpi.failed"), value: totals.failed},
  ];

  return (
    <div className="flex flex-col gap-6" data-testid="sms-stats">
      <p className="text-muted text-sm">{t("sms.stats.range", {days: STATS_DAYS})}</p>
      <ul className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        {kpis.map((k) => (
          <li key={k.id} data-testid={`kpi-${k.id}`}>
            <KPI>
              <KPI.Header>
                {/* The title is a `dt`; a lone one has no `dl`, which axe fails, so it is a term as the lab's KPI marks it. */}
                <KPI.Title role="term">{k.title}</KPI.Title>
              </KPI.Header>
              <KPI.Content>
                <NumberValue className="kpi__value" locale={numberLocale} maximumFractionDigits={k.id === "cost" ? 4 : 0} value={k.value} />
              </KPI.Content>
            </KPI>
          </li>
        ))}
      </ul>
      <section aria-labelledby="stats-days" className="flex flex-col gap-2">
        <h3 id="stats-days" className="text-sm font-medium">
          {t("sms.stats.perDay")}
        </h3>
        <DataGrid aria-label={t("sms.stats.perDay")} columns={dayColumns} data={stats.days} getRowId={(d) => d.day} contentClassName="min-w-[28rem]" scrollContainerClassName="max-h-[24rem] overflow-auto" />
      </section>
      <section aria-labelledby="stats-gateways" className="flex flex-col gap-2">
        <h3 id="stats-gateways" className="text-sm font-medium">
          {t("sms.stats.perGateway")}
        </h3>
        <DataGrid aria-label={t("sms.stats.perGateway")} columns={gatewayColumns} data={stats.gateways} getRowId={(g) => g.provider} contentClassName="min-w-[22rem]" />
      </section>
    </div>
  );
}
