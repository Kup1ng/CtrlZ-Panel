"use client";

import {contactState, hubParts, nodeHealth, permilleToPercent, useOverview, type NodeView, type Overview} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {reactAriaLocale} from "@ctrlz/i18n/locale.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Skeleton} from "@heroui/react";
import {DataGrid, NumberValue, type DataGridColumn} from "@heroui-pro/react";
import {KPI} from "@heroui-pro/react/kpi";
import {useTranslations} from "next-intl";
import {useMemo} from "react";

import {Tech} from "../../data/Tech.tsx";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {HealthChip, HubHealthChip} from "../nodes/HealthChip.tsx";
import {lagState, servingCount} from "../nodes/nodeParts.ts";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {keepRetry} from "../shared/restoreFocus.ts";
import {FreeCounters} from "./FreeCounters.tsx";

// p4-nodes 10.1, T-339. The first page of the admin: the health of every node, its last contact, its versions and how far its
// configuration is behind, the QPS and the cache hit rate of the system as a whole (no node figure: the document has none), and the
// counters of free DNS. What only the hub knows of a node is shown when the document carries it and "not reported yet" until then.

export function OverviewPage() {
  const t = useTranslations("nodes");
  const overview = useOverview();
  return (
    <>
      <PageHeader icon="overview" title={t("pages.overview.title")} subtitle={t("pages.overview.subtitle")} />
      {overview.isPending ? (
        <div role="status" aria-busy="true" data-testid="overview-loading" className="flex flex-col gap-3">
          <Skeleton className="h-24 w-full rounded-(--radius-box)" />
          <Skeleton className="h-48 w-full rounded-(--radius-box)" />
        </div>
      ) : !overview.data ? (
        <SectionError error={overview.error} onRetry={keepRetry(() => overview.refetch())} />
      ) : (
        <div className="flex flex-col gap-8">
          <RefreshFailed error={overview.error} onRetry={() => overview.refetch()} />
          <Totals overview={overview.data} />
          <NodesHealth nodes={overview.data.nodes} />
          <FreeCounters nodes={overview.data.nodes} />
        </div>
      )}
    </>
  );
}

function Totals({overview}: {overview: Overview}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const numberLocale = reactAriaLocale[format.locale];
  const {serving, total} = servingCount(overview.nodes, (n) => nodeHealth(n));
  const notReported = <span className="text-muted text-base font-medium">{t("notReported")}</span>;

  const tiles: {id: string; title: string; hint?: string; value: React.ReactNode}[] = [
    {
      id: "serving",
      title: t("overview.kpi.serving"),
      value: <span className="kpi__value tabular-nums">{t("overview.kpi.servingValue", {serving: format.number(serving), total: format.number(total)})}</span>,
    },
    {
      id: "qps",
      title: t("overview.kpi.qps"),
      hint: t("overview.kpi.qpsHint"),
      value: overview.qps === undefined ? notReported : <NumberValue className="kpi__value" locale={numberLocale} maximumFractionDigits={0} value={overview.qps} />,
    },
    {
      id: "cache",
      title: t("overview.kpi.cache"),
      hint: t("overview.kpi.cacheHint"),
      value:
        overview.cache_hit_permille === undefined ? (
          notReported
        ) : (
          <span className="kpi__value tabular-nums">{format.number(permilleToPercent(overview.cache_hit_permille) / 100, {style: "percent", maximumFractionDigits: 1})}</span>
        ),
    },
    {
      id: "head",
      title: t("overview.kpi.head"),
      hint: t("overview.kpi.headHint"),
      value: <span className="kpi__value tabular-nums">{format.number(overview.config_head, {useGrouping: false})}</span>,
    },
    {
      id: "free",
      title: t("overview.kpi.free"),
      hint: overview.free_dns.enabled ? t("overview.free.limit", {qps: format.number(overview.free_dns.qps, {useGrouping: false})}) : undefined,
      value: <span className="text-base font-medium">{overview.free_dns.enabled ? t("overview.free.on") : t("overview.free.off")}</span>,
    },
  ];

  return (
    <ul aria-label={t("overview.kpiLabel")} className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5" data-testid="overview-kpis">
      {tiles.map((k) => (
        <li key={k.id} data-testid={`kpi-${k.id}`}>
          <KPI>
            <KPI.Header>
              {/* The title is a `dt`; a lone one has no `dl`, which axe fails, so it is a term as the lab's KPI marks it. */}
              <KPI.Title role="term">{k.title}</KPI.Title>
            </KPI.Header>
            <KPI.Content>
              <div className="flex flex-col gap-1">
                {k.value}
                {k.hint ? <span className="text-muted text-xs">{k.hint}</span> : null}
              </div>
            </KPI.Content>
          </KPI>
        </li>
      ))}
    </ul>
  );
}

const tech = (chunks: React.ReactNode) => <Tech>{chunks}</Tech>;

function NodesHealth({nodes}: {nodes: NodeView[]}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();

  const columns = useMemo<DataGridColumn<NodeView>[]>(
    () => [
      {
        id: "node",
        isRowHeader: true,
        header: t("overview.nodes.columns.node"),
        minWidth: 150,
        cell: (n) => (
          <div className="flex flex-col">
            <Link href={`/nodes/${n.id}`} className="text-sm font-medium underline-offset-2 hover:underline" aria-label={t("nodes.openRow", {name: n.name})}>
              {n.name}
            </Link>
            <span className="text-muted text-xs">{t("overview.nodes.slot", {slot: format.number(n.slot)})}</span>
          </div>
        ),
      },
      {id: "health", header: t("overview.nodes.columns.health"), minWidth: 170, cell: (n) => <HealthChip health={nodeHealth(n)} />},
      {
        id: "contact",
        header: t("overview.nodes.columns.contact"),
        minWidth: 150,
        cell: (n) =>
          contactState(n) === "never" || !n.last_heartbeat_at ? (
            <span className="text-muted text-sm">{t("overview.nodes.contactNever")}</span>
          ) : (
            <time dateTime={n.last_heartbeat_at} title={format.dateTime(n.last_heartbeat_at)} className="text-sm">
              {format.relative(n.last_heartbeat_at)}
            </time>
          ),
      },
      {
        id: "version",
        header: t("overview.nodes.columns.version"),
        minWidth: 190,
        cell: (n) =>
          n.node_version || n.unbound_version || n.catalog_version ? (
            <div className="flex flex-col text-xs">
              {n.node_version ? <span>{t.rich("overview.nodes.versionNode", {version: n.node_version, tech})}</span> : null}
              {n.unbound_version ? <span>{t.rich("overview.nodes.versionUnbound", {version: n.unbound_version, tech})}</span> : null}
              {n.catalog_version ? <span>{t.rich("overview.nodes.versionCatalog", {version: n.catalog_version, tech})}</span> : null}
            </div>
          ) : (
            <span className="text-muted text-sm">{t("overview.nodes.versionNone")}</span>
          ),
      },
      {
        id: "lag",
        header: t("overview.nodes.columns.lag"),
        minWidth: 190,
        cell: (n) => {
          const lag = lagState(n);
          if (lag.kind === "none") return <span className="text-muted text-sm">—</span>;
          if (lag.kind === "upToDate") return <span className="text-sm">{t("overview.nodes.lag.upToDate")}</span>;
          return (
            <div className="flex flex-col">
              <span className="text-sm font-medium">{t("overview.nodes.lag.behind", {count: lag.count})}</span>
              <span className="text-muted text-xs tabular-nums">{t("overview.nodes.lag.applied", {applied: format.number(lag.applied, {useGrouping: false}), head: format.number(lag.head, {useGrouping: false})})}</span>
            </div>
          );
        },
      },
      {
        id: "hub",
        header: t("overview.nodes.columns.hub"),
        minWidth: 150,
        cell: (n) => {
          const hub = hubParts(n);
          return hub.health ? <HubHealthChip health={hub.health} /> : <span className="text-muted text-sm">{t("notReported")}</span>;
        },
      },
    ],
    [t, format],
  );

  return (
    <section aria-labelledby="overview-nodes" className="flex flex-col gap-2">
      <h2 id="overview-nodes" className="text-base font-medium">
        {t("overview.nodes.title")}
      </h2>
      {nodes.length === 0 ? (
        <div className="bg-surface rounded-(--radius-box) shadow-surface" data-testid="grid-empty">
          <SectionEmpty icon="nodes" title={t("overview.nodes.empty.title")} description={t("overview.nodes.empty.text")} size="md" className="py-10" />
        </div>
      ) : (
        <DataGrid
          aria-label={t("overview.nodes.gridLabel")}
          columns={columns}
          data={nodes}
          getRowId={(n) => n.id}
          contentClassName="min-w-[48rem]"
          scrollContainerClassName="max-h-[calc(100dvh-14rem)] overflow-auto"
        />
      )}
    </section>
  );
}
