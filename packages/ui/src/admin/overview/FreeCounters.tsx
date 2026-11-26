"use client";

import {groupCounters, RCODE_NAMES, useFreeCounters, type CounterGroup} from "@ctrlz/api-client/admin/hooks/freeDns.ts";
import type {NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Skeleton} from "@heroui/react";
import {DataGrid, Segment, type DataGridColumn} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useEffect, useId, useMemo, useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {COUNTER_PAGES_MAX, counterRange, outcomeKey, type CounterWindow} from "../nodes/nodeParts.ts";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {keepRetry} from "../shared/restoreFocus.ts";

// T-339. The counters of free DNS by node, transport, outcome and rcode over a period (a day or a week). A row of the API holds a
// bucket, a node, a transport, an outcome, an rcode and a count, and no name or address, so this table holds none either. The period
// ends with the current hour and is fixed while the page is open, so the query is one query and not one for every render.

export function FreeCounters({nodes}: {nodes: NodeView[]}) {
  const t = useTranslations("nodes");
  const labelId = useId();
  const [period, setPeriod] = useState<CounterWindow>("day");
  // Chosen when the period is chosen, not at every render: the key of the query holds it.
  const range = useMemo(() => counterRange(period), [period]);
  const query = useFreeCounters(range.from, range.to);
  const {hasNextPage, isFetchingNextPage, fetchNextPage} = query;
  const pages = query.data?.pages.length ?? 0;

  // A period has a few hundred rows a day for four nodes, so the pages are taken one after the other, up to a bound.
  useEffect(() => {
    if (hasNextPage && !isFetchingNextPage && pages < COUNTER_PAGES_MAX) void fetchNextPage();
  }, [hasNextPage, isFetchingNextPage, pages, fetchNextPage]);

  const groups = useMemo(() => groupCounters(query.data?.pages.flatMap((p) => p.items) ?? []), [query.data]);
  const total = useMemo(() => groups.reduce((sum, g) => sum + g.count, 0), [groups]);
  const cut = hasNextPage && pages >= COUNTER_PAGES_MAX;

  return (
    <section aria-labelledby="overview-counters" className="flex flex-col gap-3" data-testid="free-counters">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex max-w-2xl flex-col gap-1">
          <h2 id="overview-counters" className="text-base font-medium">
            {t("overview.counters.title")}
          </h2>
          <p className="text-muted text-sm">{t("overview.counters.text")}</p>
        </div>
        <div className="flex flex-col gap-1">
          <span id={labelId} className="text-sm font-medium">
            {t("overview.counters.window.label")}
          </span>
          <Segment aria-labelledby={labelId} selectedKey={period} onSelectionChange={(key) => setPeriod(key as CounterWindow)}>
            <Segment.Item id="day">{t("overview.counters.window.day")}</Segment.Item>
            <Segment.Item id="week">{t("overview.counters.window.week")}</Segment.Item>
          </Segment>
        </div>
      </div>
      {query.isPending ? (
        <div role="status" aria-busy="true" data-testid="counters-loading">
          <Skeleton className="h-40 w-full rounded-(--radius-box)" />
        </div>
      ) : !query.data ? (
        <SectionError error={query.error} onRetry={keepRetry(() => query.refetch())} />
      ) : (
        <>
          <RefreshFailed error={query.error} onRetry={() => query.refetch()} />
          <Counters groups={groups} total={total} nodes={nodes} />
          {cut ? (
            <p role="note" className="text-muted text-sm" data-testid="counters-cut">
              {t("overview.counters.truncated")}
            </p>
          ) : null}
        </>
      )}
    </section>
  );
}

function Counters({groups, total, nodes}: {groups: CounterGroup[]; total: number; nodes: NodeView[]}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();

  const columns = useMemo<DataGridColumn<CounterGroup>[]>(() => {
    const nameOf = (id: string) => nodes.find((n) => n.id === id)?.name ?? t("overview.counters.removedNode");
    return [
      {id: "node", isRowHeader: true, header: t("overview.counters.columns.node"), minWidth: 140, cell: (g) => <span className="text-sm">{nameOf(g.node_id)}</span>},
      {id: "transport", header: t("overview.counters.columns.transport"), minWidth: 100, cell: (g) => <Tech className="text-sm">{g.transport.toUpperCase()}</Tech>},
      {id: "outcome", header: t("overview.counters.columns.outcome"), minWidth: 230, cell: (g) => <span className="text-sm">{t(`outcome.${outcomeKey(g.outcome)}`)}</span>},
      {
        id: "rcode",
        header: t("overview.counters.columns.rcode"),
        minWidth: 150,
        cell: (g) => (
          <span className="text-sm">
            <Tech>{RCODE_NAMES[g.rcode] ?? format.number(g.rcode, {useGrouping: false})}</Tech>
          </span>
        ),
      },
      {id: "count", header: t("overview.counters.columns.count"), align: "end", minWidth: 110, cell: (g) => <span className="text-sm tabular-nums">{format.number(g.count)}</span>},
    ];
  }, [t, format, nodes]);

  if (groups.length === 0) {
    return (
      <div className="bg-surface rounded-(--radius-box) shadow-surface" data-testid="counters-empty">
        <SectionEmpty icon="analytics" title={t("overview.counters.empty.title")} description={t("overview.counters.empty.text")} size="md" className="py-8" />
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm font-medium tabular-nums" data-testid="counters-total">
        {t("overview.counters.total", {count: format.number(total)})}
      </p>
      <DataGrid
        aria-label={t("overview.counters.gridLabel")}
        columns={columns}
        data={groups}
        getRowId={(g) => `${g.node_id}|${g.transport}|${g.outcome}|${g.rcode}`}
        contentClassName="min-w-[40rem]"
        scrollContainerClassName="max-h-[28rem] overflow-auto"
        stickyHeader
      />
    </div>
  );
}
