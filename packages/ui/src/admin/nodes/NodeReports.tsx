"use client";

import {reportClaims, reportsStalled, useNodeReports, type NodeReports as Reports} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button} from "@heroui/react";
import {Segment, type DataGridColumn} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useId, useMemo, useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {PagedGrid} from "../shared/PagedGrid.tsx";
import {keepRetry} from "../shared/restoreFocus.ts";
import {NodeCard} from "./NodeCard.tsx";
import {REPORT_WINDOWS, reportsFrom, type ReportWindow} from "./nodeParts.ts";

// p4-nodes 4.5: after a revoke, the claims taken on the node's observations since a time the admin picks (the runbook's next step), and
// the learned rows the `node_revoked` job could not delete. The route sends 200 claims at a time, newest first, and says when more exist;
// the page asks for the older ones with a button of its own, so the load is the admin's act and the keyboard reaches it. A claim the route
// reads twice at the seam of two pages is shown once. The page names tenants and endpoints by id only: the panel holds nothing more.

type Claim = Reports["claims"][number];

export function NodeReports({nodeId}: {nodeId: string}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const labelId = useId();
  const [days, setDays] = useState<ReportWindow>(30);
  // The start of a day, so the key is the same on every render and every poll.
  const from = useMemo(() => reportsFrom(days), [days]);
  const query = useNodeReports(nodeId, from);
  const claims = useMemo(() => reportClaims(query.data?.pages ?? []), [query.data]);
  const kept = query.data?.pages[0];
  const stalled = reportsStalled(query.data?.pages ?? []);

  const columns = useMemo<DataGridColumn<Claim>[]>(
    () => [
      {id: "tenant", isRowHeader: true, header: t("node.reports.columns.tenant"), minWidth: 290, cell: (c) => <Tech className="text-xs whitespace-nowrap">{c.tenant_id}</Tech>},
      {id: "endpoint", header: t("node.reports.columns.endpoint"), minWidth: 290, cell: (c) => <Tech className="text-xs whitespace-nowrap">{c.endpoint_id}</Tech>},
      {id: "claim", header: t("node.reports.columns.claim"), minWidth: 290, cell: (c) => <Tech className="text-xs whitespace-nowrap">{c.claim_id}</Tech>},
      {id: "range", header: t("node.reports.columns.range"), minWidth: 130, cell: (c) => <Tech className="text-sm">{c.cidr}</Tech>},
      {id: "at", header: t("node.reports.columns.at"), minWidth: 160, cell: (c) => <span className="text-sm">{format.dateTime(c.consumed_at)}</span>},
    ],
    [t, format],
  );

  return (
    <NodeCard title={t("node.reports.title")} description={t("node.reports.text")} testId="node-reports" className="lg:col-span-2">
      <div className="flex flex-col gap-1">
        <span id={labelId} className="text-sm font-medium">
          {t("node.reports.window")}
        </span>
        <Segment aria-labelledby={labelId} selectedKey={String(days)} onSelectionChange={(key) => setDays(Number(key) as ReportWindow)}>
          {REPORT_WINDOWS.map((d) => (
            <Segment.Item key={d} id={String(d)}>
              {t("node.reports.days", {days: d})}
            </Segment.Item>
          ))}
        </Segment>
      </div>
      <PagedGrid
        label={t("node.reports.gridLabel")}
        columns={columns}
        rows={claims}
        getRowId={(c) => c.claim_id}
        isPending={query.isPending}
        error={query.error}
        onRetry={keepRetry(() => query.refetch())}
        refetch={() => query.refetch()}
        hasNextPage={false}
        isFetchingNextPage={false}
        fetchNextPage={() => undefined}
        isNextPageError={false}
        empty={{icon: "shield", title: t("node.reports.empty.title"), description: t("node.reports.empty.text")}}
        minWidth="min-w-[60rem]"
      />
      {query.hasNextPage ? (
        <div className="flex flex-col items-start gap-2" data-testid="reports-truncated">
          <p className="text-muted text-sm">{t("node.reports.truncated")}</p>
          <Button variant="secondary" isPending={query.isFetchingNextPage} onPress={keepRetry(() => query.fetchNextPage())}>
            {t("node.reports.more")}
          </Button>
        </div>
      ) : null}
      {stalled ? (
        <p role="status" className="flex items-start gap-2 text-sm" data-testid="reports-stalled">
          <Icon name="warning" className="mt-0.5 size-4 shrink-0" />
          {t("node.reports.stalled")}
        </p>
      ) : null}
      {kept ? (
        <section aria-labelledby={`${labelId}-kept`} className="flex flex-col gap-2" data-testid="reports-kept">
          <h3 id={`${labelId}-kept`} className="text-sm font-medium">
            {t("node.reports.kept.title")}
          </h3>
          <p className="text-muted text-sm">{t("node.reports.kept.text")}</p>
          {kept.kept_rows.length === 0 ? (
            <p className="text-sm">{t("node.reports.kept.none")}</p>
          ) : (
            <ul className="flex flex-col gap-1 text-sm">
              {kept.kept_rows.map((r) => (
                <li key={`${r.tenant_id}/${r.endpoint_id}`}>
                  {t.rich("node.reports.kept.row", {tenant: r.tenant_id, endpoint: r.endpoint_id, tech: (chunks) => <Tech className="text-xs">{chunks}</Tech>})}
                </li>
              ))}
            </ul>
          )}
          {kept.kept_truncated ? <p className="text-muted text-sm">{t("node.reports.kept.cut")}</p> : null}
        </section>
      ) : null}
    </NodeCard>
  );
}
