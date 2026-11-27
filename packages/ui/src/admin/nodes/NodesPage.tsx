"use client";

import {contactState, NODE_LIMIT, nodeHealth, useNodes, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link, useRouter} from "@ctrlz/i18n/navigation.ts";
import {Chip} from "@heroui/react";
import type {DataGridColumn} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useMemo} from "react";

import {Tech} from "../../data/Tech.tsx";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {gridState, PagedGrid} from "../shared/PagedGrid.tsx";
import {FreeDnsCard} from "./FreeDnsCard.tsx";
import {GivenUpSection} from "./GivenUpSection.tsx";
import {HealthChip} from "./HealthChip.tsx";
import {PendingEnrolments} from "./PendingEnrolments.tsx";
import {ReplacementOrder} from "./ReplacementOrder.tsx";
import {noSlotFree} from "./pairParts.ts";

// p4-nodes 10.1. The nodes, then what free DNS gives out and its switch (T-556), then the addresses given up with their safe dates
// and the fixed note (T-546), with the link to the runbook (T-561). A node's name opens its page (T-542), the plus
// enrols a new host (T-340), and a host waiting for its fingerprint to be compared is pointed out at the top.

export function NodesPage() {
  const t = useTranslations("nodes");
  const router = useRouter();
  return (
    <>
      <PageHeader
        icon="nodes"
        title={t("pages.nodes.title")}
        subtitle={t("pages.nodes.subtitle")}
        onCreate={() => router.push("/nodes/enrol")}
        createLabel={t("pages.enrol.title")}
      />
      <div className="flex flex-col gap-8">
        <PendingEnrolments />
        <NodesList />
        <FreeDnsCard />
        <GivenUpSection />
      </div>
    </>
  );
}

function NodesList() {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const nodes = useNodes();
  const grid = gridState(nodes);
  const byId = useMemo(() => new Map(grid.rows.map((n) => [n.id, n])), [grid.rows]);

  const columns = useMemo<DataGridColumn<NodeView>[]>(
    () => [
      {
        id: "name",
        isRowHeader: true,
        header: t("nodes.columns.name"),
        minWidth: 170,
        cell: (n) => (
          <div className="flex flex-col gap-0.5">
            <Link href={`/nodes/${n.id}`} className="text-sm font-medium underline-offset-2 hover:underline" aria-label={t("nodes.openRow", {name: n.name})}>
              {n.name}
            </Link>
            <span className="text-muted text-xs">{t("nodes.slot", {slot: format.number(n.slot)})}</span>
            {n.proxy_blocked ? (
              <Chip size="sm" variant="soft" color="warning" className="self-start">
                <Chip.Label>{t("nodes.proxyBlocked")}</Chip.Label>
              </Chip>
            ) : null}
          </div>
        ),
      },
      {id: "status", header: t("nodes.columns.status"), minWidth: 170, cell: (n) => <HealthChip health={nodeHealth(n)} />},
      {id: "dns", header: t("nodes.columns.dns"), minWidth: 140, cell: (n) => (n.dns_advertised_ip ? <Tech className="text-sm">{n.dns_advertised_ip}</Tech> : <span className="text-muted text-sm">{t("nodes.noAddress")}</span>)},
      {id: "proxy", header: t("nodes.columns.proxy"), minWidth: 140, cell: (n) => (n.proxy_advertised_ip ? <Tech className="text-sm">{n.proxy_advertised_ip}</Tech> : <span className="text-muted text-sm">{t("nodes.noAddress")}</span>)},
      {
        id: "contact",
        header: t("nodes.columns.contact"),
        minWidth: 150,
        cell: (n) =>
          contactState(n) === "never" || !n.last_heartbeat_at ? (
            <span className="text-muted text-sm">{t("nodes.contactNever")}</span>
          ) : (
            <time dateTime={n.last_heartbeat_at} title={format.dateTime(n.last_heartbeat_at)} className="text-sm">
              {format.relative(n.last_heartbeat_at)}
            </time>
          ),
      },
      {
        id: "pair",
        header: t("nodes.columns.pair"),
        minWidth: 150,
        cell: (n) => {
          if (!n.pair_peer_id) return <span className="text-muted text-sm">{t("nodes.pair.none")}</span>;
          const peer = byId.get(n.pair_peer_id);
          return <span className="text-sm">{peer ? t("nodes.pair.with", {name: peer.name}) : t("nodes.pair.unknownPeer")}</span>;
        },
      },
    ],
    [t, format, byId],
  );

  return (
    <section aria-labelledby="nodes-list" className="flex flex-col gap-2">
      <h2 id="nodes-list" className="sr-only">
        {t("nodes.gridLabel")}
      </h2>
      <PagedGrid
        {...grid}
        label={t("nodes.gridLabel")}
        columns={columns}
        getRowId={(n) => n.id}
        minWidth="min-w-[52rem]"
        empty={{icon: "nodes", title: t("nodes.empty.title"), description: t("nodes.empty.text")}}
      />
      {noSlotFree(grid.rows, NODE_LIMIT) && !grid.hasNextPage ? <ReplacementOrder /> : null}
    </section>
  );
}
