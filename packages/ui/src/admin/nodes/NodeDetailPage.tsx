"use client";

import {useNode, useNodes} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {usePairs} from "@ctrlz/api-client/admin/hooks/pairs.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {buttonVariants, Skeleton} from "@heroui/react";
import {useTranslations} from "next-intl";

import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {keepRetry} from "../shared/restoreFocus.ts";
import {NodeAddressesCard} from "./NodeAddressesCard.tsx";
import {NodeFailover} from "./NodeFailover.tsx";
import {NodeLifecycle} from "./NodeLifecycle.tsx";
import {NodeReports} from "./NodeReports.tsx";
import {NodeSettingsCard} from "./NodeSettingsCard.tsx";
import {NodeSummary} from "./NodeSummary.tsx";

// p4-nodes 10.1, T-542: one node. Its state and the hub's view, the failover and the three requests, approve, revoke and remove with
// their conditions, its addresses and name, and after a revoke the claims its reports hold. The page asks for the node every 30 s, as the
// list does, and a refresh that fails keeps what is on screen and says so.

export function BackToNodes() {
  const t = useTranslations("nodes");
  return (
    <Link href="/nodes" className={buttonVariants({variant: "ghost", size: "sm", className: "mb-2 self-start"})} data-testid="back-to-nodes">
      <Icon name="chevron" className="size-4 ltr:rotate-180" />
      {t("node.back")}
    </Link>
  );
}

export function NodeDetailPage({id}: {id: string}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const node = useNode(id);
  const all = useNodes();
  const pairsQuery = usePairs();
  const peerId = node.data?.pair_peer_id;
  const peerName = peerId ? all.data?.pages.flatMap((p) => p.items).find((n) => n.id === peerId)?.name : undefined;

  if (node.isPending) {
    return (
      <>
        <BackToNodes />
        <div role="status" aria-busy="true" aria-label={t("node.loadingLabel")} className="flex flex-col gap-4">
          <Skeleton className="h-16 w-full rounded-(--radius-box)" />
          <Skeleton className="h-64 w-full rounded-(--radius-box)" />
        </div>
      </>
    );
  }

  if (!node.data) {
    return (
      <>
        <BackToNodes />
        {hasCode(node.error, "not_found") ? (
          <SectionEmpty icon="nodes" title={t("node.notFound.title")} description={t("node.notFound.text")} size="md" />
        ) : (
          <SectionError error={node.error} onRetry={keepRetry(() => node.refetch())} />
        )}
      </>
    );
  }

  const n = node.data;
  // The role of the node in its pair comes from the pairs list, so a node is called advertised only when the pair says it is (PG-r1-3).
  const pairList = pairsQuery.data?.pages.flatMap((p) => p.items);
  const inGlobalPair = pairList?.some((p) => p.is_global && (p.primary_node_id === n.id || p.fallback_node_id === n.id)) ?? false;
  const nodeList = all.data?.pages.flatMap((p) => p.items);
  return (
    <>
      <BackToNodes />
      <PageHeader icon="nodes" title={n.name} subtitle={t("nodes.slot", {slot: format.number(n.slot)})} />
      <RefreshFailed error={node.error} onRetry={() => node.refetch()} />
      <div className="grid items-start gap-6 lg:grid-cols-2" data-testid="node-detail" data-node-status={n.status}>
        <NodeSummary node={n} peerName={peerName} />
        <NodeFailover node={n} pairs={pairList} nodes={nodeList} />
        <NodeLifecycle node={n} peerName={peerName} others={nodeList} />
        <NodeAddressesCard key={`addresses-${n.id}`} node={n} inGlobalPair={inGlobalPair} />
        <NodeSettingsCard key={`settings-${n.id}`} node={n} />
        {n.status === "revoked" ? <NodeReports nodeId={n.id} /> : null}
      </div>
    </>
  );
}
