"use client";

import {hubParts, nodeHealth, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert} from "@heroui/react";
import {useTranslations} from "next-intl";

import {Tech} from "../../data/Tech.tsx";
import {HealthChip, HubHealthChip} from "./HealthChip.tsx";
import {Facts, NodeCard, NotReported} from "./NodeCard.tsx";
import {lagState} from "./nodeParts.ts";

// p4-nodes 10.1, T-542: the node's state as a word, what the hub says of it, and what the database holds of it. The parts that live
// in the memory of the hub are shown when the document carries them and read "not reported yet" until then (the page says so, it never
// guesses).

export function NodeSummary({node, peerName}: {node: NodeView; peerName: string | undefined}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const hub = hubParts(node);
  const lag = lagState(node);
  const tech = (chunks: React.ReactNode) => <Tech>{chunks}</Tech>;
  const notReported = <NotReported text={t("notReported")} />;

  return (
    <NodeCard title={t("node.summary.title")} testId="node-summary" className="lg:col-span-2">
      {hub.revocation_pending ? (
        <Alert status="warning" data-testid="revocation-pending">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t("node.revocationPending.title")}</Alert.Title>
            <Alert.Description>{t("node.revocationPending.text")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <Facts
        rows={[
          {id: "state", label: t("node.summary.state"), value: <HealthChip health={nodeHealth(node)} />},
          {id: "hub", label: t("node.summary.hub"), value: hub.health ? <HubHealthChip health={hub.health} /> : notReported},
          {
            id: "contact",
            label: t("node.summary.contact"),
            value: node.last_heartbeat_at ? (
              <time dateTime={node.last_heartbeat_at} title={format.dateTime(node.last_heartbeat_at)}>
                {format.relative(node.last_heartbeat_at)}
              </time>
            ) : (
              t("nodes.contactNever")
            ),
          },
          {
            id: "pair",
            label: t("node.summary.pair"),
            value: node.pair_peer_id ? (
              <Link href={`/nodes/${node.pair_peer_id}`} className="underline underline-offset-2">
                {peerName ? t("nodes.pair.with", {name: peerName}) : t("nodes.pair.unknownPeer")}
              </Link>
            ) : (
              t("nodes.pair.none")
            ),
          },
          {id: "slot", label: t("node.summary.slot"), value: format.number(node.slot)},
          {id: "mode", label: t("node.summary.mode"), value: t(`node.mode.${node.resolve_mode}`)},
          {id: "created", label: t("node.summary.created"), value: format.dateTime(node.created_at)},
          {id: "fingerprint", label: t("node.summary.fingerprint"), value: node.key_fingerprint ? <Tech className="text-xs">{node.key_fingerprint}</Tech> : t("nodes.noAddress")},
          {id: "dns", label: t("nodes.columns.dns"), value: node.dns_advertised_ip ? <Tech>{node.dns_advertised_ip}</Tech> : t("nodes.noAddress")},
          {id: "proxy", label: t("nodes.columns.proxy"), value: node.proxy_advertised_ip ? <Tech>{node.proxy_advertised_ip}</Tech> : t("nodes.noAddress")},
          {
            id: "versions",
            label: t("node.summary.versions"),
            value:
              node.node_version || node.unbound_version || node.catalog_version ? (
                <span className="flex flex-col text-xs">
                  {node.node_version ? <span>{t.rich("overview.nodes.versionNode", {version: node.node_version, tech})}</span> : null}
                  {node.unbound_version ? <span>{t.rich("overview.nodes.versionUnbound", {version: node.unbound_version, tech})}</span> : null}
                  {node.catalog_version ? <span>{t.rich("overview.nodes.versionCatalog", {version: node.catalog_version, tech})}</span> : null}
                </span>
              ) : (
                t("overview.nodes.versionNone")
              ),
          },
          {
            id: "config",
            label: t("node.summary.config"),
            value:
              lag.kind === "none" ? (
                "-"
              ) : lag.kind === "upToDate" ? (
                <span className="inline-flex items-center gap-1">
                  <Icon name="check" className="size-4" />
                  {t("overview.nodes.lag.upToDate")}
                </span>
              ) : (
                <span className="inline-flex flex-wrap items-center gap-x-2">
                  <Icon name="warning" className="size-4" />
                  {t("overview.nodes.lag.behind", {count: lag.count})}
                  <span className="text-muted text-xs">{t("overview.nodes.lag.applied", {applied: format.number(lag.applied), head: format.number(lag.head)})}</span>
                </span>
              ),
          },
          {
            id: "proxy-state",
            label: t("node.summary.proxy"),
            value: node.proxy_blocked ? (
              <span className="inline-flex items-center gap-1">
                <Icon name="warning" className="size-4" />
                {t("node.summary.proxyBlocked")}
              </span>
            ) : (
              t("node.summary.proxyOpen")
            ),
          },
        ]}
      />
    </NodeCard>
  );
}
