"use client";

import type {NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import type {PairView} from "@ctrlz/api-client/admin/hooks/pairs.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Card} from "@heroui/react";
import {useTranslations} from "next-intl";

import {Tech} from "../../data/Tech.tsx";
import {PairAnswering} from "./PairAnswering.tsx";
import {PlainCopyButton} from "./PlainCopyButton.tsx";
import {advertisedNode, byIdMap, revokedMembers} from "./pairParts.ts";
import {HealthChip} from "./HealthChip.tsx";
import {nodeHealth} from "@ctrlz/api-client/admin/hooks/nodes.ts";

// T-341. The global pair on its own: free DNS and every Endpoint use it (D30), so it is the one pair whose two nodes and addresses the
// admin reads first. Primary first, as the free DNS card lists them. Each node links to its page, where its state and requests are.

export function PairGlobalCard({pair, nodes}: {pair: PairView | undefined; nodes: readonly NodeView[]}) {
  const t = useTranslations("nodes");
  const byId = byIdMap(nodes);
  return (
    <Card className="max-w-3xl gap-4 p-6" data-testid="pair-global">
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("pair.global.title")}</Card.Title>
        <Card.Description>{t("pair.global.text")}</Card.Description>
      </Card.Header>
      <Card.Content className="flex flex-col gap-4">
        {!pair ? (
          <div className="bg-surface-secondary flex flex-col gap-1 rounded-(--radius-box) p-4 text-sm" data-testid="pair-global-none">
            <span className="font-medium">{t("pair.global.none.title")}</span>
            <span className="text-muted">{t("pair.global.none.text")}</span>
          </div>
        ) : (
          <>
            <ul className="flex flex-col gap-2">
              {(["primary", "fallback"] as const).map((role) => {
                const node = byId.get(role === "primary" ? pair.primary_node_id : pair.fallback_node_id);
                return (
                  <li key={role} className="border-separator flex flex-wrap items-center justify-between gap-3 rounded-(--radius-box) border px-4 py-3" data-testid={`global-${role}`}>
                    <div className="flex min-w-0 flex-col gap-1">
                      <span className="text-muted text-xs">{t(`pair.global.${role}`)}</span>
                      {node ? (
                        <>
                          <Link href={`/nodes/${node.id}`} className="text-sm font-medium underline-offset-2 hover:underline" aria-label={t("nodes.openRow", {name: node.name})}>
                            {node.name}
                          </Link>
                          {node.dns_advertised_ip ? <Tech className="text-sm">{node.dns_advertised_ip}</Tech> : <span className="text-muted text-sm">{t("nodes.noAddress")}</span>}
                        </>
                      ) : (
                        <span className="text-muted text-sm">{t("pair.advertised.unknown")}</span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      {node ? <HealthChip health={nodeHealth(node)} /> : null}
                      {/* A revoked node is still advertised until the pair changes, but its address is not one to hand out (PG-r2-6). */}
                      {node?.dns_advertised_ip && node.status === "active" ? <PlainCopyButton text={node.dns_advertised_ip} label={t("pair.global.copy", {role: t(`pair.global.${role}`)})} /> : null}
                    </div>
                  </li>
                );
              })}
            </ul>
            <div className="flex flex-col gap-1">
              <span className="text-muted text-xs">{t("pair.global.answering")}</span>
              <PairAnswering advertised={advertisedNode(pair, byId)} revoked={revokedMembers(pair, byId).map((n) => n.name)} />
            </div>
          </>
        )}
      </Card.Content>
    </Card>
  );
}
