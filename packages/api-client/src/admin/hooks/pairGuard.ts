import {queryOptions} from "@tanstack/react-query";

import {required} from "../../core.ts";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";
import {contactState, type NodeView} from "./nodes.ts";
import {pairKeys, type PairView} from "./pairs.ts";

// The read a pair form makes before the write that follows the fresh-code dialog (PG-r1-14, PG-r2-5, PG-r2-8). The warnings and the
// refusals the admin read were worked out from the pairs and the nodes at the moment of choosing, and the dialog has no timeout. So the
// guard compares what those warnings were made from: whether a global pair exists, the pairs that hold any of the nodes of the change, and
// the flags of those nodes that SC 8a.9 reads (withdrawn, held, behind, in contact). The hub flips the withdrawn flag on its own, so a node
// that changed meanwhile is a change the admin has not seen. Everything is a string, so two shapes compare with one test.

export type PairGuardShape = {global: boolean; pairs: string[]; nodes: string[]};

type NodeFlags = Pick<NodeView, "id" | "status" | "dns_withdrawn" | "dns_hold" | "applied_seq_lag" | "last_heartbeat_at">;

/**
 * `ids` are the nodes of the change (the two chosen, and the two the edited pair holds now); `editing` is the pair being edited, which
 * counts as moved when it is gone. `now` only decides the contact bucket of a node.
 */
export function pairGuardShape(pairs: readonly PairView[], nodes: readonly NodeFlags[], ids: readonly (string | null | undefined)[], editing?: string, now: number = Date.now()): PairGuardShape {
  const wanted = [...new Set(ids.filter((id): id is string => typeof id === "string" && id !== ""))].sort();
  const touches = (p: PairView) => p.id === editing || wanted.includes(p.primary_node_id) || wanted.includes(p.fallback_node_id);
  return {
    global: pairs.some((p) => p.is_global),
    pairs: pairs
      .filter(touches)
      .map((p) => `${p.id}:${p.primary_node_id}:${p.fallback_node_id}:${p.is_global ? 1 : 0}`)
      .sort(),
    nodes: wanted.map((id) => {
      const n = nodes.find((row) => row.id === id);
      return n ? `${id}:${n.status}:${n.dns_withdrawn ? 1 : 0}:${n.dns_hold ? 1 : 0}:${n.applied_seq_lag > 0 ? 1 : 0}:${contactState(n, now)}` : `${id}:gone`;
    }),
  };
}

export const samePairGuard = (a: PairGuardShape, b: PairGuardShape): boolean => a.global === b.global && a.pairs.join("|") === b.pairs.join("|") && a.nodes.join("|") === b.nodes.join("|");

export type PairGuardData = {pairs: PairView[]; nodes: NodeView[]};

/** The pairs and the nodes as the server holds them now. There are four nodes at most and two pairs, so a page of each is all there is. */
export const pairGuardQueryOptions = () =>
  queryOptions({
    queryKey: [...pairKeys.all, "guard"] as const,
    queryFn: async ({signal}): Promise<PairGuardData> => {
      const [pairs, nodes] = await Promise.all([
        adminApi.GET("/pairs", {params: {query: {limit: 50}}, signal}).then(required),
        adminApi.GET("/nodes", {params: {query: {limit: 50}}, signal}).then(required),
      ]);
      return {pairs: pairs.items, nodes: nodes.items};
    },
    retry: shouldRetry,
  });

