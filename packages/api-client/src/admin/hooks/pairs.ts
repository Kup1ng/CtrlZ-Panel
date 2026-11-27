import {infiniteQueryOptions, useInfiniteQuery, useMutation, useQueryClient} from "@tanstack/react-query";

import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";

// P4, p4-nodes 9.2. The pairs of nodes and the global pair. A pair change is `admin-fresh` and queues `pair_change`.

type S = components["schemas"];
export type PairView = S["PairView"];
export type PairRequest = S["PairRequest"];

export const pairKeys = {all: ["admin", "pairs"] as const};

export const pairsQueryOptions = () =>
  infiniteQueryOptions({
    queryKey: pairKeys.all,
    queryFn: async ({pageParam, signal}) => required(await adminApi.GET("/pairs", {params: {query: {cursor: pageParam, limit: 50}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    retry: shouldRetry,
  });
export const usePairs = () => useInfiniteQuery(pairsQueryOptions());

function useInvalidatePairs() {
  const queryClient = useQueryClient();
  // A pair changes what the nodes list says of each node (`pair_peer_id`) and what the overview shows, so they are asked again too.
  return () =>
    Promise.all([
      queryClient.invalidateQueries({queryKey: pairKeys.all}),
      queryClient.invalidateQueries({queryKey: ["admin", "nodes"]}),
      queryClient.invalidateQueries({queryKey: ["admin", "overview"]}),
    ]);
}

export function useCreatePair() {
  const invalidate = useInvalidatePairs();
  return useMutation({
    mutationFn: async (body: PairRequest) => required(await adminApi.POST("/pairs", {body})),
    onSettled: invalidate,
  });
}

export function useUpdatePair() {
  const invalidate = useInvalidatePairs();
  return useMutation({
    mutationFn: async ({id, ...body}: PairRequest & {id: string}) => required(await adminApi.PUT("/pairs/{id}", {params: {path: {id}}, body})),
    onSettled: invalidate,
  });
}

export function useDeletePair() {
  const invalidate = useInvalidatePairs();
  return useMutation({
    mutationFn: async (id: string) => {
      await adminApi.DELETE("/pairs/{id}", {params: {path: {id}}});
    },
    onSettled: invalidate,
  });
}

export function usePutGlobalPair() {
  const invalidate = useInvalidatePairs();
  return useMutation({
    mutationFn: async (pair_id: string) => required(await adminApi.PUT("/settings/global-pair", {body: {pair_id}})),
    onSettled: invalidate,
  });
}

export type GlobalAddress = {role: "primary" | "fallback"; node_id: string; name: string; ip: string; /** Revoked and still named by the pair: still advertised, not an address to hand out (PG-r3-3). */ revoked: boolean};

/**
 * The advertised DNS addresses of the global pair, primary first, for the places that show what a free DNS user types (T-556).
 * A node with no advertised address is absent: nothing is made up. A revoked member stays in the list, marked `revoked`, because a revocation
 * changes only the node's status and the pair keeps advertising it until it is replaced; the caller shows it as a warning, not as an address.
 */
export function globalPairAddresses(
  pairs: readonly PairView[],
  nodes: readonly {id: string; name: string; dns_advertised_ip?: string; status: string}[],
): GlobalAddress[] {
  const pair = pairs.find((p) => p.is_global);
  if (!pair) return [];
  const out: GlobalAddress[] = [];
  for (const [role, id] of [
    ["primary", pair.primary_node_id],
    ["fallback", pair.fallback_node_id],
  ] as const) {
    const node = nodes.find((n) => n.id === id);
    if (node?.dns_advertised_ip && (node.status === "active" || node.status === "revoked")) {
      out.push({role, node_id: node.id, name: node.name, ip: node.dns_advertised_ip, revoked: node.status === "revoked"});
    }
  }
  return out;
}
