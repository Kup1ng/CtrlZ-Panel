import {infiniteQueryOptions, queryOptions, useInfiniteQuery, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";
import {nodeKeys} from "./nodes.ts";

// P4, T-556 and T-339. The free DNS switch and its `qps`, and the hourly counters (no name, no address). The write is `admin-fresh`.

type S = components["schemas"];
export type FreeDnsSettings = S["FreeDnsSettings"];
export type FreeDnsRequest = S["FreeDnsRequest"];
export type FreeCounterRow = S["FreeCounterRow"];

/**
 * The floor the page holds: a `qps` of 0 is refused, because the switch is how free DNS is turned off. There is no ceiling here. The ceiling
 * is the route's (2000 until T-374 measures it, p4-nodes 9.2), so a raised ceiling can be used without a release of the page and the page shows
 * the route's `qps_out_of_range` text for a value above it (PG-r1-8). The field's upper bound is the contract's own integer range.
 */
export const FREE_QPS_MIN = 1;
export const FREE_QPS_SCHEMA_MAX = 2147483647;

export const freeDnsKeys = {
  settings: ["admin", "free-dns", "settings"] as const,
  counters: (from: string, to: string, nodeId: string) => ["admin", "free-dns", "counters", from, to, nodeId] as const,
};

export const freeDnsQueryOptions = () =>
  queryOptions({
    queryKey: freeDnsKeys.settings,
    queryFn: async ({signal}) => required(await adminApi.GET("/settings/free-dns", {signal})),
    retry: shouldRetry,
  });
export const useFreeDns = () => useQuery(freeDnsQueryOptions());

export function useSaveFreeDns() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: FreeDnsRequest) => required(await adminApi.PUT("/settings/free-dns", {body})),
    onSuccess: (settings) => {
      queryClient.setQueryData(freeDnsKeys.settings, settings);
      // The overview carries the switch too.
      void queryClient.invalidateQueries({queryKey: nodeKeys.overview});
    },
  });
}

/** Hourly rows by node, transport, outcome and rcode over a window (at most 31 days). `nodeId` "" is every node. */
export function freeCountersQueryOptions(from: string, to: string, nodeId = "") {
  return infiniteQueryOptions({
    queryKey: freeDnsKeys.counters(from, to, nodeId),
    queryFn: async ({pageParam, signal}) =>
      required(
        await adminApi.GET("/free-dns/counters", {params: {query: {from, to, ...(nodeId ? {node_id: nodeId} : {}), cursor: pageParam, limit: 500}}, signal}),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    retry: shouldRetry,
  });
}
export const useFreeCounters = (from: string, to: string, nodeId = "") => useInfiniteQuery(freeCountersQueryOptions(from, to, nodeId));

export type CounterGroup = {node_id: string; transport: FreeCounterRow["transport"]; outcome: string; rcode: number; count: number};

/**
 * The hourly rows summed by node, transport, outcome and rcode. A row names neither a client nor a domain, so a group is only these
 * four fields and a count. Sorted by node, then by count, largest first; the sum stops at a safe integer so a figure is never NaN.
 */
export function groupCounters(rows: readonly FreeCounterRow[]): CounterGroup[] {
  const map = new Map<string, CounterGroup>();
  for (const r of rows) {
    const key = `${r.node_id}|${r.transport}|${r.outcome}|${r.rcode}`;
    const found = map.get(key);
    if (found) found.count = Math.min(Number.MAX_SAFE_INTEGER, found.count + r.count);
    else map.set(key, {node_id: r.node_id, transport: r.transport, outcome: r.outcome, rcode: r.rcode, count: r.count});
  }
  return [...map.values()].sort((a, b) => a.node_id.localeCompare(b.node_id) || b.count - a.count || a.outcome.localeCompare(b.outcome) || a.rcode - b.rcode);
}

/** The rcodes with a name (RFC 6895), for the label beside the number; any other is shown as its number alone. */
export const RCODE_NAMES: Readonly<Record<number, string>> = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"};
