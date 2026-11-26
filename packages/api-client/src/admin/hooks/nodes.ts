import {infiniteQueryOptions, queryOptions, useInfiniteQuery, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {pollEvery} from "../../activity.ts";
import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";
import {pairKeys} from "./pairs.ts";

// P4, p4-nodes 9.2 and 10.1. The nodes, the overview, the addresses a node gave up, the claims a revoked node's reports hold, and
// the enrolments. Every write is `admin-fresh` (the fresh TOTP window), so a screen calls them through `useCheckedWrite().send`.
//
// What a NodeView holds is what the database holds, and since T-542 what the hub wrote of a node's return and drain (`f3_unmet`, `drain_state`,
// with `f3_due_at` and `drain_since`: migration 0103, p4-nodes 5.6 and 9.2). A revocation still pending stays in the hub's memory and is not
// in the document. `HubParts` names each as optional, so a screen says "not reported yet" for a node the hub has written nothing for; the
// contract test of this file fails if the document gains such a field under a name this reader does not know.

type S = components["schemas"];
export type NodeView = S["NodeView"];
export type NodeStatus = NodeView["status"];
export type Overview = S["Overview"];
export type AddressGivenUp = S["AddressGivenUp"];
export type NodeReports = S["NodeReports"];
export type NodeEnrollmentRow = S["NodeEnrollmentRow"];
export type NodeEnrollmentState = NodeEnrollmentRow["state"];
export type CreateNodeEnrollmentRequest = S["CreateNodeEnrollmentRequest"];
export type NodeEnrollmentCreated = S["NodeEnrollmentCreated"];
export type ConfirmNodeEnrollmentRequest = S["ConfirmNodeEnrollmentRequest"];
export type PatchNodeRequest = S["PatchNodeRequest"];
export type NodeAddressesRequest = S["NodeAddressesRequest"];
export type NodeDnsRequestKind = S["NodeDnsRequestBody"]["kind"];

/**
 * The fields of a node that only the hub knows, as p4-nodes 5.3 to 5.6 describe them. The hub writes `f3_unmet` and `drain_state` (9.2
 * NodeView) and keeps `revocation_pending` in memory only, so each is optional and read defensively: `hubParts(node)` returns what is
 * there. A field the document later gives under another name is a change here and nowhere else.
 */
export type HubParts = {
  /** The F3 conditions not yet met, by name. */
  f3_unmet?: string[];
  /** "serving", "draining" and so on: the drain state of 8a.6. */
  drain_state?: string;
  /** A revocation the hub has not yet carried out on this node. */
  revocation_pending?: boolean;
  /** The hub's own verdict on the node. */
  health?: "healthy" | "degraded" | "down";
};
export type NodeWithHubParts = NodeView & HubParts;

/**
 * The names of the unmet conditions, or undefined when the field is not a list the page can read. Only strings are names, each once: a hub
 * that sends objects or repeats a name must not crash the page or give React a duplicate key (PG-r3-5). An empty list means every condition
 * is met; a list with entries and none of them a string is a field this page cannot read, so it is "not reported yet".
 */
function unmetNames(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const names = [...new Set(value.filter((s): s is string => typeof s === "string" && s !== ""))];
  return names.length === 0 && value.length > 0 ? undefined : names;
}

export function hubParts(node: NodeView): HubParts {
  const n = node as NodeWithHubParts;
  const unmet = unmetNames(n.f3_unmet);
  return {
    ...(unmet !== undefined ? {f3_unmet: unmet} : {}),
    ...(typeof n.drain_state === "string" ? {drain_state: n.drain_state} : {}),
    ...(typeof n.revocation_pending === "boolean" ? {revocation_pending: n.revocation_pending} : {}),
    ...(n.health === "healthy" || n.health === "degraded" || n.health === "down" ? {health: n.health} : {}),
  };
}

/** The most nodes a deployment has (D25). */
export const NODE_LIMIT = 4;
/** The panel asks for the nodes and the overview again this often while a person is at the page (the alerts do the same, 13.6). */
export const NODES_POLL_MS = 30_000;
/** The enrolments are asked for more often: an admin waits at the page for the host to call in. */
export const ENROLLMENTS_POLL_MS = 10_000;

export const nodeKeys = {
  all: ["admin", "nodes"] as const,
  list: ["admin", "nodes", "list"] as const,
  one: (id: string) => ["admin", "nodes", "one", id] as const,
  givenUp: ["admin", "nodes", "given-up"] as const,
  reports: (id: string, from: string) => ["admin", "nodes", "reports", id, from] as const,
  enrollments: ["admin", "nodes", "enrollments"] as const,
  overview: ["admin", "overview"] as const,
};

export const nodesQueryOptions = () =>
  infiniteQueryOptions({
    queryKey: nodeKeys.list,
    queryFn: async ({pageParam, signal}) => required(await adminApi.GET("/nodes", {params: {query: {cursor: pageParam, limit: 50}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    refetchInterval: pollEvery(NODES_POLL_MS),
    retry: shouldRetry,
  });
export const useNodes = () => useInfiniteQuery(nodesQueryOptions());

export const nodeQueryOptions = (id: string) =>
  queryOptions({
    queryKey: nodeKeys.one(id),
    queryFn: async ({signal}) => required(await adminApi.GET("/nodes/{id}", {params: {path: {id}}, signal})),
    refetchInterval: pollEvery(NODES_POLL_MS),
    retry: shouldRetry,
  });
export const useNode = (id: string) => useQuery(nodeQueryOptions(id));

export const overviewQueryOptions = () =>
  queryOptions({
    queryKey: nodeKeys.overview,
    queryFn: async ({signal}) => required(await adminApi.GET("/overview", {signal})),
    refetchInterval: pollEvery(NODES_POLL_MS),
    retry: shouldRetry,
  });
export const useOverview = () => useQuery(overviewQueryOptions());

export const givenUpQueryOptions = () =>
  queryOptions({
    queryKey: nodeKeys.givenUp,
    queryFn: async ({signal}) => required(await adminApi.GET("/nodes/addresses-given-up", {signal})).items,
    retry: shouldRetry,
  });
export const useAddressesGivenUp = () => useQuery(givenUpQueryOptions());

/** The claims a node's reports hold come 200 at a time, newest first. */
export const REPORTS_PAGE = 200;

/**
 * The claims taken on a node's proof observations since `from` (4.5), for the page of a revoked node. The route walks back by the
 * `consumed_at` of the last claim sent as `to`, and reads that instant again, so a claim may come twice: `reportClaims` drops the
 * repeats. The kept rows of the first page are the whole list the job left (the later pages repeat it), so a screen reads them from the first.
 */
export function useNodeReports(id: string, from: string, enabled = true) {
  return useInfiniteQuery({
    queryKey: nodeKeys.reports(id, from),
    queryFn: async ({pageParam, signal}) =>
      required(await adminApi.GET("/nodes/{id}/reports", {params: {path: {id}, query: {from, ...(pageParam ? {to: pageParam} : {})}}, signal})),
    initialPageParam: undefined as string | undefined,
    // The cursor is an instant, and the route reads that instant again (inclusive). When more claims than one page share it, the next page is
    // the same rows and the list would never move: the walk stops there and the page says so (`reportsStalled`, PG-r1-15).
    getNextPageParam: (last, all) => (last.claims_truncated && last.claims.length > 0 && !reportsStalled(all) ? last.claims[last.claims.length - 1]!.consumed_at : undefined),
    enabled,
    retry: shouldRetry,
  });
}

/**
 * True when the last page loaded added no claim the pages before it did not hold, though the route says more exist: more than one page of
 * claims share one `consumed_at`, and the cursor cannot get past them. The contract needs a compound cursor (consumed_at, claim_id) for that.
 */
export function reportsStalled(pages: readonly NodeReports[]): boolean {
  const last = pages.length > 1 ? pages[pages.length - 1] : undefined;
  if (!last || !last.claims_truncated) return false;
  const before = new Set(pages.slice(0, -1).flatMap((p) => p.claims.map((c) => c.claim_id)));
  return last.claims.every((c) => before.has(c.claim_id));
}

/** Every claim of the pages loaded so far, each once. */
export function reportClaims(pages: readonly NodeReports[]): NodeReports["claims"] {
  const seen = new Set<string>();
  return pages.flatMap((p) => p.claims).filter((c) => (seen.has(c.claim_id) ? false : (seen.add(c.claim_id), true)));
}

export const enrollmentsQueryOptions = () =>
  infiniteQueryOptions({
    queryKey: nodeKeys.enrollments,
    queryFn: async ({pageParam, signal}) => required(await adminApi.GET("/node-enrollments", {params: {query: {cursor: pageParam, limit: 50}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    // A host that enrols during the fifteen minutes shows up here without a reload.
    refetchInterval: pollEvery(ENROLLMENTS_POLL_MS),
    retry: shouldRetry,
  });
export const useEnrollments = () => useInfiniteQuery(enrollmentsQueryOptions());

/** Every change of a node moves the overview, the pairs and the list of addresses given up as well. */
function useInvalidateNodes() {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({queryKey: nodeKeys.all}),
      queryClient.invalidateQueries({queryKey: nodeKeys.overview}),
      queryClient.invalidateQueries({queryKey: pairKeys.all}),
    ]);
}

/** The answer holds the install command, shown once: a screen keeps it in state and never puts it in a query or a key. */
export function useCreateEnrollment() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: CreateNodeEnrollmentRequest) => required(await adminApi.POST("/node-enrollments", {body})),
    onSuccess: () => {
      void queryClient.invalidateQueries({queryKey: nodeKeys.enrollments});
    },
  });
}

export function useConfirmEnrollment() {
  const invalidate = useInvalidateNodes();
  return useMutation({
    mutationFn: async ({id, ...body}: ConfirmNodeEnrollmentRequest & {id: string}) =>
      required(await adminApi.POST("/node-enrollments/{id}:confirm", {params: {path: {id}}, body})),
    onSettled: invalidate,
  });
}

export function useRejectEnrollment() {
  const invalidate = useInvalidateNodes();
  return useMutation({
    mutationFn: async (id: string) => {
      await adminApi.POST("/node-enrollments/{id}:reject", {params: {path: {id}}});
    },
    onSettled: invalidate,
  });
}

export function useApproveNode() {
  const invalidate = useInvalidateNodes();
  return useMutation({
    mutationFn: async (id: string) => required(await adminApi.POST("/nodes/{id}:approve", {params: {path: {id}}})),
    onSettled: invalidate,
  });
}

export function useRevokeNode() {
  const invalidate = useInvalidateNodes();
  return useMutation({
    mutationFn: async (id: string) => required(await adminApi.POST("/nodes/{id}:revoke", {params: {path: {id}}})),
    onSettled: invalidate,
  });
}

export function useRemoveNode() {
  const invalidate = useInvalidateNodes();
  return useMutation({
    mutationFn: async (id: string) => {
      await adminApi.DELETE("/nodes/{id}", {params: {path: {id}}});
    },
    onSettled: invalidate,
  });
}

export function usePatchNode() {
  const invalidate = useInvalidateNodes();
  return useMutation({
    mutationFn: async ({id, ...body}: PatchNodeRequest & {id: string}) => required(await adminApi.PATCH("/nodes/{id}", {params: {path: {id}}, body})),
    onSettled: invalidate,
  });
}

export function usePutNodeAddresses() {
  const invalidate = useInvalidateNodes();
  return useMutation({
    mutationFn: async ({id, ...body}: NodeAddressesRequest & {id: string}) => required(await adminApi.PUT("/nodes/{id}/addresses", {params: {path: {id}}, body})),
    onSettled: invalidate,
  });
}

export function useNodeDnsRequest() {
  const invalidate = useInvalidateNodes();
  return useMutation({
    mutationFn: async ({id, kind}: {id: string; kind: NodeDnsRequestKind}) =>
      required(await adminApi.POST("/nodes/{id}/dns-requests", {params: {path: {id}}, body: {kind}})),
    onSettled: invalidate,
  });
}

// ---- Reading a node as the screens do ---------------------------------------------------------------------------------------------

/** How long without a Heartbeat before a node reads as out of touch. The hub waits 60 s between Heartbeats (5.2), so two missed ones. */
export const STALE_AFTER_MS = 150_000;

export type ContactState = "never" | "recent" | "stale";

/** `never` for a node that has sent no Heartbeat, `stale` past two missed ones. A clock that is wrong reads as `recent`, never as a fault. */
export function contactState(node: Pick<NodeView, "last_heartbeat_at">, now: number = Date.now()): ContactState {
  if (!node.last_heartbeat_at) return "never";
  const age = now - Date.parse(node.last_heartbeat_at);
  return Number.isNaN(age) || age < STALE_AFTER_MS ? "recent" : "stale";
}

export type NodeHealth = "serving" | "held" | "withdrawn" | "out_of_touch" | "no_contact" | "isolated" | "pending" | "revoked";

/**
 * One word for a row, from what the database holds. Order matters: a revoked or pending node is that and nothing else; then the contact;
 * then the hub's failover flags. `isolated` is the node's own report (it serves under Isolated mode). A hub verdict, when there is one,
 * is shown beside this word and does not replace it.
 */
export function nodeHealth(node: NodeView, now: number = Date.now()): NodeHealth {
  if (node.status === "revoked") return "revoked";
  if (node.status === "pending") return "pending";
  const contact = contactState(node, now);
  if (contact === "never") return "no_contact";
  if (contact === "stale") return "out_of_touch";
  if (node.isolated) return "isolated";
  if (node.dns_hold) return "held";
  if (node.dns_withdrawn) return "withdrawn";
  return "serving";
}

/** Cache hit rate as a percentage with one decimal, from parts per thousand. */
export const permilleToPercent = (permille: number): number => Math.round(permille) / 10;
