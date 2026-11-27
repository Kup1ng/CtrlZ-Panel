import {infiniteQueryOptions, queryOptions, useInfiniteQuery, useMutation, useQuery, useQueryClient, type InfiniteData} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {pollEvery} from "../activity.ts";
import {shouldRetry} from "../queryDefaults.ts";
import type {LockPasswords} from "./lockPasswords.ts";
import {endpointKeys} from "./profileKeys.ts";
import {filterKey, isUuid, nextCursor, PAGE_LIMIT} from "./support.ts";

// Spec p3 9.2 and 10: the four lists that hang under one Endpoint: clients, DDNS hosts, authorized IPs and IP claims.

export type Client = components["schemas"]["Client"];
export type ClientPage = components["schemas"]["ClientPage"];
export type ClientCreate = components["schemas"]["ClientCreate"];
export type ClientPatch = components["schemas"]["ClientPatch"];
export type ClientBatch = components["schemas"]["ClientBatch"];
export type DdnsHost = components["schemas"]["DdnsHost"];
export type AuthorizedIP = components["schemas"]["AuthorizedIP"];
export type AuthorizedPage = components["schemas"]["AuthorizedPage"];
export type IPClaim = components["schemas"]["IPClaim"];
export type ClaimChallenge = components["schemas"]["ClaimChallenge"];
export type Challenge = components["schemas"]["Challenge"];
export type ClaimTake = components["schemas"]["ClaimTake"];

export type ClientFilter = {q?: string; group?: string; inactive_days?: number};

// ---- Clients ----

export const clientListQuery = (endpointId: string | undefined, filter: ClientFilter = {}) =>
  infiniteQueryOptions({
    queryKey: endpointKeys.clients(endpointId ?? "", filterKey(filter)),
    queryFn: async ({pageParam, signal}) =>
      required(
        await api.GET("/endpoints/{id}/clients", {
          params: {path: {id: endpointId!}, query: {...filter, ...(pageParam ? {cursor: pageParam} : {}), limit: PAGE_LIMIT}},
          signal,
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
    enabled: isUuid(endpointId),
    retry: shouldRetry,
  });

/** The clients of an Endpoint in a view, with `count`: how many match the filter (shown before "delete inactive", spec p3 9.3). */
export function useClients(endpointId: string | undefined, filter: ClientFilter = {}) {
  const query = useInfiniteQuery(clientListQuery(endpointId, filter));
  return {...query, clients: flattenClients(query.data), count: query.data?.pages[0]?.count};
}

export const flattenClients = (data: InfiniteData<ClientPage, unknown> | undefined): Client[] => data?.pages.flatMap((p) => p.items) ?? [];

function refreshClients(queryClient: ReturnType<typeof useQueryClient>, endpointId: string) {
  void queryClient.invalidateQueries({queryKey: endpointKeys.clientsOf(endpointId)});
  void queryClient.invalidateQueries({queryKey: endpointKeys.detail(endpointId)});
}

export function useCreateClient() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, ...body}: {endpointId: string} & ClientCreate) =>
      required(await api.POST("/endpoints/{id}/clients", {params: {path: {id: endpointId}}, body})),
    onSuccess: (_c, v) => refreshClients(queryClient, v.endpointId),
  });
}

export function usePatchClient() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, clientId, ...body}: {endpointId: string; clientId: string} & ClientPatch) =>
      required(await api.PATCH("/endpoints/{id}/clients/{cid}", {params: {path: {id: endpointId, cid: clientId}}, body})),
    onSuccess: (_c, v) => refreshClients(queryClient, v.endpointId),
  });
}

/**
 * `POST /endpoints/{id}/clients:batch`: edit or delete, by `ids` or by a `selector` (inactive for N days, or all). A selector is
 * applied to at most 500 clients: `more` says matches remain, and the screen repeats the call until it is false (spec p3 9.3).
 */
export function useBatchClients() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, ...body}: {endpointId: string} & ClientBatch) =>
      required(await api.POST("/endpoints/{id}/clients:batch", {params: {path: {id: endpointId}}, body})),
    onSuccess: (_r, v) => refreshClients(queryClient, v.endpointId),
  });
}

// ---- DDNS hosts ----

export const ddnsQuery = (endpointId: string | undefined) =>
  queryOptions({
    queryKey: endpointKeys.ddns(endpointId ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/endpoints/{id}/ddns-hosts", {params: {path: {id: endpointId!}}, signal})).hosts,
    enabled: isUuid(endpointId),
    retry: shouldRetry,
  });

export function useDdnsHosts(endpointId: string | undefined) {
  return useQuery(ddnsQuery(endpointId));
}

export function useCreateDdnsHost() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, hostname}: {endpointId: string; hostname: string}) =>
      required(await api.POST("/endpoints/{id}/ddns-hosts", {params: {path: {id: endpointId}}, body: {hostname}})),
    onSuccess: (_h, v) => void queryClient.invalidateQueries({queryKey: endpointKeys.ddns(v.endpointId)}),
  });
}

/** `POST .../ddns-hosts/{hid}:delete`. The last authorized address under Require is 422 `last_authorized`. */
export function useDeleteDdnsHost() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, hostId, lockPasswords}: {endpointId: string; hostId: string; lockPasswords?: LockPasswords}) => {
      await api.POST("/endpoints/{id}/ddns-hosts/{hid}:delete", {params: {path: {id: endpointId, hid: hostId}}, body: lockPasswords?.length ? {lock_passwords: lockPasswords} : {}});
    },
    onSuccess: (_x, v) => {
      void queryClient.invalidateQueries({queryKey: endpointKeys.ddns(v.endpointId)});
      void queryClient.invalidateQueries({queryKey: endpointKeys.authorizedOf(v.endpointId)});
    },
  });
}

// ---- Authorized IPs ----

export type AuthorizedFilter = {q?: string};

export const authorizedListQuery = (endpointId: string | undefined, filter: AuthorizedFilter = {}) =>
  infiniteQueryOptions({
    queryKey: endpointKeys.authorized(endpointId ?? "", filterKey(filter)),
    queryFn: async ({pageParam, signal}) =>
      required(
        await api.GET("/endpoints/{id}/authorized-ips", {
          params: {path: {id: endpointId!}, query: {...filter, ...(pageParam ? {cursor: pageParam} : {}), limit: PAGE_LIMIT}},
          signal,
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
    enabled: isUuid(endpointId),
    retry: shouldRetry,
  });

export function useAuthorizedIps(endpointId: string | undefined, filter: AuthorizedFilter = {}) {
  const query = useInfiniteQuery(authorizedListQuery(endpointId, filter));
  return {...query, rows: query.data?.pages.flatMap((p) => p.items) ?? []};
}

/** The current address and the last one under Require are marked by the server (`is_current`); their delete is disabled, and the API refuses it too. */
export function canDeleteAuthorized(row: Pick<AuthorizedIP, "is_current">, requireOn: boolean, total: number): boolean {
  return !row.is_current && !(requireOn && total <= 1);
}

export function useAddAuthorizedIps() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, cidrs}: {endpointId: string; cidrs: string[]}) =>
      required(await api.POST("/endpoints/{id}/authorized-ips", {params: {path: {id: endpointId}}, body: {cidrs}})).items,
    onSuccess: (_rows, v) => void queryClient.invalidateQueries({queryKey: endpointKeys.authorizedOf(v.endpointId)}),
  });
}

export function usePatchAuthorizedIp() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, ipId, cleanupOptIn, lockPasswords}: {endpointId: string; ipId: string; cleanupOptIn: boolean; lockPasswords?: LockPasswords}) =>
      required(
        await api.PATCH("/endpoints/{id}/authorized-ips/{aid}", {
          params: {path: {id: endpointId, aid: ipId}},
          body: lockPasswords?.length ? {cleanup_opt_in: cleanupOptIn, lock_passwords: lockPasswords} : {cleanup_opt_in: cleanupOptIn},
        }),
      ),
    onSuccess: (_row, v) => void queryClient.invalidateQueries({queryKey: endpointKeys.authorizedOf(v.endpointId)}),
  });
}

export function useDeleteAuthorizedIps() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, ids, lockPasswords}: {endpointId: string; ids: string[]; lockPasswords?: LockPasswords}) => {
      await api.POST("/endpoints/{id}/authorized-ips:delete", {params: {path: {id: endpointId}}, body: lockPasswords?.length ? {ids, lock_passwords: lockPasswords} : {ids}});
    },
    onSuccess: (_x, v) => void queryClient.invalidateQueries({queryKey: endpointKeys.authorizedOf(v.endpointId)}),
  });
}

// ---- IP claims ----

/** Claims move on their own (the sweep, a proof arriving), so the list is read again every 10 seconds while a person is at it and a claim waits. */
export const CLAIM_POLL_MS = 10_000;

export const claimsQuery = (endpointId: string | undefined) =>
  queryOptions({
    queryKey: endpointKeys.claims(endpointId ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/endpoints/{id}/ip-claims", {params: {path: {id: endpointId!}}, signal})).claims,
    enabled: isUuid(endpointId),
    retry: shouldRetry,
    refetchInterval: (query) => (query.state.data?.some((c) => c.state === "pending_proof" || c.challenge) ? pollEvery(CLAIM_POLL_MS)() : false),
  });

export function useIpClaims(endpointId: string | undefined) {
  return useQuery(claimsQuery(endpointId));
}

/** A claim waiting for proof, or in its grace: the rows the IPs page marks (T-262, T-267). */
export const isClaimWaiting = (claim: Pick<IPClaim, "state">): boolean => claim.state === "pending_proof" || claim.state === "grace";

function refreshClaims(queryClient: ReturnType<typeof useQueryClient>, endpointId: string) {
  void queryClient.invalidateQueries({queryKey: endpointKeys.claims(endpointId)});
  void queryClient.invalidateQueries({queryKey: endpointKeys.detail(endpointId)});
}

/** `POST .../ip-claims`: a prefix, or `use_my_address` for the address of this browser. 30 an hour per tenant. */
export function useRequestIpClaim() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, ...body}: {endpointId: string; cidr?: string; useMyAddress?: boolean}) =>
      required(await api.POST("/endpoints/{id}/ip-claims", {params: {path: {id: endpointId}}, body: body.cidr ? {cidr: body.cidr} : {use_my_address: body.useMyAddress ?? true}})),
    onSuccess: (_c, v) => refreshClaims(queryClient, v.endpointId),
  });
}

/** Opens the proof: a label the person resolves from the network being claimed (`Challenge.commands` holds the pair and the host to query). */
export function useOpenClaimChallenge() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, claimId}: {endpointId: string; claimId: string}) =>
      required(await api.POST("/endpoints/{id}/ip-claims/{claim_id}/challenges", {params: {path: {id: endpointId, claim_id: claimId}}})),
    onSuccess: (_c, v) => refreshClaims(queryClient, v.endpointId),
  });
}

/** `:take`: `outcome` is `active`, `already_active` or `no_proof`. `code` is the UDP code, held in the proof dialog's state only. */
export function useTakeIpClaim() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, claimId, code}: {endpointId: string; claimId: string; code?: string}) =>
      required(await api.POST("/endpoints/{id}/ip-claims/{claim_id}:take", {params: {path: {id: endpointId, claim_id: claimId}}, body: code ? {code} : {}})),
    onSuccess: (_r, v) => refreshClaims(queryClient, v.endpointId),
  });
}

export function useReleaseIpClaim() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, claimId, lockPasswords}: {endpointId: string; claimId: string; lockPasswords?: LockPasswords}) => {
      await api.POST("/endpoints/{id}/ip-claims/{claim_id}:release", {
        params: {path: {id: endpointId, claim_id: claimId}},
        body: lockPasswords?.length ? {lock_passwords: lockPasswords} : {},
      });
    },
    onSuccess: (_x, v) => refreshClaims(queryClient, v.endpointId),
  });
}
