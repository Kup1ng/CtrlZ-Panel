import {infiniteQueryOptions, queryOptions, useInfiniteQuery, useMutation, useQuery, useQueryClient, type InfiniteData} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import {isApiError} from "../errors.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import type {LockPasswords} from "./lockPasswords.ts";
import {optimistic} from "./optimistic.ts";
import {catalogKeys, endpointKeys, profileKeys} from "./profileKeys.ts";
import {filterKey, isUuid, newIdempotencyKey, nextCursor, PAGE_LIMIT} from "./support.ts";

// Spec p3 9.2 and 10. Endpoints: the cursor-paged list with its type and status counts, one Endpoint, create (several names at once),
// edit, batch, delete, rotate, the schedule, groups, and the lists a form needs (types, time zones).
//
// A change that takes a locked profile away from an identity carries `lock_passwords` (lockPasswords.ts). The Endpoint's own writes
// never touch a profile's content, so none of them is a guarded write of P2 and none notes a locked profile.

export type Endpoint = components["schemas"]["Endpoint"];
export type EndpointPage = components["schemas"]["EndpointPage"];
export type EndpointType = components["schemas"]["EndpointType"];
export type EndpointCreate = components["schemas"]["EndpointCreate"];
export type EndpointPatch = components["schemas"]["EndpointPatch"];
export type EndpointBatch = components["schemas"]["EndpointBatch"];
export type Schedule = components["schemas"]["Schedule"];
export type SchedulePut = components["schemas"]["SchedulePut"];
export type ScheduleWindow = components["schemas"]["ScheduleWindow"];
export type Group = components["schemas"]["Group"];
export type AnalyticsLevel = NonNullable<Endpoint["analytics_level"]>;
export type AdminState = Endpoint["admin_state"];

export type EndpointFilter = {
  group?: string;
  type?: string;
  status?: "pending" | "active";
  q?: string;
  sort?: "created" | "name";
};

export const endpointTypesQueryOptions = () =>
  queryOptions({
    queryKey: catalogKeys.endpointTypes,
    queryFn: async ({signal}) => required(await api.GET("/endpoint-types", {signal})).types,
    staleTime: 10 * 60_000,
    retry: shouldRetry,
  });

/** The 30 types of Endpoint, in the order of the catalogue (`position`). */
export function useEndpointTypes() {
  return useQuery(endpointTypesQueryOptions());
}

export const timezonesQueryOptions = () =>
  queryOptions({
    queryKey: catalogKeys.timezones,
    queryFn: async ({signal}) => required(await api.GET("/catalog/timezones", {signal})).zones,
    staleTime: 60 * 60_000,
    retry: shouldRetry,
  });

export function useTimezones() {
  return useQuery(timezonesQueryOptions());
}

export const endpointListQuery = (filter: EndpointFilter = {}) =>
  infiniteQueryOptions({
    queryKey: endpointKeys.list(filterKey(filter)),
    queryFn: async ({pageParam, signal}) =>
      required(await api.GET("/endpoints", {params: {query: {...filter, ...(pageParam ? {cursor: pageParam} : {}), limit: PAGE_LIMIT}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
    retry: shouldRetry,
  });

/** The Endpoints in a view. `byType` and `byStatus` are the chip counts: they come with every page and the first is read. */
export function useEndpoints(filter: EndpointFilter = {}, options: {enabled?: boolean} = {}) {
  const query = useInfiniteQuery({...endpointListQuery(filter), enabled: options.enabled ?? true});
  const first = query.data?.pages[0];
  return {...query, endpoints: flattenEndpoints(query.data), byType: first?.by_type, byStatus: first?.by_status};
}

export const endpointCountQueryOptions = () =>
  queryOptions({
    queryKey: endpointKeys.count,
    queryFn: async ({signal}) => {
      const page = required(await api.GET("/endpoints", {params: {query: {limit: 1}}, signal}));
      return {total: page.by_status.pending + page.by_status.active, pending: page.by_status.pending, active: page.by_status.active};
    },
    retry: shouldRetry,
  });

/** How many Endpoints the tenant has and how many of them are configured, for the sidebar and the first-run checklist (T-113, T-119). One row is read. */
export function useEndpointCount(options: {enabled?: boolean} = {}) {
  return useQuery({...endpointCountQueryOptions(), enabled: options.enabled ?? true});
}

export const flattenEndpoints = (data: InfiniteData<EndpointPage, unknown> | undefined): Endpoint[] => data?.pages.flatMap((p) => p.items) ?? [];

export const endpointDetailQuery = (id: string | undefined) =>
  queryOptions({
    queryKey: endpointKeys.detail(id ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/endpoints/{id}", {params: {path: {id: id!}}, signal})),
    enabled: isUuid(id),
    retry: shouldRetry,
  });

/** One Endpoint. `enabled` is false for a path that is not a UUID, and the frame shows its 404. */
export function useEndpoint(id: string | undefined) {
  return useQuery(endpointDetailQuery(id));
}

/** Puts a changed Endpoint into its detail cache and into every cached list page that holds it. */
export function putEndpoint(queryClient: ReturnType<typeof useQueryClient>, endpoint: Endpoint): void {
  queryClient.setQueryData(endpointKeys.detail(endpoint.id), endpoint);
  queryClient.setQueriesData<InfiniteData<EndpointPage, unknown>>({queryKey: endpointKeys.lists}, (data) =>
    data ? {...data, pages: data.pages.map((p) => ({...p, items: p.items.map((e) => (e.id === endpoint.id ? endpoint : e))}))} : data,
  );
}

/**
 * `POST /endpoints`: one request creates up to 50 Endpoints (`names`). Needs an `Idempotency-Key`, one for the action. The Resolvers
 * dialog opens by itself for the first one created (WF), so the answer is the screen's to read. `destinations_lost` (409) is asked
 * again with `confirm_destinations`.
 */
export function useCreateEndpoints() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({key, ...body}: {key?: string} & EndpointCreate) =>
      required(await api.POST("/endpoints", {params: {header: {"Idempotency-Key": key ?? newIdempotencyKey()}}, body})).endpoints,
    onSuccess: () => {
      void queryClient.invalidateQueries({queryKey: endpointKeys.all});
      void queryClient.invalidateQueries({queryKey: profileKeys.list});
    },
  });
}

/**
 * What setup shows is built from the Endpoint: the Resolver view and the generators' text (the DoH token, the addresses, legacy DNS and
 * secure DNS). A change of the Endpoint makes them stale, and a rotation makes the old text WRONG, not only old: a Copy button must never
 * hand out the dead token from a cache, so after a rotation they are reset, which empties them and asks again at once if a screen shows them (`drop`). With no `id` it is
 * every Endpoint's (a batch edit).
 */
export function resetSetupCaches(queryClient: ReturnType<typeof useQueryClient>, id: string | undefined, drop = false): void {
  for (const queryKey of [endpointKeys.resolversOf(id), endpointKeys.generatorsOf(id)]) {
    if (drop) void queryClient.resetQueries({queryKey});
    else void queryClient.invalidateQueries({queryKey});
  }
}

/** `PATCH /endpoints/{id}`. A field in `clear` is unset. */
export function usePatchEndpoint() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({id, ...body}: {id: string} & EndpointPatch) => required(await api.PATCH("/endpoints/{id}", {params: {path: {id}}, body})),
    onSuccess: (endpoint) => {
      putEndpoint(queryClient, endpoint);
      resetSetupCaches(queryClient, endpoint.id);
      void queryClient.invalidateQueries({queryKey: endpointKeys.lists});
      void queryClient.invalidateQueries({queryKey: profileKeys.list});
    },
  });
}

/** `POST /endpoints:batch`: Move, Edit and Delete of a selection (at most 500 ids). */
export function useBatchEndpoints() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: EndpointBatch) => required(await api.POST("/endpoints:batch", {body})),
    onSuccess: () => {
      resetSetupCaches(queryClient, undefined);
      void queryClient.invalidateQueries({queryKey: endpointKeys.all});
      void queryClient.invalidateQueries({queryKey: profileKeys.list});
    },
  });
}

/** `POST /endpoints/{id}:delete`. A held Endpoint is 409 `endpoint_held`; a locked profile it leaves needs its password. */
export function useDeleteEndpoint() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({id, lockPasswords}: {id: string; lockPasswords?: LockPasswords}) => {
      await api.POST("/endpoints/{id}:delete", {params: {path: {id}}, body: lockPasswords?.length ? {lock_passwords: lockPasswords} : {}});
      return id;
    },
    onSuccess: (id) => {
      queryClient.removeQueries({queryKey: endpointKeys.detail(id)});
      void queryClient.invalidateQueries({queryKey: endpointKeys.all});
      void queryClient.invalidateQueries({queryKey: profileKeys.list});
    },
  });
}

/** `POST /endpoints/{id}:rotate-resolver`: a new resolver id and DoH token; every device must be set up again and every link ends. */
export function useRotateResolver() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({id, lockPasswords}: {id: string; lockPasswords?: LockPasswords}) =>
      required(await api.POST("/endpoints/{id}:rotate-resolver", {params: {path: {id}}, body: lockPasswords?.length ? {lock_passwords: lockPasswords} : {}})),
    onSuccess: (endpoint) => {
      putEndpoint(queryClient, endpoint);
      resetSetupCaches(queryClient, endpoint.id, true);
      void queryClient.invalidateQueries({queryKey: endpointKeys.shareLinks(endpoint.id)});
    },
    // The server may have rotated and the answer been lost (a dropped connection, a timeout, a 5xx from a proxy after the commit). Then the
    // caches still hold the dead resolver id and DoH token, and a Copy button would hand them out (S5-r2-10).
    onError: (error, {id}) => afterRotateFailure(queryClient, id, error),
  });
}

/** Whether a failed rotation may still have happened: anything but a definite refusal (a 4xx other than 408). */
export function afterRotateFailure(queryClient: ReturnType<typeof useQueryClient>, id: string, error: unknown): boolean {
  if (isApiError(error) && error.status >= 400 && error.status < 500 && error.status !== 408) return false;
  resetSetupCaches(queryClient, id, true);
  void queryClient.invalidateQueries({queryKey: endpointKeys.detail(id)});
  void queryClient.invalidateQueries({queryKey: endpointKeys.lists});
  void queryClient.invalidateQueries({queryKey: endpointKeys.shareLinks(id)});
  return true;
}

/** `GET /endpoints/export`: the CSV of the list, as text. The browser saves it. Never holds the DoH token (spec p3 9.3). */
export async function fetchEndpointsCsv(): Promise<string> {
  const result = (await api.GET("/endpoints/export", {parseAs: "text"})) as unknown as {data?: string};
  return required(result);
}

export const scheduleQuery = (id: string | undefined) =>
  queryOptions({
    queryKey: endpointKeys.schedule(id ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/endpoints/{id}/schedule", {params: {path: {id: id!}}, signal})),
    enabled: isUuid(id),
    retry: shouldRetry,
  });

export function useSchedule(id: string | undefined) {
  return useQuery(scheduleQuery(id));
}

/** `PUT /endpoints/{id}/schedule`: replaces the whole set of windows. Copy day and Clear all are PUTs too. */
export function usePutSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({id, ...body}: {id: string} & SchedulePut) => required(await api.PUT("/endpoints/{id}/schedule", {params: {path: {id}}, body})),
    onSuccess: (schedule, v) => {
      queryClient.setQueryData(endpointKeys.schedule(v.id), schedule);
      void queryClient.invalidateQueries({queryKey: endpointKeys.detail(v.id)});
      void queryClient.invalidateQueries({queryKey: endpointKeys.lists});
    },
  });
}

export const groupsQueryOptions = () =>
  queryOptions({
    queryKey: endpointKeys.groups,
    queryFn: async ({signal}) => required(await api.GET("/endpoint-groups", {signal})).groups,
    retry: shouldRetry,
  });

export function useGroups() {
  return useQuery(groupsQueryOptions());
}

export function useCreateGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: {name: string; endpoint_ids?: string[]}) => required(await api.POST("/endpoint-groups", {body})),
    onSuccess: () => {
      void queryClient.invalidateQueries({queryKey: endpointKeys.groups});
      void queryClient.invalidateQueries({queryKey: endpointKeys.lists});
    },
  });
}

export function useRenameGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({gid, name}: {gid: string; name: string}) => required(await api.PATCH("/endpoint-groups/{gid}", {params: {path: {gid}}, body: {name}})),
    ...optimistic<{gid: string; name: string}>({
      queryClient,
      keys: [endpointKeys.groups],
      apply: (groups, v) => (groups as Group[]).map((g) => (g.id === v.gid ? {...g, name: v.name} : g)),
    }),
  });
}

/** `DELETE /endpoint-groups/{gid}`: the group goes and its Endpoints stay, without a group. */
export function useDeleteGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (gid: string) => {
      await api.DELETE("/endpoint-groups/{gid}", {params: {path: {gid}}});
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({queryKey: endpointKeys.groups});
      void queryClient.invalidateQueries({queryKey: endpointKeys.lists});
    },
  });
}

/**
 * The state of the Endpoint switch of the list row (enabled or soft disabled), shown at once. Hard disabled is a heavier state
 * and goes through the edit dialog with its confirmation.
 */
export function useSetEndpointState() {
  const queryClient = useQueryClient();
  type Vars = {id: string; state: AdminState; lockPasswords?: LockPasswords};
  const change = (e: Endpoint, state: AdminState): Endpoint => ({...e, admin_state: state});
  return useMutation({
    mutationFn: async ({id, state, lockPasswords}: Vars) =>
      required(await api.PATCH("/endpoints/{id}", {params: {path: {id}}, body: lockPasswords?.length ? {admin_state: state, lock_passwords: lockPasswords} : {admin_state: state}})),
    ...optimistic<Vars>({
      queryClient,
      keys: (v) => [endpointKeys.detail(v.id), endpointKeys.lists],
      apply: (data, v) => {
        if (data !== null && typeof data === "object" && "pages" in data) {
          const infinite = data as InfiniteData<EndpointPage, unknown>;
          return {...infinite, pages: infinite.pages.map((p) => ({...p, items: p.items.map((e) => (e.id === v.id ? change(e, v.state) : e))}))};
        }
        const one = data as Endpoint;
        return one.id === v.id ? change(one, v.state) : undefined;
      },
    }),
  });
}
