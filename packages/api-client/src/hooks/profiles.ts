import {queryOptions, useMutation, useQuery, useQueryClient, type QueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import {sessionGuard} from "../sessionEnd.ts";
import {noteLockedProfile, optimistic} from "./optimistic.ts";
import {profileKeys} from "./profileKeys.ts";
import {isUuid, jobOr, newIdempotencyKey, type JobOr} from "./support.ts";

// Spec p2 8.2 (profiles), 9.1 to 9.3. The list, one profile, and the writes of the header: create, import, duplicate, rename,
// delete, disable, lock, unlock, export, and the locations a profile may redirect to.
//
// `Profile` is the row of the list and the whole of one profile (the list carries `lock_message` too), so one write changes both
// caches. A new profile is placed first with a highlight until the next load (T-136): `useCreateProfile` hands the screen the
// profile and it puts the id in its own state.

export type Profile = components["schemas"]["Profile"];
export type ProfileKind = Profile["kind"];
export type ProfileCreated = components["schemas"]["ProfileCreated"];
export type ProfileDocument = components["schemas"]["ProfileDocument"];
export type LocationSet = components["schemas"]["LocationSet"];
export type LocationRef = components["schemas"]["LocationRef"];

/** The seven kinds a person picks when creating a profile, in the order of the cards (spec p2 5). */
export const PROFILE_KINDS = ["custom", "developer", "gaming", "kids", "privacy", "productivity", "vpn_replacement"] as const satisfies readonly ProfileKind[];

export const profileListQueryOptions = () =>
  queryOptions({
    queryKey: profileKeys.list,
    queryFn: async ({signal}) => required(await api.GET("/profiles", {signal})).items,
    retry: shouldRetry,
  });

/** Every profile of the tenant. A tenant holds few, so the list is not paged (spec p2 9.1). */
export function useProfiles(options: {enabled?: boolean} = {}) {
  return useQuery({...profileListQueryOptions(), enabled: options.enabled ?? true});
}

export const profileDetailQuery = (id: string | undefined) =>
  queryOptions({
    queryKey: profileKeys.detail(id ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/profiles/{id}", {params: {path: {id: id!}}, signal})),
    // A path that is not an id is a page that does not exist: no request carries it (support.ts, isUuid).
    enabled: isUuid(id),
    retry: shouldRetry,
  });

/** One profile. `enabled` is false for a path that is not a UUID, and the frame shows its 404. */
export function useProfile(id: string | undefined) {
  return useQuery(profileDetailQuery(id));
}

/**
 * Puts a changed profile into the list and the detail caches, so no screen waits for a refetch to show it. A profile the list does not
 * hold is added only when `add` says it is new (a create, an import, a duplicate): an answer for one that is not there (a write of
 * another session that answered late, S2-r2-7) must not put a stranger's profile into this list.
 */
export function putProfile(queryClient: QueryClient, profile: Profile, options: {add?: boolean} = {}): void {
  queryClient.setQueryData(profileKeys.detail(profile.id), profile);
  queryClient.setQueryData<Profile[]>(profileKeys.list, (list) => {
    if (!list) return list;
    if (list.some((p) => p.id === profile.id)) return list.map((p) => (p.id === profile.id ? profile : p));
    return options.add ? [profile, ...list] : list;
  });
}

/**
 * The cache of a session that has ended is not written by an answer that was still on its way (S2-r2-7): `queryClient.clear()` does not
 * stop a mutation in flight, and its callbacks would put the old person's profile into the next person's list. The guard is taken when
 * the write starts and asked when it answers. Create, import and duplicate take it too, because they are the ones that ADD a profile to the
 * list (S2-r3-6); each write has an options factory so a test can run it without React.
 */
const startedIn = () => ({alive: sessionGuard()});
type Started = {alive: () => boolean} | undefined;

/** `POST /profiles`. The kind is one of the seven cards; `flagged` above 0 means destinations that act as Bypass until they return. */
export const createProfileOptions = (queryClient: QueryClient) => ({
  mutationFn: async (body: {name: string; kind: ProfileKind}) => required(await api.POST("/profiles", {body})),
  onMutate: startedIn,
  onSuccess: (created: ProfileCreated, _body: {name: string; kind: ProfileKind}, context: Started) => {
    if (!context?.alive()) return;
    putProfile(queryClient, created.profile, {add: true});
    void queryClient.invalidateQueries({queryKey: profileKeys.all});
  },
});

export function useCreateProfile() {
  return useMutation(createProfileOptions(useQueryClient()));
}

/** `POST /profiles:import`. `document` is the file as base64; above 1,000 rules the answer is a job. */
export const importProfileOptions = (queryClient: QueryClient) => ({
  mutationFn: async ({document, key}: {document: string; key?: string}): Promise<JobOr<ProfileCreated>> =>
    jobOr(await api.POST("/profiles:import", {params: {header: {"Idempotency-Key": key ?? newIdempotencyKey()}}, body: {document}})),
  onMutate: startedIn,
  onSuccess: (result: JobOr<ProfileCreated>, _vars: {document: string; key?: string}, context: Started) => {
    if (!context?.alive()) return;
    if (result.kind === "done") putProfile(queryClient, result.data.profile, {add: true});
    void queryClient.invalidateQueries({queryKey: profileKeys.all});
  },
});

export function useImportProfile() {
  return useMutation(importProfileOptions(useQueryClient()));
}

/** `POST /profiles/{id}:duplicate`. Reading a locked profile is allowed, so a locked profile can be duplicated. */
export const duplicateProfileOptions = (queryClient: QueryClient) => ({
  mutationFn: async ({id, name, key}: {id: string; name: string; key?: string}): Promise<JobOr<ProfileCreated>> =>
    jobOr(
      await api.POST("/profiles/{id}:duplicate", {
        params: {path: {id}, header: {"Idempotency-Key": key ?? newIdempotencyKey()}},
        body: {name},
      }),
    ),
  onMutate: startedIn,
  onSuccess: (result: JobOr<ProfileCreated>, _vars: {id: string; name: string; key?: string}, context: Started) => {
    if (!context?.alive()) return;
    if (result.kind === "done") putProfile(queryClient, result.data.profile, {add: true});
    void queryClient.invalidateQueries({queryKey: profileKeys.all});
  },
});

export function useDuplicateProfile() {
  return useMutation(duplicateProfileOptions(useQueryClient()));
}

/** `PATCH /profiles/{id}`, the name. Shown at once and put back on a refusal. */
export function useRenameProfile() {
  const queryClient = useQueryClient();
  const change = (p: Profile, name: string): Profile => ({...p, name});
  return useMutation({
    mutationFn: async ({id, name}: {id: string; name: string}) => required(await api.PATCH("/profiles/{id}", {params: {path: {id}}, body: {name}})),
    ...optimistic<{id: string; name: string}>({
      queryClient,
      keys: [profileKeys.all],
      apply: (current, {id, name}) => {
        if (Array.isArray(current)) return (current as Profile[]).map((p) => (p.id === id ? change(p, name) : p));
        const one = current as Profile;
        return one.id === id ? change(one, name) : undefined;
      },
      onFail: (error, {id}) => noteLockedProfile(queryClient, id, error),
    }),
  });
}

/**
 * `DELETE /profiles/{id}`. A profile an Endpoint or a schedule window still uses is 409 `profile_in_use`. The caches of the profile
 * go and the sidebar count follows from the list.
 */
export function useDeleteProfile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.DELETE("/profiles/{id}", {params: {path: {id}}});
      return id;
    },
    onSuccess: (id) => {
      queryClient.removeQueries({queryKey: profileKeys.detail(id)});
      queryClient.setQueryData<Profile[]>(profileKeys.list, (list) => list?.filter((p) => p.id !== id));
      void queryClient.invalidateQueries({queryKey: profileKeys.list});
    },
    onError: (error, id) => noteLockedProfile(queryClient, id, error),
  });
}

export type DisableFor = "5m" | "1h" | "1d";

/** `PUT /profiles/{id}/disabled` with `for` or `until`, and `DELETE` to switch it back on (T-138). */
export const disableProfileOptions = (queryClient: QueryClient) => ({
  mutationFn: async ({id, ...when}: {id: string; for?: DisableFor; until?: string}) =>
    required(await api.PUT("/profiles/{id}/disabled", {params: {path: {id}}, body: when})),
  onMutate: startedIn,
  onSuccess: (profile: Profile, _vars: {id: string; for?: DisableFor; until?: string}, context: Started) => {
    if (context?.alive()) putProfile(queryClient, profile);
  },
  onError: (error: unknown, {id}: {id: string}, context: Started) => {
    if (context?.alive()) noteLockedProfile(queryClient, id, error);
  },
});

export function useDisableProfile() {
  return useMutation(disableProfileOptions(useQueryClient()));
}

export const enableProfileOptions = (queryClient: QueryClient) => ({
  mutationFn: async (id: string) => required(await api.DELETE("/profiles/{id}/disabled", {params: {path: {id}}})),
  onMutate: startedIn,
  onSuccess: (profile: Profile, _id: string, context: Started) => {
    if (context?.alive()) putProfile(queryClient, profile);
  },
  onError: (error: unknown, id: string, context: Started) => {
    if (context?.alive()) noteLockedProfile(queryClient, id, error);
  },
});

export function useEnableProfile() {
  return useMutation(enableProfileOptions(useQueryClient()));
}

/**
 * `POST /profiles/{id}/lock`. Needs a live reauth: `reauth_required` is the caller's to handle (`callWithRecovery`). The password
 * is the profile's own and lives in the dialog's state only (FE 9): it is a variable of this mutation, which keeps nothing once the
 * dialog unmounts (`mutationDefaults.gcTime`).
 */
export function useLockProfile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({id, password, message}: {id: string; password: string; message?: string}) => {
      await api.POST("/profiles/{id}/lock", {params: {path: {id}}, body: message ? {password, message} : {password}});
    },
    onSettled: (_data, _error, {id}) => {
      void queryClient.invalidateQueries({queryKey: profileKeys.detail(id)});
      void queryClient.invalidateQueries({queryKey: profileKeys.list});
    },
  });
}

/** `POST /profiles/{id}/unlock`. A wrong password is 401 `invalid_credentials`; five failures in 15 minutes is 429. */
export function useUnlockProfile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({id, password}: {id: string; password: string}) => {
      await api.POST("/profiles/{id}/unlock", {params: {path: {id}}, body: {password}});
    },
    onSettled: (_data, _error, {id}) => {
      void queryClient.invalidateQueries({queryKey: profileKeys.detail(id)});
      void queryClient.invalidateQueries({queryKey: profileKeys.list});
    },
  });
}

/** `GET /profiles/{id}/export`: the document, canonical, as the browser saves it. Heavy: 10 a minute per session. */
export async function fetchProfileDocument(id: string): Promise<ProfileDocument> {
  return required(await api.GET("/profiles/{id}/export", {params: {path: {id}}}));
}

export function useExportProfile() {
  return useMutation({mutationFn: fetchProfileDocument});
}

/**
 * `GET /profiles/{id}/locations`: where a Redirect may go (the Destinations dialog, T-063). `slugs` limits it to the intersection of
 * the services named, at most 100 a call (spec p2 9.5): a longer selection is several calls intersected by the caller.
 */
export const profileLocationsQuery = (id: string | undefined, slugs: readonly string[] = []) => {
  const joined = [...slugs].sort().join(",");
  return queryOptions({
    queryKey: profileKeys.locations(id ?? "", joined),
    queryFn: async ({signal}) =>
      required(await api.GET("/profiles/{id}/locations", {params: {path: {id: id!}, query: joined ? {services: joined} : {}}, signal})),
    enabled: isUuid(id),
    retry: shouldRetry,
  });
};

export function useProfileLocations(id: string | undefined, slugs: readonly string[] = [], options: {enabled?: boolean} = {}) {
  return useQuery({...profileLocationsQuery(id, slugs), enabled: isUuid(id) && (options.enabled ?? true)});
}

