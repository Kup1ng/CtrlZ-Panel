import {queryOptions, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import {noteLockedProfile, optimistic} from "./optimistic.ts";
import {catalogKeys, profileKeys} from "./profileKeys.ts";
import {isUuid} from "./support.ts";

// Spec p2 9.4. The catalogue of services (categories and services, the same for every tenant), a profile's services, and the writes:
// set one (switch, action, destination), remove one, and the batch of Choose Service and of the group actions.
//
// `target` of a write names a location by `location_id` (spec p2 8.1); the one of a read names it by key as well, so a row whose
// location left the set can still be shown.

export type CatalogService = components["schemas"]["CatalogService"];
export type ServiceCategory = components["schemas"]["Category"];
export type ProfileService = components["schemas"]["ProfileService"];
export type Target = components["schemas"]["Target"];
export type ServiceAction = ProfileService["action"];
export type BatchResult = components["schemas"]["BatchResult"];

export const catalogServicesQueryOptions = () =>
  queryOptions({
    queryKey: catalogKeys.services,
    queryFn: async ({signal}) => required(await api.GET("/catalog/services", {signal})),
    staleTime: 10 * 60_000,
    retry: shouldRetry,
  });

export function useCatalogServices() {
  return useQuery(catalogServicesQueryOptions());
}

export const profileServicesQuery = (profileId: string | undefined) =>
  queryOptions({
    queryKey: profileKeys.services(profileId ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/profiles/{id}/services", {params: {path: {id: profileId!}}, signal})).services,
    enabled: isUuid(profileId),
    retry: shouldRetry,
  });

export function useProfileServices(profileId: string | undefined) {
  return useQuery(profileServicesQuery(profileId));
}

/** A service a Redirect may not go to (D42, T-521): the card offers Block and Bypass only. */
export const canRedirect = (service: Pick<CatalogService, "redirect_allowed">): boolean => service.redirect_allowed;

/**
 * What a group action offers for a selection (T-166, T-521): Redirect is off when one of the services is never proxied. The empty
 * shared destination is the location set's to say (`auto_random` and `locations` of `GET /profiles/{id}/locations`).
 */
export function selectionAllowsRedirect(selection: readonly Pick<CatalogService, "redirect_allowed">[]): boolean {
  return selection.every(canRedirect);
}

/** The services of the catalogue grouped by category, in the category order of the catalogue. A category with none is left out. */
export function groupByCategory<T extends {category_id: string}>(categories: readonly ServiceCategory[], services: readonly T[]): {category: ServiceCategory; services: T[]}[] {
  const byId = new Map<string, T[]>();
  for (const s of services) {
    const list = byId.get(s.category_id);
    if (list) list.push(s);
    else byId.set(s.category_id, [s]);
  }
  return categories.flatMap((category) => {
    const list = byId.get(category.id);
    return list ? [{category, services: list}] : [];
  });
}

export type SetServiceVars = {profileId: string; slug: string; enabled: boolean; action: ServiceAction; target?: Target};

/**
 * A target as a write names it (spec p2 8.1): by `location_id`, never by the `location` key that a read adds to show it in words. A row
 * is written back with the target it was read with (the switch of a Redirect card), so the key is dropped here and not by each caller.
 */
export function writeTarget(target: Target): Target {
  const rest = {...target};
  delete rest.location;
  return rest;
}

/**
 * The cache after a service was set: replaced, or added. `location_unavailable` and `iranian_bypass` are the server's to say and are kept
 * until the refetch. A write that leaves a Redirect a Redirect and names no target keeps the row's destination in the cache.
 */
export function withService(rows: readonly ProfileService[], v: Omit<SetServiceVars, "profileId">): ProfileService[] {
  const old = rows.find((r) => r.slug === v.slug);
  const target = v.target ?? (v.action === "redirect" && old?.action === "redirect" ? old.target : undefined);
  const next: ProfileService = {
    slug: v.slug,
    enabled: v.enabled,
    action: v.action,
    ...(target ? {target} : {}),
    location_unavailable: old?.location_unavailable ?? false,
    iranian_bypass: old?.iranian_bypass ?? false,
  };
  return old ? rows.map((r) => (r.slug === v.slug ? next : r)) : [...rows, next];
}

/** `PUT /profiles/{id}/services/{slug}`. The switch and the three-state control answer at once and are put back on a refusal. */
export function useSetProfileService() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, slug, enabled, action, target}: SetServiceVars) =>
      required(
        await api.PUT("/profiles/{id}/services/{slug}", {
          params: {path: {id: profileId, slug}},
          body: target ? {enabled, action, target: writeTarget(target)} : {enabled, action},
        }),
      ),
    ...optimistic<SetServiceVars>({
      queryClient,
      keys: (v) => [profileKeys.services(v.profileId)],
      apply: (rows, v) => withService(rows as ProfileService[], v),
      settle: (v) => [profileKeys.services(v.profileId), profileKeys.list],
      onFail: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
    }),
  });
}

/** `DELETE /profiles/{id}/services/{slug}`: the service leaves the profile, and the card with it. */
export function useRemoveProfileService() {
  const queryClient = useQueryClient();
  type Vars = {profileId: string; slug: string};
  return useMutation({
    mutationFn: async ({profileId, slug}: Vars) => {
      await api.DELETE("/profiles/{id}/services/{slug}", {params: {path: {id: profileId, slug}}});
    },
    ...optimistic<Vars>({
      queryClient,
      keys: (v) => [profileKeys.services(v.profileId)],
      apply: (rows, v) => (rows as ProfileService[]).filter((r) => r.slug !== v.slug),
      settle: (v) => [profileKeys.services(v.profileId), profileKeys.list],
      onFail: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
    }),
  });
}

export type ServicesBatchVars =
  | {profileId: string; op: "set"; slugs: string[]; enabled: boolean; action: ServiceAction; target?: Target}
  | {profileId: string; op: "delete"; slugs: string[]};

/**
 * `POST /profiles/{id}/services:batch`: Choose Service's Add, the group actions and remove all of a category (T-163, T-164). At most
 * 2,000 slugs, so it never becomes a job. A Redirect on a service that is never proxied is 422 `iranian_name`.
 */
export function useBatchProfileServices() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (v: ServicesBatchVars) => {
      const {profileId, ...body} = v;
      const sent = body.op === "set" && body.target ? {...body, target: writeTarget(body.target)} : body;
      return required(await api.POST("/profiles/{id}/services:batch", {params: {path: {id: profileId}}, body: sent}));
    },
    onSuccess: (_result, v) => {
      void queryClient.invalidateQueries({queryKey: profileKeys.services(v.profileId)});
      void queryClient.invalidateQueries({queryKey: profileKeys.list});
    },
    onError: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
  });
}
