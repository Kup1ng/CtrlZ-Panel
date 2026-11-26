import {queryOptions, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import {noteLockedProfile, optimistic} from "./optimistic.ts";
import {catalogKeys, profileKeys} from "./profileKeys.ts";
import {isUuid} from "./support.ts";

// Spec p2 9.3. The catalogue of filters (the same for every tenant, so cached long), a profile's filters, and the one write: turn a
// filter on or off and pick its mode. A filter that is switched off keeps its row, so its mode is remembered (T-144).

export type CatalogFilter = components["schemas"]["CatalogFilter"];
export type ProfileFilter = components["schemas"]["ProfileFilter"];

export const catalogFiltersQueryOptions = () =>
  queryOptions({
    queryKey: catalogKeys.filters,
    queryFn: async ({signal}) => required(await api.GET("/catalog/filters", {signal})).filters,
    // The catalogue changes with a release, not with a click.
    staleTime: 10 * 60_000,
    retry: shouldRetry,
  });

export function useCatalogFilters() {
  return useQuery(catalogFiltersQueryOptions());
}

export const profileFiltersQuery = (profileId: string | undefined) =>
  queryOptions({
    queryKey: profileKeys.filters(profileId ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/profiles/{id}/filters", {params: {path: {id: profileId!}}, signal})).filters,
    enabled: isUuid(profileId),
    retry: shouldRetry,
  });

export function useProfileFilters(profileId: string | undefined) {
  return useQuery(profileFiltersQuery(profileId));
}

/** The state of one filter in a profile: no row is "off with no remembered mode". */
export function filterState(rows: readonly ProfileFilter[] | undefined, filterId: string): {enabled: boolean; mode?: string} {
  const row = rows?.find((r) => r.filter_id === filterId);
  return row ? {enabled: row.enabled, ...(row.mode !== undefined ? {mode: row.mode} : {})} : {enabled: false};
}

/** The mode a filter takes when it is first switched on: the one the catalogue marks as default (T-146). `undefined` for a one-mode filter. */
export function defaultMode(filter: Pick<CatalogFilter, "modes">): string | undefined {
  return filter.modes.find((m) => m.default)?.mode;
}

/**
 * The cache after a filter was set, as a pure function so the optimistic rule is tested without React: the row is replaced or added,
 * and a switch-off keeps the mode that the row already had unless a new one is given.
 */
export function withFilter(rows: readonly ProfileFilter[], filterId: string, set: {enabled: boolean; mode?: string}): ProfileFilter[] {
  const old = rows.find((r) => r.filter_id === filterId);
  const mode = set.mode ?? old?.mode;
  const next: ProfileFilter = {filter_id: filterId, enabled: set.enabled, ...(mode !== undefined ? {mode} : {})};
  return old ? rows.map((r) => (r.filter_id === filterId ? next : r)) : [...rows, next];
}

export type SetFilterVars = {profileId: string; filterId: string; enabled: boolean; mode?: string};

/**
 * `PUT /profiles/{id}/filters/{filter_id}`. The switch moves at once, a refusal puts it back (423 `profile_locked` also makes the
 * profile read again, so the lock banner shows). A one-mode filter is sent no `mode`, and any `mode` on it would be refused.
 */
export function useSetProfileFilter() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, filterId, enabled, mode}: SetFilterVars) =>
      required(
        await api.PUT("/profiles/{id}/filters/{filter_id}", {
          params: {path: {id: profileId, filter_id: filterId}},
          body: mode === undefined ? {enabled} : {enabled, mode},
        }),
      ),
    ...optimistic<SetFilterVars>({
      queryClient,
      keys: (v) => [profileKeys.filters(v.profileId)],
      apply: (rows, v) => withFilter(rows as ProfileFilter[], v.filterId, v),
      // The profile's counters (the filters count of its row in the list) follow.
      settle: (v) => [profileKeys.filters(v.profileId), profileKeys.list],
      onFail: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
    }),
  });
}
