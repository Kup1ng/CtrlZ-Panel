import {queryOptions, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import {noteLockedProfile, optimistic} from "./optimistic.ts";
import {profileKeys} from "./profileKeys.ts";
import {isUuid} from "./support.ts";

// Spec p2 9.7. A profile's options and the one write, a PATCH of the fields to set and `clear` of the ones to unset. A switch turned
// off clears the option (open question 3), so `setOption(name, false)` is `clear: [name]` for the boolean options that have no
// meaningful "off" value of their own.

export type Options = components["schemas"]["Options"];
export type OptionsPatch = components["schemas"]["OptionsPatch"];
export type OptionName = NonNullable<OptionsPatch["clear"]>[number];

export const profileOptionsQuery = (profileId: string | undefined) =>
  queryOptions({
    queryKey: profileKeys.options(profileId ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/profiles/{id}/options", {params: {path: {id: profileId!}}, signal})),
    enabled: isUuid(profileId),
    retry: shouldRetry,
  });

export function useProfileOptions(profileId: string | undefined) {
  return useQuery(profileOptionsQuery(profileId));
}

/** The cache after a patch, as a pure function: the fields set replace, the names in `clear` go. `default_location_unavailable` is the server's. */
export function applyOptionsPatch(options: Options, patch: OptionsPatch): Options {
  const {clear, ...set} = patch;
  const next: Record<string, unknown> = {...options, ...set};
  for (const name of clear ?? []) delete next[name];
  return next as Options;
}

export type PatchOptionsVars = {profileId: string; patch: OptionsPatch};

/** `PATCH /profiles/{id}/options`. A switch or a segmented control answers at once and is put back on a refusal. */
export function usePatchOptions() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, patch}: PatchOptionsVars) => required(await api.PATCH("/profiles/{id}/options", {params: {path: {id: profileId}}, body: patch})),
    ...optimistic<PatchOptionsVars>({
      queryClient,
      keys: (v) => [profileKeys.options(v.profileId)],
      apply: (current, v) => applyOptionsPatch(current as Options, v.patch),
      // The options counter of the profile's row follows.
      settle: (v) => [profileKeys.options(v.profileId), profileKeys.list],
      onFail: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
    }),
  });
}

/** The number of option units that are set, as the list counter counts them (spec p2 2.2 item 10): Default Rule, Block Response and ECS one each. */
export function optionUnitCount(options: Options): number {
  return Object.entries(options).filter(([name, value]) => name !== "default_location_unavailable" && value !== undefined && value !== null).length;
}
