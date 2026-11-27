import {queryOptions, useQuery} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import {hasCode, type FieldError} from "../errors.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import {accountKeys} from "./profileKeys.ts";

// Spec p2 3.4 and p3 3.5. A write over a limit is 422 `validation_failed` with `fields: [{name: <limit>, code: "exceeded"}]` and nothing
// written. The answer names the limit and not its number, so the capacity notice asks `GET /account/limits` for the figure.

export type Limits = components["schemas"]["Limits"];
export type LimitName = keyof Limits;

export const limitsQueryOptions = () =>
  queryOptions({
    queryKey: accountKeys.limits,
    queryFn: async ({signal}) => required(await api.GET("/account/limits", {signal})),
    staleTime: 5 * 60_000,
    retry: shouldRetry,
  });

export function useLimits(options: {enabled?: boolean} = {}) {
  return useQuery({...limitsQueryOptions(), enabled: options.enabled ?? true});
}

/** Limits of P2 and P3 that are not in `Limits` (constants of the API, spec p2 3.4 and p3 3.5), for the notice's wording only. */
export const KNOWN_CAPS = [
  "max_profiles",
  "max_rules_per_profile",
  "max_wildcards_per_profile",
  "max_folders_per_profile",
  "max_rules_per_request",
  "max_endpoints",
  "max_clients_per_endpoint",
  "max_endpoint_groups",
  "max_ddns_hosts",
  "max_authorized_ips",
  "max_ip_claims",
  "max_share_links_per_endpoint",
  "max_download_links_per_tenant",
  "max_api_tokens",
  "lock_passwords",
] as const;
export type KnownCap = (typeof KNOWN_CAPS)[number];

const KNOWN = new Set<string>(KNOWN_CAPS);

/** The limit a 422 ran into, or `null` when the answer is not a limit. An unknown name reads as `other`, so a new cap still shows a line. */
export function exceededCap(error: unknown): {name: KnownCap | "other"; field: FieldError} | null {
  if (!hasCode(error, "validation_failed")) return null;
  const field = (error.fields ?? []).find((f) => f.code === "exceeded");
  if (!field) return null;
  const bare = field.name.replace(/^\//, "");
  return {name: KNOWN.has(bare) ? (bare as KnownCap) : "other", field};
}

/** The number of a cap if `Limits` holds it. */
export function capOf(limits: Limits | undefined, name: KnownCap | "other"): number | undefined {
  return limits && name !== "other" && name in limits ? limits[name as LimitName] : undefined;
}
