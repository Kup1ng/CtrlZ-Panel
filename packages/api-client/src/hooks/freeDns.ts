import {queryOptions, useQuery} from "@tanstack/react-query";

import {pollEvery} from "../activity.ts";
import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";

// Plan T-557 (D55): the Endpoint page, the verify wizard, the delete dialog and the notices say what happens to a device that is not
// identified. That depends on one switch, which the browser reads from the public route `GET /public/free-dns` (p4-nodes 9.3): a server of
// ours never calls the API, so the source network of the request is the visitor's own.
//
// The switch is either known or not. When the route cannot be read (429, 5xx, no network), the tab uses the last good answer of its own for
// up to five minutes. After that, or with none, the state is "unknown" and a text that depends on the switch is not shown at all: no free
// DNS wording and no REFUSED wording. The memory is a module variable, so it belongs to this tab only and is never stored.

export type PublicFreeDns = components["schemas"]["PublicFreeDns"];

export const FREE_DNS_KEEP_MS = 5 * 60_000;
const READ_EVERY_MS = 60_000;

export const freeDnsKeys = {public: ["public", "free-dns"] as const};

let lastGood: {value: PublicFreeDns; at: number} | null = null;

/** Forgets the last good answer: for tests, and for a tab that signs out. */
export function forgetFreeDns(): void {
  lastGood = null;
}

/** One read. A failure answers with the last good value when it is younger than five minutes, and throws otherwise. */
export async function readFreeDns(signal?: AbortSignal, now: () => number = Date.now): Promise<PublicFreeDns> {
  try {
    const value = required(await api.GET("/public/free-dns", {signal}));
    if (typeof value.enabled !== "boolean") throw new Error("free-dns: not an answer");
    lastGood = {value, at: now()};
    return value;
  } catch (error) {
    if (signal?.aborted) throw error;
    if (lastGood && now() - lastGood.at < FREE_DNS_KEEP_MS) return lastGood.value;
    throw error;
  }
}

export const freeDnsQuery = () =>
  queryOptions({
    queryKey: freeDnsKeys.public,
    queryFn: ({signal}) => readFreeDns(signal),
    retry: false,
    // The route says `max-age=30`; the browser cache and this agree, so a second component of the page does not ask again.
    staleTime: 30_000,
    refetchInterval: pollEvery(READ_EVERY_MS),
    refetchOnWindowFocus: false,
  });

export type FreeDnsState = {
  /** `true` and `false` are the switch; `null` is not known, and nothing that depends on the switch is said. */
  enabled: boolean | null;
  primary?: string;
  fallback?: string;
};

/** The switch of free DNS and the addresses to type, or `{enabled: null}` while it is not known. `enabled: false` is the option of a caller that needs it only sometimes. */
export function useFreeDns(options: {enabled?: boolean} = {}): FreeDnsState {
  const query = useQuery({...freeDnsQuery(), enabled: options.enabled ?? true});
  if (query.isError || !query.data) return {enabled: null};
  return {
    enabled: query.data.enabled,
    ...(query.data.primary_dns_ip ? {primary: query.data.primary_dns_ip} : {}),
    ...(query.data.fallback_dns_ip ? {fallback: query.data.fallback_dns_ip} : {}),
  };
}
