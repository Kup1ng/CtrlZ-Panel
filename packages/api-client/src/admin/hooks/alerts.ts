import {queryOptions, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {pollEvery} from "../../activity.ts";
import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";
import {adminMeKeys, type AdminMe} from "../session.ts";
import {adminAuthApi} from "./auth.ts";

// Spec 13.6. The header notices of `AdminMe` and the operator alerts. Alerts poll every 60 s while a person is at
// the page (activity.ts), like the panel's bell: an unattended tab must not keep the session alive by asking.

type S = components["schemas"];
export type AlertRow = S["AlertRow"];
export type AdminNotice = S["AdminNotice"];
export type AlertSeverity = AlertRow["severity"];

export const ALERT_POLL_MS = 60_000;
/** One page is enough for a banner stack that shows at most a handful, and the API sorts unresolved first. */
export const ALERT_PAGE_SIZE = 50;

export const alertKeys = {list: ["admin", "alerts"] as const};

export const alertsQueryOptions = () =>
  queryOptions({
    queryKey: alertKeys.list,
    queryFn: async ({signal}) => required(await adminApi.GET("/alerts", {params: {query: {limit: ALERT_PAGE_SIZE}}, signal})).items,
    refetchInterval: pollEvery(ALERT_POLL_MS),
    retry: shouldRetry,
  });

const SEVERITY_ORDER: Record<AlertSeverity, number> = {critical: 0, warning: 1, info: 2};

/** Unresolved alerts, `critical` first and the newest first inside a severity. Pure, so the order is tested. */
export function unresolvedAlerts(items: readonly AlertRow[] | undefined): AlertRow[] {
  return (items ?? [])
    .filter((a) => a.resolved_at === undefined)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || Date.parse(b.created_at) - Date.parse(a.created_at));
}

export function useAlerts(options: {enabled?: boolean} = {}) {
  return useQuery({...alertsQueryOptions(), enabled: options.enabled ?? true});
}

/** `POST /alerts/{id}/ack`. The row is marked resolved in the cache at once, then the list is asked again. */
export function useAckAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await adminApi.POST("/alerts/{id}/ack", {params: {path: {id}}});
    },
    onSuccess: (_data, id) => {
      queryClient.setQueryData<AlertRow[]>(alertKeys.list, (items) =>
        items?.map((a) => (a.id === id ? {...a, resolved_at: new Date().toISOString()} : a)),
      );
      return queryClient.invalidateQueries({queryKey: alertKeys.list});
    },
  });
}

/**
 * `POST /me/notices/ack`, then `/me` is asked again. The ack clears only the notices dated before this session
 * began, so a notice made in this session survives it: the shell must not assume `/me` is empty afterwards (13.6).
 */
export function useAckNotices() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => adminAuthApi.ackNotices(),
    onSuccess: () => queryClient.invalidateQueries({queryKey: adminMeKeys.all}),
  });
}

/** The notices of `/me`, newest first. */
export function noticesOf(me: Pick<AdminMe, "notices"> | undefined): AdminNotice[] {
  return [...(me?.notices ?? [])].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
}
