import {queryOptions, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {pollEvery} from "../../activity.ts";
import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";

// Spec 13.3. The SMS page: gateways, routing, templates, limits, stats and the test send. Credentials are
// write-only: a request carries them, nothing here reads them back, and no variable of a call is kept (the
// mutations are used through `mutateAsync` by screens that clear their fields when the call goes out).
// The calls marked `admin-fresh` in the document answer 403 `totp_fresh_required` outside the five minute window;
// the screens run them through `useFreshRecoverable` (ui/auth/FreshTotpDialog.tsx), which opens the dialog and repeats once.

type S = components["schemas"];
export type SmsProvider = S["SmsProvider"];
export type SmsGatewayRow = S["SmsGatewayRow"];
export type SmsGatewayRequest = S["SmsGatewayRequest"];
export type SmsRoutingRequest = S["SmsRoutingRequest"];
export type SmsTemplateRow = S["SmsTemplateRow"];
export type SmsTemplateMapping = S["SmsTemplateMapping"];
export type SmsProviderTemplateRequest = S["SmsProviderTemplateRequest"];
export type SmsLimits = S["SmsLimits"];
export type SmsStats = S["SmsStats"];
export type SmsOutboxStatus = S["SmsOutboxStatus"];
export type SmsTestRequest = S["SmsTestRequest"];
export type LocaleCode = S["LocaleCode"];

export const smsKeys = {
  gateways: ["admin", "sms", "gateways"] as const,
  templates: ["admin", "sms", "templates"] as const,
  limits: ["admin", "sms", "limits"] as const,
  stats: (days: number) => ["admin", "sms", "stats", days] as const,
  outbox: (id: string) => ["admin", "sms", "outbox", id] as const,
};

export const gatewaysQueryOptions = () =>
  queryOptions({
    queryKey: smsKeys.gateways,
    queryFn: async ({signal}) => required(await adminApi.GET("/sms/gateways", {signal})).items,
    retry: shouldRetry,
  });
export const useGateways = () => useQuery(gatewaysQueryOptions());

export const templatesQueryOptions = () =>
  queryOptions({
    queryKey: smsKeys.templates,
    queryFn: async ({signal}) => required(await adminApi.GET("/sms/templates", {signal})).items,
    retry: shouldRetry,
  });
export const useTemplates = () => useQuery(templatesQueryOptions());

export const limitsQueryOptions = () =>
  queryOptions({
    queryKey: smsKeys.limits,
    queryFn: async ({signal}) => required(await adminApi.GET("/sms/limits", {signal})),
    retry: shouldRetry,
  });
export const useLimits = () => useQuery(limitsQueryOptions());

export const STATS_DAYS = 7;
export const statsQueryOptions = (days = STATS_DAYS) =>
  queryOptions({
    queryKey: smsKeys.stats(days),
    queryFn: async ({signal}) => required(await adminApi.GET("/sms/stats", {params: {query: {days}}, signal})),
    retry: shouldRetry,
  });
export const useStats = (days = STATS_DAYS) => useQuery(statsQueryOptions(days));

export function useSaveGateway() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({provider, body}: {provider: SmsProvider; body: SmsGatewayRequest}) =>
      required(await adminApi.PUT("/sms/gateways/{provider}", {params: {path: {provider}}, body})),
    // Not awaited: the answer of a credentials PUT holds the one fingerprint that confirms the staged pair, and the form must have it the
    // moment the server has committed, not after a refetch that a slow link can hold for as long as its retries take (merge-r3-13).
    onSuccess: () => {
      void queryClient.invalidateQueries({queryKey: smsKeys.gateways});
    },
  });
}

export function useSaveRouting() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: SmsRoutingRequest) => required(await adminApi.PUT("/sms/routing", {body})).items,
    onSuccess: (items) => queryClient.setQueryData(smsKeys.gateways, items),
  });
}

export function useSaveLimits() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: SmsLimits) => required(await adminApi.PUT("/sms/limits", {body})),
    onSuccess: (limits) => queryClient.setQueryData(smsKeys.limits, limits),
  });
}

export function useSaveTemplate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({key, locale, body}: {key: string; locale: LocaleCode; body: string}) =>
      required(await adminApi.PUT("/sms/templates/{key}/{locale}", {params: {path: {key, locale}}, body: {body}})),
    onSuccess: () => queryClient.invalidateQueries({queryKey: smsKeys.templates}),
  });
}

export function useSaveProviderTemplate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({provider, key, locale, body}: {provider: SmsProvider; key: string; locale: LocaleCode; body: SmsProviderTemplateRequest}) =>
      required(await adminApi.PUT("/sms/gateways/{provider}/templates/{key}/{locale}", {params: {path: {provider, key, locale}}, body})),
    onSuccess: () => queryClient.invalidateQueries({queryKey: smsKeys.templates}),
  });
}

/** `POST /sms/gateways/{provider}/test`. Goes through the outbox, so the answer is an id to poll. */
export function useTestGateway() {
  return useMutation({
    mutationFn: async ({provider, body}: {provider: SmsProvider; body: SmsTestRequest}) =>
      required(await adminApi.POST("/sms/gateways/{provider}/test", {params: {path: {provider}}, body})).outbox_id,
  });
}

export const OUTBOX_POLL_MS = 1500;

/**
 * Whether the outbox lookup asks again: only while the last answer said `pending`. A lookup that has failed (an expired row, a
 * 403, a permanent 5xx) holds no answer, and polling it would hit the endpoint every interval under a visible Retry (wp10-r14-3).
 * The first answer comes from the ordinary fetch, and Retry refetches by hand, after which polling resumes by itself.
 */
export function outboxPollInterval(state: {status: string; data?: {state: string}}): number | false {
  if (state.status === "error" || state.data?.state !== "pending") return false;
  return pollEvery(OUTBOX_POLL_MS)();
}

/** The state of one queued test message, polled until it is no longer `pending`. Never holds a number or a text. */
export function useOutbox(id: string | undefined) {
  return useQuery({
    queryKey: smsKeys.outbox(id ?? ""),
    queryFn: async ({signal}) => required(await adminApi.GET("/sms/outbox/{id}", {params: {path: {id: id ?? ""}}, signal})),
    enabled: id !== undefined,
    refetchInterval: (query) => outboxPollInterval(query.state),
    retry: shouldRetry,
  });
}
