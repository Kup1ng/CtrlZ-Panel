import {queryOptions, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";

// Spec 13.4. Registration mode and the Passkey RP ID. Both writes are `admin-fresh`, and both have an impact route
// that the screen shows before it asks for confirmation (Plan T-331): the counts are for the value that is about to be
// written, so they are asked for each candidate and never cached across candidates for long.

type S = components["schemas"];
export type RegistrationMode = S["RegistrationMode"];
export type RegistrationSettings = S["RegistrationSettings"];
export type RegistrationRequest = S["RegistrationRequest"];
export type RegistrationImpact = S["RegistrationImpact"];
export type WebauthnConfig = S["WebauthnConfig"];
export type WebauthnRequest = S["WebauthnRequest"];
export type WebauthnImpact = S["WebauthnImpact"];

/** The API's own bounds for `open_grace_days` (a grace outside 1 to 365 is a 400). */
export const GRACE_DAYS_MIN = 1;
export const GRACE_DAYS_MAX = 365;
export const GRACE_DAYS_DEFAULT = 30;

export const settingsKeys = {
  registration: ["admin", "settings", "registration"] as const,
  registrationImpact: (to: RegistrationMode) => ["admin", "settings", "registration", "impact", to] as const,
  webauthn: ["admin", "settings", "webauthn"] as const,
  webauthnImpact: (rpId: string) => ["admin", "settings", "webauthn", "impact", rpId] as const,
};

export const registrationQueryOptions = () =>
  queryOptions({
    queryKey: settingsKeys.registration,
    queryFn: async ({signal}) => required(await adminApi.GET("/settings/registration", {signal})),
    retry: shouldRetry,
  });
export const useRegistration = () => useQuery(registrationQueryOptions());

export const webauthnQueryOptions = () =>
  queryOptions({
    queryKey: settingsKeys.webauthn,
    queryFn: async ({signal}) => required(await adminApi.GET("/settings/webauthn", {signal})),
    retry: shouldRetry,
  });
export const useWebauthn = () => useQuery(webauthnQueryOptions());

/** What moving to `to` does to unproven claims. Asked when the admin picks a mode, before any write. */
export function useRegistrationImpact(to: RegistrationMode | undefined) {
  return useQuery({
    queryKey: settingsKeys.registrationImpact(to ?? "closed"),
    queryFn: async ({signal}) => required(await adminApi.GET("/settings/registration/impact", {params: {query: {to: to ?? "closed"}}, signal})),
    enabled: to !== undefined,
    // The counts move with the users, so a candidate that was looked at a while ago is asked again.
    staleTime: 0,
    gcTime: 0,
    retry: shouldRetry,
  });
}

export function useWebauthnImpact(rpId: string | undefined) {
  return useQuery({
    queryKey: settingsKeys.webauthnImpact(rpId ?? ""),
    queryFn: async ({signal}) => required(await adminApi.GET("/settings/webauthn/impact", {params: {query: {rp_id: rpId ?? ""}}, signal})),
    enabled: rpId !== undefined && rpId !== "",
    staleTime: 0,
    gcTime: 0,
    retry: shouldRetry,
  });
}

export function useSaveRegistration() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: RegistrationRequest) => required(await adminApi.PUT("/settings/registration", {body})),
    onSuccess: (settings) => queryClient.setQueryData(settingsKeys.registration, settings),
  });
}

export function useSaveWebauthn() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: WebauthnRequest) => required(await adminApi.PUT("/settings/webauthn", {body})),
    onSuccess: (config) => queryClient.setQueryData(settingsKeys.webauthn, config),
  });
}
