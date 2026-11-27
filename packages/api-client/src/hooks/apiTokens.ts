import {queryOptions, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import {accountKeys} from "./profileKeys.ts";

// Spec p3 6.4 and 9.2: the API tokens page (`/preferences/api`) and the feedback dialog of the logo menu.
//
// Types come from the generated document, so a schema change reaches tsc here instead of failing at run time.
export type ApiToken = components["schemas"]["ApiToken"];
export type ApiTokenKind = ApiToken["kind"];
export type ApiTokenCreate = components["schemas"]["ApiTokenCreate"];
export type ApiTokenPatch = components["schemas"]["ApiTokenPatch"];
/** `value` is `ctz_` and 64 characters, shown once. */
export type ApiTokenCreated = components["schemas"]["ApiTokenCreated"];
export type FeedbackCreate = components["schemas"]["FeedbackCreate"];
export type FeedbackKind = FeedbackCreate["kind"];

export const apiTokensQueryOptions = () =>
  queryOptions({
    queryKey: accountKeys.apiKeys,
    queryFn: async ({signal}) => required(await api.GET("/api-tokens", {signal})).tokens,
    retry: shouldRetry,
  });

export function useApiTokens() {
  return useQuery(apiTokensQueryOptions());
}

export type TokenState = "live" | "expired" | "ended";

/** One word for the list: a token that a credential change ended, one past its year, or a live one. Never by colour alone. */
export function tokenState(token: Pick<ApiToken, "ended" | "expires_at">, now: number): TokenState {
  if (token.ended) return "ended";
  return Date.parse(token.expires_at) <= now ? "expired" : "live";
}

/**
 * `POST /api-tokens`: needs a live reauth (`reauth_required` is the caller's to handle with `callWithRecovery`). The answer holds the
 * value ONCE: the page keeps it in the state of the dialog that shows it, and the mutation forgets it when that dialog unmounts.
 */
export function useCreateApiToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: ApiTokenCreate): Promise<ApiTokenCreated> => required(await api.POST("/api-tokens", {body})),
    onSuccess: () => void queryClient.invalidateQueries({queryKey: accountKeys.apiKeys}),
  });
}

/** `PATCH /api-tokens/{tid}`: name and allowed prefixes only; the kind cannot change. Needs a live reauth. */
export function usePatchApiToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({id, ...body}: {id: string} & ApiTokenPatch) => required(await api.PATCH("/api-tokens/{tid}", {params: {path: {tid: id}}, body})),
    onSuccess: () => void queryClient.invalidateQueries({queryKey: accountKeys.apiKeys}),
  });
}

export function useDeleteApiToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.DELETE("/api-tokens/{tid}", {params: {path: {tid: id}}});
    },
    onSuccess: () => void queryClient.invalidateQueries({queryKey: accountKeys.apiKeys}),
  });
}

/** `POST /feedback`: Request Feature and Contact. 20 a day per tenant. */
export function useSendFeedback() {
  return useMutation({
    mutationFn: async (body: FeedbackCreate) => {
      await api.POST("/feedback", {body});
    },
  });
}
