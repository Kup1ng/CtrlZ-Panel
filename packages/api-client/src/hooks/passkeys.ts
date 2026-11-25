import {queryOptions, useMutation, useQuery, useQueryClient, type QueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import {passkeyAdd} from "../webauthn.ts";
import {meKeys} from "./me.ts";
import {sessionKeys} from "./sessions.ts";

// Spec 12.5. Passkey routes of the Account page. Every route that changes the set
// of passkeys or Enforce also changes what `/me` says (`security.*`), and some
// end other sessions, so those caches are dropped together.

export const passkeyKeys = {list: ["account", "passkeys"] as const};

export const passkeysQueryOptions = () =>
  queryOptions({
    queryKey: passkeyKeys.list,
    queryFn: async ({signal}) => required(await api.GET("/account/passkeys", {signal})).passkeys,
  });

export function usePasskeys() {
  return useQuery(passkeysQueryOptions());
}

/** Every route that changes passkeys or Enforce also changes `/me` and the session list (`ended_sessions`). Pure, so a test can see which keys it drops. */
export function refreshSecurity(queryClient: QueryClient) {
  return Promise.all([
    queryClient.invalidateQueries({queryKey: passkeyKeys.list}),
    queryClient.invalidateQueries({queryKey: meKeys.all}),
    queryClient.invalidateQueries({queryKey: sessionKeys.list}),
  ]);
}

/** The mutations as plain options, for the hooks below and for tests that run them without a DOM. */
export function passkeyMutationOptions(queryClient: QueryClient) {
  const onSuccess = () => refreshSecurity(queryClient);
  return {
    /** Begin, the browser prompt, finish. Needs a live reauth. Resolves to `PasskeyAdded`, with `ended_sessions`. */
    add: {mutationFn: (signal?: AbortSignal) => passkeyAdd({signal}), onSuccess},
    rename: {
      mutationFn: async ({id, name}: {id: string; name: string}) =>
        required(await api.PATCH("/account/passkeys/{id}", {params: {path: {id}}, body: {name}})),
      onSuccess,
    },
    remove: {
      mutationFn: async (id: string) => {
        await api.DELETE("/account/passkeys/{id}", {params: {path: {id}}});
      },
      onSuccess,
    },
    /** `POST /account/passkeys/review`: the user has looked at the list (AUTH 7.7). */
    review: {
      mutationFn: async () => {
        await api.POST("/account/passkeys/review", {body: {}});
      },
      onSuccess,
    },
    /** `PUT /account/passkey-enforcement`. Resolves to `SessionsEnded`. */
    enforce: {
      mutationFn: async (enabled: boolean) => required(await api.PUT("/account/passkey-enforcement", {body: {enabled}})),
      onSuccess,
    },
  };
}

export function useAddPasskey() {
  return useMutation(passkeyMutationOptions(useQueryClient()).add);
}

export function useRenamePasskey() {
  return useMutation(passkeyMutationOptions(useQueryClient()).rename);
}

export function useDeletePasskey() {
  return useMutation(passkeyMutationOptions(useQueryClient()).remove);
}

export function useReviewPasskeys() {
  return useMutation(passkeyMutationOptions(useQueryClient()).review);
}

export function useSetPasskeyEnforcement() {
  return useMutation(passkeyMutationOptions(useQueryClient()).enforce);
}
