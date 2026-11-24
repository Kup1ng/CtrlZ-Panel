import {infiniteQueryOptions, useInfiniteQuery, useMutation, useQueryClient} from "@tanstack/react-query";

import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";

// Spec 13.2. Invites. A list never holds a code; the code and link come once, from the create call.

type S = components["schemas"];
export type InviteRow = S["InviteRow"];
export type CreateInviteRequest = S["CreateInviteRequest"];
export type InviteCreated = S["InviteCreated"];

export const INVITE_TTL_DEFAULT_HOURS = 72;
export const INVITE_TTL_MAX_HOURS = 720;

export const inviteKeys = {all: ["admin", "invites"] as const};

export const invitesQueryOptions = () =>
  infiniteQueryOptions({
    queryKey: inviteKeys.all,
    queryFn: async ({pageParam, signal}) => required(await adminApi.GET("/invites", {params: {query: {cursor: pageParam, limit: 50}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    retry: shouldRetry,
  });

export function useInvites() {
  return useInfiniteQuery(invitesQueryOptions());
}

export function useCreateInvite() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: CreateInviteRequest) => required(await adminApi.POST("/invites", {body})),
    // Not returned, for the same reason as useCreateUser: the invite code is shown once and must not wait for the list (wp10-r6-2).
    onSuccess: () => {
      void queryClient.invalidateQueries({queryKey: inviteKeys.all});
    },
  });
}

export function useRevokeInvite() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await adminApi.DELETE("/invites/{id}", {params: {path: {id}}});
    },
    onSettled: () => queryClient.invalidateQueries({queryKey: inviteKeys.all}),
  });
}
