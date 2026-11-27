import {infiniteQueryOptions, useInfiniteQuery, useMutation, useQueryClient} from "@tanstack/react-query";

import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";

// Spec 13.1. Users, newest first, found by a phone prefix. No log data (D19).

type S = components["schemas"];
export type AdminUserRow = S["AdminUserRow"];
export type CreateUserRequest = S["CreateUserRequest"];
export type UserCreated = S["UserCreated"];

export const USERS_PAGE_SIZE = 50;

export const userKeys = {all: ["admin", "users"] as const, list: (q: string) => ["admin", "users", "list", q] as const};

export const usersQueryOptions = (q: string) =>
  infiniteQueryOptions({
    queryKey: userKeys.list(q),
    queryFn: async ({pageParam, signal}) =>
      required(await adminApi.GET("/users", {params: {query: {...(q ? {q} : {}), cursor: pageParam, limit: USERS_PAGE_SIZE}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    retry: shouldRetry,
  });

/**
 * `q` is the phone prefix as typed: the API reads every accepted form of a number. `enabled` is false for text that cannot
 * start a number, which the API would refuse with 400 validation_failed (the page says "not a number" instead).
 */
export function useUsers(q: string, enabled = true) {
  return useInfiniteQuery({...usersQueryOptions(q.trim()), enabled});
}

/**
 * `POST /users`. The answer holds the one-time password, shown once: the caller moves it into its own state at
 * once and resets the mutation, so nothing of it stays in the cache.
 */
export function useCreateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: CreateUserRequest) => required(await adminApi.POST("/users", {body})),
    // Not returned: TanStack awaits what onSuccess returns, and an invalidation resolves only when every loaded page of the
    // list has been fetched again, so the one-time password, which exists and cannot be shown again, would wait behind an
    // unrelated refresh (and be lost if the admin closed the dialog meanwhile) (wp10-r6-2).
    onSuccess: () => {
      void queryClient.invalidateQueries({queryKey: userKeys.all});
    },
  });
}
