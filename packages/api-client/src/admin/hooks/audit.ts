import {infiniteQueryOptions, useInfiniteQuery} from "@tanstack/react-query";

import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";

// Spec 13.5. The admin audit log, newest first, read only, filtered by an exact action name.

export type AuditRow = components["schemas"]["AuditRow"];

export const auditKeys = {list: (action: string) => ["admin", "audit", action] as const};

export const auditQueryOptions = (action: string) =>
  infiniteQueryOptions({
    queryKey: auditKeys.list(action),
    queryFn: async ({pageParam, signal}) =>
      required(await adminApi.GET("/audit", {params: {query: {...(action ? {action} : {}), cursor: pageParam, limit: 50}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    retry: shouldRetry,
  });

/** `action` is an exact name (`^[a-z][a-z0-9_.-]*$`); the screen checks the shape before it asks. */
export function useAudit(action: string) {
  return useInfiniteQuery(auditQueryOptions(action));
}

/** The shape the API accepts for the filter. Anything else is not sent, so the call can never be a 400. */
export const AUDIT_ACTION_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
