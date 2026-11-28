import type {Mutation, QueryClient, QueryKey} from "@tanstack/react-query";

import {hasCode} from "../errors.ts";
import {sessionGuard} from "../sessionEnd.ts";
import {profileKeys} from "./profileKeys.ts";

// The one pattern of every switch of P2 and P3 (a filter, a service, a rule, an option, an Endpoint's state): the screen answers
// at once, the write goes out, and a refusal puts the old value back. TanStack's own recipe, written once so that a lane does not
// write its own and forget one of the three steps (cancel what is in flight, remember, restore).
//
// The data of a query is changed with `setQueriesData` under a key PREFIX, so a list that was loaded with filters and pages
// (rules of a folder, endpoints of a group) is changed wherever the row is. `apply` gets the cached value and returns the new
// one, or `undefined` to leave it alone; it must not mutate its argument.

type Snapshot = [QueryKey, unknown][];

export type OptimisticContext = {snapshot: Snapshot; alive: () => boolean};

type Keys<TVars> = readonly QueryKey[] | ((variables: TVars) => readonly QueryKey[]);

export type OptimisticSpec<TVars> = {
  queryClient: QueryClient;
  /** The prefix of every query that may hold the row. A function of the variables when the key holds the id of a profile or an Endpoint. */
  keys: Keys<TVars>;
  /** The new cached value of one query of those; `queryKey` is that query's own key, for a view that depends on its filter. `undefined` keeps it. */
  apply: (current: unknown, variables: TVars, queryKey: QueryKey) => unknown;
  /** What to refetch when the write has ended, whatever its answer. Defaults to `keys`. */
  settle?: Keys<TVars>;
  /**
   * Queries the screen already shows right (a switch it flipped before the write): after a good write they are only marked stale, so the next
   * mount or focus reads them again but nothing asks for them now. A list of 50 loaded pages would otherwise be asked for 50 times per switch.
   * After a refused write they are refetched like `settle`, since the server's state is then not what the screen showed.
   */
  quiet?: Keys<TVars>;
  /** Runs after the old values are back, with the error: where a guarded write calls `noteLockedProfile`. */
  onFail?: (error: unknown, variables: TVars) => void;
};

const keysOf = <TVars,>(keys: Keys<TVars>, variables: TVars): readonly QueryKey[] => (typeof keys === "function" ? keys(variables) : keys);

/**
 * `onMutate`, `onError` and `onSettled` of a mutation whose result the screen shows before the server has answered.
 * Spread them into `useMutation({mutationFn, ...optimistic({...})})`.
 */
export function optimistic<TVars>(spec: OptimisticSpec<TVars>) {
  const {queryClient, keys, apply, settle, quiet, onFail} = spec;
  return {
    async onMutate(variables: TVars): Promise<OptimisticContext> {
      // A write that answers after its session ended must not put the old person's values back into the next person's cache (S2-r2-7):
      // `queryClient.clear()` does not stop a mutation in flight, so its callbacks ask this before they touch the cache.
      const alive = sessionGuard();
      const list = keysOf(keys, variables);
      await Promise.all(list.map((queryKey) => queryClient.cancelQueries({queryKey})));
      const snapshot: Snapshot = list.flatMap((queryKey) => queryClient.getQueriesData({queryKey}));
      for (const prefix of list) {
        for (const [queryKey, current] of queryClient.getQueriesData({queryKey: prefix})) {
          if (current === undefined) continue;
          const next = apply(current, variables, queryKey);
          if (next !== undefined) queryClient.setQueryData(queryKey, next);
        }
      }
      return {snapshot, alive};
    },
    onError(error: unknown, variables: TVars, context: OptimisticContext | undefined) {
      if (context && !context.alive()) return;
      for (const [queryKey, data] of context?.snapshot ?? []) queryClient.setQueryData(queryKey, data);
      onFail?.(error, variables);
    },
    onSettled(_data: unknown, error: unknown, variables: TVars, context?: OptimisticContext) {
      if (context && !context.alive()) return;
      for (const queryKey of keysOf(settle ?? keys, variables)) void queryClient.invalidateQueries({queryKey});
      if (quiet) {
        for (const queryKey of keysOf(quiet, variables)) void queryClient.invalidateQueries(error ? {queryKey} : {queryKey, refetchType: "none"});
      }
    },
  };
}

/** Maps the rows of one list page by page: the shape of an infinite query (`{pages, pageParams}`) or a plain array or a `{items}` object. */
export function mapRows<T>(current: unknown, pick: (page: unknown) => T[] | undefined, put: (page: unknown, rows: T[]) => unknown, change: (row: T) => T): unknown {
  if (current === null || typeof current !== "object") return current;
  const infinite = current as {pages?: unknown[]; pageParams?: unknown[]};
  if (Array.isArray(infinite.pages)) {
    return {...infinite, pages: infinite.pages.map((page) => mapRows(page, pick, put, change))};
  }
  const rows = pick(current);
  return rows === undefined ? current : put(current, rows.map(change));
}

/**
 * A write refused with 423 `profile_locked` means the page's copy of the profile is out of date: somebody locked it. The profile is
 * read again so the lock banner shows and every control disables (spec 9.8). Every guarded write calls this from its `onError`.
 */
export function noteLockedProfile(queryClient: QueryClient, profileId: string, error: unknown): void {
  if (hasCode(error, "profile_locked")) {
    void queryClient.invalidateQueries({queryKey: profileKeys.detail(profileId)});
    void queryClient.invalidateQueries({queryKey: profileKeys.list});
  }
}

/** For tests and for screens that wait on a write: whether a mutation is of the given key. */
export function mutationHasKey(mutation: Mutation, head: string): boolean {
  return mutation.options.mutationKey?.[0] === head;
}
