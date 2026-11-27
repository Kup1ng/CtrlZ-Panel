import {infiniteQueryOptions, queryOptions, useInfiniteQuery, useMutation, useQuery, useQueryClient, type InfiniteData, type QueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import {noteLockedProfile, optimistic} from "./optimistic.ts";
import {profileKeys} from "./profileKeys.ts";
import {filterKey, isUuid, jobOr, newIdempotencyKey, nextCursor, PAGE_LIMIT, type JobOr} from "./support.ts";

// Spec p2 9.6. Rules and folders: the cursor-paged list (10,000 rules is the ceiling of a profile, so it is a virtual list over
// pages, never one request), the one-rule writes behind the row's hover actions, the batch that selection mode sends, and the
// folder routes with Export Rules and Upload Folder.

export type Rule = components["schemas"]["Rule"];
export type RulePage = components["schemas"]["RulePage"];
export type RuleAction = Rule["action"];
export type RulesCreate = components["schemas"]["RulesCreate"];
export type RulePatch = components["schemas"]["RulePatch"];
export type RulesBatch = components["schemas"]["RulesBatch"];
export type RuleTransfer = components["schemas"]["RuleTransfer"];
export type RuleSelector = components["schemas"]["RuleSelector"];
export type BatchResult = components["schemas"]["BatchResult"];
export type Folder = components["schemas"]["Folder"];
export type FolderCreate = components["schemas"]["FolderCreate"];
export type FolderPatch = components["schemas"]["FolderPatch"];
export type RulesDocument = components["schemas"]["RulesDocument"];

/** What the list filters on: the folder (`root` is the top level; an id is a folder), the search, the status, the action and the sort. */
export type RuleFilter = {
  folder?: string;
  q?: string;
  status?: "enabled" | "disabled" | "expired";
  action?: RuleAction;
  sort?: "pattern" | "created" | "updated";
};

/** The rules of a profile in a view, `PAGE_LIMIT` a page. `filterKey` keeps one cache entry per view. */
export const ruleListQuery = (profileId: string | undefined, filter: RuleFilter = {}) =>
  infiniteQueryOptions({
    queryKey: profileKeys.rules(profileId ?? "", filterKey(filter)),
    queryFn: async ({pageParam, signal}) =>
      required(
        await api.GET("/profiles/{id}/rules", {
          params: {path: {id: profileId!}, query: {...filter, ...(pageParam ? {cursor: pageParam} : {}), limit: PAGE_LIMIT}},
          signal,
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
    enabled: isUuid(profileId),
    retry: shouldRetry,
  });

/**
 * The rules of a view. With `keepPrevious` the list that was on screen stays (with `isPlaceholderData` true) while another filter of the SAME
 * profile and folder loads, so a search does not turn the list into skeletons at each change.
 */
export function useRules(profileId: string | undefined, filter: RuleFilter = {}, options: {keepPrevious?: boolean} = {}) {
  const base = ruleListQuery(profileId, filter);
  const query = useInfiniteQuery({
    ...base,
    ...(options.keepPrevious
      ? {
          placeholderData: (previous: InfiniteData<RulePage, string | undefined> | undefined, previousQuery: {queryKey: readonly unknown[]} | undefined) =>
            previousQuery && previousQuery.queryKey[1] === profileId && sameScope(folderOfKey(previousQuery.queryKey[2]), filter.folder ?? "") ? previous : undefined,
        }
      : {}),
  });
  return {...query, rules: flattenRules(query.data)};
}

/** A search on the top level leaves `folder=root` for no folder at all (every rule): the same list for the eye. Another folder is another list. */
const sameScope = (a: string, b: string): boolean => a === b || ((a === "" || a === "root") && (b === "" || b === "root"));

/** One `name=` part of a list key (`filterKey`), or the empty string. */
const partOfKey = (key: unknown, name: string): string => (typeof key === "string" ? (new RegExp(`(?:^|&)${name}=([^&]*)`).exec(key)?.[1] ?? "") : "");
const folderOfKey = (key: unknown): string => partOfKey(key, "folder");

export const flattenRules = (data: InfiniteData<RulePage, unknown> | undefined): Rule[] => data?.pages.flatMap((p) => p.items) ?? [];

/** Rules of every loaded page, with the ones `change` names replaced. For an optimistic write; the argument is not changed. */
export function mapRulePages(data: InfiniteData<RulePage, unknown>, change: (rule: Rule) => Rule): InfiniteData<RulePage, unknown> {
  return {...data, pages: data.pages.map((page) => ({...page, items: page.items.map(change)}))};
}

/** The pages without the rule `id`. The next page still follows from the last row (a cursor is a key, not an offset). */
const withoutRule = (data: InfiniteData<RulePage, unknown>, id: string): InfiniteData<RulePage, unknown> => ({
  ...data,
  pages: data.pages.map((page) => ({...page, items: page.items.filter((r) => r.id !== id)})),
});

/**
 * The pages with the rule's switch set. A view filtered by state (`filter` is its `filterKey`) no longer holds a rule that the switch moved out
 * of it, and its pages are not asked for again, so the row leaves them here: the list, the header and Select All then say what the server's
 * selector would match.
 */
export function applySwitch(data: InfiniteData<RulePage, unknown>, ruleId: string, enabled: boolean, filter: unknown): InfiniteData<RulePage, unknown> {
  const changed = mapRulePages(data, (r) => (r.id === ruleId ? {...r, enabled} : r));
  const status = partOfKey(filter, "status");
  return (status === "enabled" && !enabled) || (status === "disabled" && enabled) ? withoutRule(changed, ruleId) : changed;
}

export type PatchRuleVars = {profileId: string; ruleId: string; patch: RulePatch};

/**
 * `PATCH /profiles/{id}/rules/{rule_id}`. Only the switch (`enabled`) is shown before the answer: a pattern, an action or a folder
 * change can be refused for reasons only the server knows (`iranian_name`, the location set), so those wait for it.
 */
export function usePatchRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, ruleId, patch}: PatchRuleVars) =>
      required(await api.PATCH("/profiles/{id}/rules/{rule_id}", {params: {path: {id: profileId, rule_id: ruleId}}, body: patch})),
    ...optimistic<PatchRuleVars>({
      queryClient,
      keys: (v) => [profileKeys.rulesOf(v.profileId)],
      apply: (data, v, key) => {
        if (v.patch.enabled === undefined) return undefined;
        return applySwitch(data as InfiniteData<RulePage, unknown>, v.ruleId, v.patch.enabled, key[2]);
      },
      // A switch is already on screen: the loaded pages are marked stale and not asked for again (a list scrolled to row 5,000 is 50 requests, and
      // the read budget is shared with every other read). A pattern, action or folder change is the server's to decide, so those read the list again.
      settle: (v) => (switchOnly(v.patch) ? [] : [profileKeys.rulesOf(v.profileId), profileKeys.folders(v.profileId)]),
      quiet: (v) => (switchOnly(v.patch) ? [profileKeys.rulesOf(v.profileId)] : []),
      onFail: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
    }),
  });
}

const switchOnly = (patch: RulePatch): boolean => Object.keys(patch).length === 1 && patch.enabled !== undefined;

/**
 * The profile's own counts (`counts.rules`) and the list of profiles move with every write of a rule or a folder. The open page's header,
 * `Select all N` and the delete confirmation read them, so they are asked for again: one request.
 */
function refreshProfileCounts(queryClient: QueryClient, profileId: string): void {
  void queryClient.invalidateQueries({queryKey: profileKeys.detail(profileId)});
  void queryClient.invalidateQueries({queryKey: profileKeys.list});
}

/** `POST /profiles/{id}/rules`: one or more patterns (at most 1,000), one rule each (a Geo Rule dialog with several rows is several rules). */
export function useCreateRules() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, ...body}: {profileId: string} & RulesCreate) =>
      required(await api.POST("/profiles/{id}/rules", {params: {path: {id: profileId}}, body})).rules,
    onSuccess: (_rules, v) => {
      void queryClient.invalidateQueries({queryKey: profileKeys.rulesOf(v.profileId)});
      void queryClient.invalidateQueries({queryKey: profileKeys.folders(v.profileId)});
      refreshProfileCounts(queryClient, v.profileId);
    },
    onError: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
  });
}

/** `DELETE /profiles/{id}/rules/{rule_id}`; the row goes at once. */
export function useDeleteRule() {
  const queryClient = useQueryClient();
  type Vars = {profileId: string; ruleId: string};
  return useMutation({
    mutationFn: async ({profileId, ruleId}: Vars) => {
      await api.DELETE("/profiles/{id}/rules/{rule_id}", {params: {path: {id: profileId, rule_id: ruleId}}});
    },
    ...optimistic<Vars>({
      queryClient,
      keys: (v) => [profileKeys.rulesOf(v.profileId)],
      apply: (data, v) => withoutRule(data as InfiniteData<RulePage, unknown>, v.ruleId),
      // The row is gone from every loaded page already, and the next page still follows from the last row (a cursor is a key, not an offset), so
      // the pages are only marked stale. The folders and the profile's counts moved, and are asked for again.
      settle: (v) => [profileKeys.folders(v.profileId), profileKeys.detail(v.profileId), profileKeys.list],
      quiet: (v) => [profileKeys.rulesOf(v.profileId)],
      onFail: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
    }),
  });
}

/** `POST /profiles/{id}/rules/{rule_id}:transfer`: Copy or Move of one rule, with the batch semantics of one id (spec p2 8.3). */
export function useTransferRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, ruleId, ...body}: {profileId: string; ruleId: string} & RuleTransfer) =>
      required(await api.POST("/profiles/{id}/rules/{rule_id}:transfer", {params: {path: {id: profileId, rule_id: ruleId}}, body})),
    onSettled: (_data, error, v) => {
      void queryClient.invalidateQueries({queryKey: profileKeys.all});
      void queryClient.invalidateQueries({queryKey: ["profile-rules"]});
      void queryClient.invalidateQueries({queryKey: ["profile-folders"]});
      noteLockedProfile(queryClient, v.profileId, error);
    },
  });
}

/**
 * `POST /profiles/{id}/rules:batch`: what selection mode sends (Copy, Move, Edit, Enable, Disable, Delete). A selection is `ids`, or a
 * `selector` over the current filter for Select All, never a list of the rows that happen to be loaded. Above 1,000 items the answer
 * is a job. One `key` for the action: a retry that passes the same key is a replay and not a second effect.
 */
export function useBatchRules() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, key, ...body}: {profileId: string; key?: string} & RulesBatch): Promise<JobOr<BatchResult>> =>
      jobOr(
        await api.POST("/profiles/{id}/rules:batch", {
          params: {path: {id: profileId}, header: {"Idempotency-Key": key ?? newIdempotencyKey()}},
          body,
        }),
      ),
    onSettled: (_data, error, v) => {
      void queryClient.invalidateQueries({queryKey: ["profile-rules"]});
      void queryClient.invalidateQueries({queryKey: ["profile-folders"]});
      refreshProfileCounts(queryClient, v.profileId);
      noteLockedProfile(queryClient, v.profileId, error);
    },
  });
}

export const folderListQuery = (profileId: string | undefined) =>
  queryOptions({
    queryKey: profileKeys.folders(profileId ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/profiles/{id}/folders", {params: {path: {id: profileId!}}, signal})).folders,
    enabled: isUuid(profileId),
    retry: shouldRetry,
  });

export function useFolders(profileId: string | undefined) {
  return useQuery(folderListQuery(profileId));
}

export function useCreateFolder() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, ...body}: {profileId: string} & FolderCreate) =>
      required(await api.POST("/profiles/{id}/folders", {params: {path: {id: profileId}}, body})),
    onSuccess: (_folder, v) => {
      void queryClient.invalidateQueries({queryKey: profileKeys.folders(v.profileId)});
    },
    onError: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
  });
}

export function usePatchFolder() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, folderId, ...body}: {profileId: string; folderId: string} & FolderPatch) =>
      required(await api.PATCH("/profiles/{id}/folders/{folder_id}", {params: {path: {id: profileId, folder_id: folderId}}, body})),
    onSuccess: (_folder, v) => {
      void queryClient.invalidateQueries({queryKey: profileKeys.folders(v.profileId)});
      void queryClient.invalidateQueries({queryKey: profileKeys.rulesOf(v.profileId)});
    },
    onError: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
  });
}

/** `DELETE /profiles/{id}/folders/{folder_id}`: the folder and the rules in it. */
export function useDeleteFolder() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, folderId}: {profileId: string; folderId: string}) => {
      await api.DELETE("/profiles/{id}/folders/{folder_id}", {params: {path: {id: profileId, folder_id: folderId}}});
    },
    onSuccess: (_x, v) => {
      // The lists of the deleted folder are left alone: the folder page is still on screen for a moment, and a list that is marked stale and read
      // again would ask the server for the rules of a folder that is gone (a 404, and a "list may be old" line over the rows). Every other list is.
      void queryClient.invalidateQueries({queryKey: profileKeys.folders(v.profileId)});
      void queryClient.invalidateQueries({queryKey: profileKeys.rulesOf(v.profileId), predicate: (query) => folderOfKey(query.queryKey[2]) !== v.folderId});
      refreshProfileCounts(queryClient, v.profileId);
    },
    onError: (error, v) => noteLockedProfile(queryClient, v.profileId, error),
  });
}

/** `GET /profiles/{id}/folders/{folder_id}/export`: Export Rules, the rules document of one folder. */
export async function fetchFolderDocument(profileId: string, folderId: string): Promise<RulesDocument> {
  return required(await api.GET("/profiles/{id}/folders/{folder_id}/export", {params: {path: {id: profileId, folder_id: folderId}}}));
}

export function useExportFolderRules() {
  return useMutation({mutationFn: ({profileId, folderId}: {profileId: string; folderId: string}) => fetchFolderDocument(profileId, folderId)});
}

/** `POST /profiles/{id}/folders/{folder_id}:upload`: Upload Folder, `document` as base64, merged with `new_only` (the default) or `upsert`. */
export function useUploadFolderRules() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({profileId, folderId, document, mode, key}: {profileId: string; folderId: string; document: string; mode?: "new_only" | "upsert"; key?: string}): Promise<JobOr<BatchResult>> =>
      jobOr(
        await api.POST("/profiles/{id}/folders/{folder_id}:upload", {
          params: {path: {id: profileId, folder_id: folderId}, header: {"Idempotency-Key": key ?? newIdempotencyKey()}},
          body: mode ? {document, mode} : {document},
        }),
      ),
    onSettled: (_data, error, v) => {
      void queryClient.invalidateQueries({queryKey: profileKeys.rulesOf(v.profileId)});
      void queryClient.invalidateQueries({queryKey: profileKeys.folders(v.profileId)});
      refreshProfileCounts(queryClient, v.profileId);
      noteLockedProfile(queryClient, v.profileId, error);
    },
  });
}

/** A search a person typed, as the API wants it: trimmed, with no more than 253 characters (the longest name). */
export const searchTerm = (input: string): string | undefined => {
  const q = input.trim().slice(0, 253);
  return q === "" ? undefined : q;
};
