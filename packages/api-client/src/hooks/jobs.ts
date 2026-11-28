import {queryOptions, useQuery, useQueryClient, type QueryClient} from "@tanstack/react-query";
import {useEffect, useRef} from "react";

import {isUserPresent} from "../activity.ts";
import {api} from "../client.ts";
import {required} from "../core.ts";
import {isApiError} from "../errors.ts";
import {shouldRetry} from "../queryDefaults.ts";
import {endpointKeys, jobKeys, profileKeys} from "./profileKeys.ts";
import type {Job} from "./support.ts";

// Spec p2 3.5 and 9.6. A request of more than 1,000 items is answered 202 with a Job. The screen shows its state from
// `GET /jobs/{id}`, polled every 2 seconds until it is `done` or `failed`; a job dialog that opens, or meets `409 job_running`,
// reads `GET /jobs/active` and resumes polling that job. There is no percentage: `progress` moves only at commit.

export type {Job};

export const JOB_POLL_MS = 2_000;

export const isJobFinished = (job: Pick<Job, "state"> | undefined): boolean => job?.state === "done" || job?.state === "failed";

/**
 * An answer that repeating the question cannot change (S1-r2-5): the job is gone (404, swept after 24 hours or cascaded away with its
 * profile) or the request is refused for good (any other 4xx). 408 and 429 are the two 4xx that say "later", and a 5xx or a network
 * error is retried by the query's own rule.
 */
export const isTerminalJobError = (error: unknown): boolean =>
  isApiError(error) && error.status >= 400 && error.status < 500 && error.status !== 408 && error.status !== 429;

/**
 * The refetch interval of a job: 2 s while it runs and a person is at the page (the same presence gate as the bell, activity.ts),
 * and never once it has ended or the API has said that there is no such job. A job that has ended is not asked for again.
 */
export const jobRefetchInterval = (job: Job | undefined, error?: unknown): number | false => {
  if (isJobFinished(job) || isTerminalJobError(error)) return false;
  return isUserPresent() ? JOB_POLL_MS : false;
};

export const activeJobQueryOptions = () =>
  queryOptions({
    queryKey: jobKeys.active,
    queryFn: async ({signal}) => required(await api.GET("/jobs/active", {signal})).job ?? null,
    retry: shouldRetry,
    // Asked when a dialog opens, not on a timer: a tenant has at most one job, and the dialog that started it holds its id.
    staleTime: 0,
  });

/** The job the tenant has queued or running, or `null`. Turn it on only while a job dialog is open or after a 409 `job_running`. */
export function useActiveJob(options: {enabled?: boolean} = {}) {
  return useQuery({...activeJobQueryOptions(), enabled: options.enabled ?? true});
}

export const jobQuery = (id: string | undefined) =>
  queryOptions({
    queryKey: jobKeys.one(id ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/jobs/{id}", {params: {path: {id: id!}}, signal})),
    enabled: id !== undefined,
    retry: shouldRetry,
    refetchInterval: (query) => jobRefetchInterval(query.state.data, query.state.error),
  });

/**
 * What a job that has ended changed: the profile list and counters, the profile's rules, folders and the rest. Everything of the
 * profile family is read again, because a job does not say which of them it touched.
 */
export function invalidateAfterJob(queryClient: QueryClient, job: Job): void {
  void queryClient.invalidateQueries({queryKey: profileKeys.all});
  if (job.profile_id) {
    void queryClient.invalidateQueries({queryKey: profileKeys.rulesOf(job.profile_id)});
    void queryClient.invalidateQueries({queryKey: profileKeys.folders(job.profile_id)});
  } else {
    // A rules batch or an upload does not name a profile in the job, so every list of rules is stale.
    void queryClient.invalidateQueries({queryKey: ["profile-rules"]});
    void queryClient.invalidateQueries({queryKey: ["profile-folders"]});
  }
  void queryClient.invalidateQueries({queryKey: endpointKeys.all});
  void queryClient.invalidateQueries({queryKey: jobKeys.active});
}

/**
 * Follows one job. `id` is `undefined` before there is a job, and the query is off. When the state turns to `done` or `failed` the
 * caches that the job may have changed are marked stale, once.
 */
export function useJob(id: string | undefined) {
  const queryClient = useQueryClient();
  const query = useQuery(jobQuery(id));
  const finished = isJobFinished(query.data);
  const handled = useRef<string | null>(null);
  const job = query.data;
  useEffect(() => {
    if (!finished || !job || handled.current === job.id) return;
    handled.current = job.id;
    invalidateAfterJob(queryClient, job);
  }, [finished, job, queryClient]);
  return query;
}
