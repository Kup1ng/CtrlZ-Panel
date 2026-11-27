import {isErrorCode, type ErrorCode} from "@ctrlz/api-client/errors.ts";
import type {Job} from "@ctrlz/api-client/hooks/jobs.ts";

// What the job dialog shows, as pure functions (spec p2 3.5 and 9.6).

export type JobState = Job["state"];

export const isActive = (job: Pick<Job, "state"> | null | undefined): boolean => job?.state === "queued" || job?.state === "running";

const COUNTS = ["created", "updated", "skipped", "conflict", "flagged"] as const;
export type CountKey = (typeof COUNTS)[number];

/** The counts of a finished job's result that are above zero, in a fixed order. `flagged` is last: it is the one that asks for a look. */
export function resultLines(result: Job["result"] | undefined): {key: CountKey; count: number}[] {
  if (!result) return [];
  return COUNTS.flatMap((key) => (result[key] > 0 ? [{key, count: result[key]}] : []));
}

/**
 * The text key of a failed job's error. `job_attempts_exhausted` exists only in `Job.error` (spec p2 8.4) and has its own line in the
 * `jobs` namespace; any other code is one of the API's (`errors.<code>`), and one this client does not know is `unknown`.
 */
export function jobErrorText(error: Job["error"] | undefined): {namespace: "jobs"; key: "error.job_attempts_exhausted"} | {namespace: "errors"; key: ErrorCode} {
  const code = error?.code;
  if (code === "job_attempts_exhausted") return {namespace: "jobs", key: "error.job_attempts_exhausted"};
  return {namespace: "errors", key: isErrorCode(code) ? code : "unknown"};
}

/** The pointers of a failed Import or Upload (`/rules/12/pattern`) with the code of each, at most `max`: they are shown in `Tech`. */
export function jobFields(error: Job["error"] | undefined, max = 100): {name: string; code: string}[] {
  const fields = (error as {fields?: {name?: unknown; code?: unknown}[]} | undefined)?.fields;
  if (!Array.isArray(fields)) return [];
  return fields
    .filter((f): f is {name: string; code: string} => typeof f?.name === "string" && typeof f?.code === "string" && f.name.length <= 128)
    .slice(0, max);
}

/**
 * The job a resumed dialog follows: the id it was given, else the one kept from the first answer of `GET /jobs/active` since the dialog
 * opened. The active query turns to `null` the moment the job ends (`invalidateAfterJob` reads it again), and a dialog that followed the
 * query would lose its job, and with it the counts and the failure the person is waiting for. `fresh` is an answer that is not a
 * leftover of the previous job (the dialog passes it only when no fetch is under way).
 */
export function followedJobId(latched: string | undefined, given: string | undefined, fresh: string | undefined): string | undefined {
  return given ?? latched ?? fresh;
}
