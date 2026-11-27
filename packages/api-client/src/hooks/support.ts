import type {components} from "../generated/panel";

// Small pieces every resource hook of P2 and P3 uses.

export type Job = components["schemas"]["Job"];

/** What a route that may queue a job answered: the result itself (200, 201), or the job that will make it (202, spec p2 3.5). */
export type JobOr<T> = {kind: "done"; data: T} | {kind: "job"; job: Job};

/**
 * Reads the answer of Import, Duplicate, Upload and `rules:batch`. Which of the two it is comes from the status and not from the
 * shape of the body, so a result that one day gains an `id` and `state` cannot be taken for a job.
 */
export function jobOr<T>(result: {data?: T | Job; response: {status: number}}): JobOr<T> {
  if (result.data === undefined) throw new Error("empty answer");
  return result.response.status === 202 ? {kind: "job", job: result.data as Job} : {kind: "done", data: result.data as T};
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * An id of a path. Every id of P2 and P3 is a UUID, and names never go in a path (Plan.md, the P2 note about escaped names), so a
 * value that is not one is a page that does not exist: the frame shows the 404 without asking the API, and no request carries it.
 */
export function isUuid(value: string | undefined): value is string {
  return value !== undefined && UUID.test(value);
}

/**
 * The header of the routes that need one (`rules:batch`, Upload, Import, Duplicate, `POST /endpoints`). One key for each action of the
 * person, made when the action starts and kept for a retry of the same action: the server answers a replay with the first answer and
 * a different request under the same key with `idempotency_key_reused`. 36 characters of `[0-9a-f-]`, inside the 1 to 64 of the schema.
 */
export function newIdempotencyKey(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * Filters of a list as ONE string, for a query key (a key part is never an object). The order of the names is fixed, so the same filters
 * always give the same key, and an empty or absent value is left out.
 */
export function filterKey(filter: Record<string, string | number | boolean | undefined | null>): string {
  return Object.keys(filter)
    .sort()
    .filter((k) => filter[k] !== undefined && filter[k] !== null && filter[k] !== "" && filter[k] !== false)
    .map((k) => `${k}=${String(filter[k])}`)
    .join("&");
}

/** The cursor of the next page, or `undefined` at the end. The one `getNextPageParam` of every list. */
export const nextCursor = (last: {next_cursor?: string}) => last.next_cursor;

export const PAGE_LIMIT = 100;
