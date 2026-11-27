"use client";

import {onSessionEnd} from "@ctrlz/api-client/sessionEnd.ts";
import {useSyncExternalStore} from "react";

import type {JobTarget} from "./jobTarget.ts";

// The job that a profile dialog started (Import, Duplicate) and the screen is still following, S1-r1-1. It is a small store like
// `newProfile.ts` and not state of `ProfileDialogs`, for two reasons: closing the job dialog ("keep going in the background") must not
// stop the follower that shows the Bypass toast and marks the new profile when the job ends, and the follower must survive the move from a
// profile's page (Duplicate) to the list, which are two mounts of `ProfileDialogs`. `open` says whether the job dialog is on screen, and
// `jobId` is filled in for a resumed job as soon as `GET /jobs/active` has named it.
//
// A module store outlives the screen that made it, and two things follow from that (S1-r2-1, S1-r2-4):
//   - `open` belongs to the mount that opened the dialog (`owner`). A later mount of the screen finds an `open` that is not its own and
//     closes it, so a dialog the person left behind does not come back, and the job is still followed. It is the owner and not an
//     unmount effect that decides, because React StrictMode runs a mount's effects, their cleanups and the effects again at once.
//   - the ids of the jobs whose end has been handled are kept here and not in a ref of the follower, so a new mount does not toast and
//     mark a second time for a job it finds already done in the cache.
// Both, and the entry itself, belong to one session: they are dropped with the rest of it (`onSessionEnd`).

export type FollowedJobEntry = {jobId?: string; kind?: "import" | "duplicate"; open: boolean; owner: number};

let current: FollowedJobEntry | null = null;
let nextOwner = 0;
const handled = new Set<string>();
const listeners = new Set<() => void>();

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => void listeners.delete(listener);
};

function set(next: FollowedJobEntry | null): void {
  current = next;
  for (const listener of listeners) listener();
}

/** A number for one mount of `ProfileDialogs`, which says whose dialog an entry's `open` is. Take it once per mount (`useState`). */
export const newFollowOwner = (): number => ++nextOwner;

/** Starts following a job, with its dialog open and `owner`'s. */
export function followJob(target: JobTarget, owner: number): void {
  set({open: true, owner, ...(target.jobId ? {jobId: target.jobId} : {}), ...(target.kind ? {kind: target.kind} : {})});
}

/** Closes the job dialog and keeps following. */
export function closeJobDialog(): void {
  if (current?.open) set({...current, open: false});
}

/** A resumed job has been named by `GET /jobs/active`. */
export function resolveFollowedJob(jobId: string): void {
  if (current && current.jobId === undefined) set({...current, jobId});
}

/** The job has ended and its dialog is closed, or there is nothing to follow. */
export function stopFollowingJob(): void {
  if (current) set(null);
}

/** True the first time it is asked about a job, so that its end (toast, mark) is announced once however many mounts see it. */
export function takeJobOutcome(jobId: string): boolean {
  if (handled.has(jobId)) return false;
  handled.add(jobId);
  return true;
}

/** The session is over: nothing of the person who was signed in is followed or remembered (S1-r2-4). */
export function resetFollowedJob(): void {
  handled.clear();
  stopFollowingJob();
}

onSessionEnd(resetFollowedJob);

/** The entry right now, for code that is not a render (the tests, an effect that must not subscribe). */
export const peekFollowedJob = (): FollowedJobEntry | null => current;

export function useFollowedJob(): FollowedJobEntry | null {
  return useSyncExternalStore(subscribe, () => current, () => null);
}
