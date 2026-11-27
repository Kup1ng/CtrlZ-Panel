"use client";

import {onSessionEnd} from "@ctrlz/api-client/sessionEnd.ts";
import {useEffect, useRef, useSyncExternalStore} from "react";

// T-136, spec p2 9.1. "A new profile is placed first with a highlight until the next load." The dialogs that make a profile (Add, Import,
// Duplicate) are not the list, and Duplicate is made from a profile's own page, so the id of the new profile is handed over through this
// one small store instead of through props. The list reads it, shows the row first with the highlight and the word "New" (a colour never
// stands alone), and drops it when the list page is left, which is the next load of the list.

let current: string | null = null;
const listeners = new Set<() => void>();

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => void listeners.delete(listener);
};

/** Marks the profile that was just made, or clears the mark with `null`. */
export function markNewProfile(id: string | null): void {
  if (current === id) return;
  current = id;
  for (const listener of listeners) listener();
}

// A profile id means something to one tenant, so the mark does not pass to the next session of this tab (S1-r2-4).
onSessionEnd(() => markNewProfile(null));

/** The mark right now, for code that is not a render. */
export const peekNewProfile = (): string | null => current;

/** The id of the profile made in this visit to the list, or `null`. */
export function useNewProfileId(): string | null {
  return useSyncExternalStore(subscribe, () => current, () => null);
}

/**
 * A cleanup that runs only when the screen is really left (S1-r3-2). React StrictMode, which `next dev` turns on, mounts a component, runs
 * its cleanup at once and runs the effect again; a mark cleared in that cleanup was gone before the person saw the list. `leave` therefore
 * only schedules the clear, and `enter` (the effect running again, in the same task) cancels it. A real unmount has no `enter` after it.
 */
export function createLeaveClear(clear: () => void): {enter: () => void; leave: () => void} {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return {
    enter: () => clearTimeout(timer),
    leave: () => {
      timer = setTimeout(clear, 0);
    },
  };
}

/** Drops the New mark when the list is left, which is "until the next load" of T-136, and not when StrictMode simulates a leave. */
export function useClearNewProfileOnLeave(): void {
  const guard = useRef<ReturnType<typeof createLeaveClear> | null>(null);
  useEffect(() => {
    guard.current ??= createLeaveClear(() => markNewProfile(null));
    const {enter, leave} = guard.current;
    enter();
    return leave;
  }, []);
}
