// State that lives outside the QueryClient and belongs to the person who is signed in (S1-r2-4). A screen that keeps a small module store (the
// job the Profiles screen is following, the profile it marked as new) holds an id that means something to ONE tenant, and the tab's memory
// outlives a session in two ways that no page load wipes: the soft navigation to /login after the cookies expire (`resetLoginSession`) and the
// idle cover, which unmounts the page and clears the cache and then remounts the same tab for whoever presses Continue. The query cache is
// cleared by both; this registry is the same promise for the stores that are not in it. Every end of a session calls `runSessionEnd` next to
// its `queryClient.clear()`, so a store that registers here cannot be forgotten by one path.

const handlers = new Set<() => void>();

/** Registers what to forget when a session ends. Returns what unregisters it. */
export function onSessionEnd(handler: () => void): () => void {
  handlers.add(handler);
  return () => void handlers.delete(handler);
}

/** The session of this tab is over (logout, a new identity, cookies expired, idle cover): drop what belonged to it. */
export function runSessionEnd(): void {
  epoch++;
  for (const handler of [...handlers]) {
    try {
      handler();
    } catch {
      // One store failing to reset must not leave the others (or the logout that called this) half done.
    }
  }
}

// A request that was accepted before the session ended can still answer after it (S1-r3-5): `cancelQueries` does not touch a mutation, and
// the code after its `await` would write the old session's job id, New mark and toast into the next one. A caller takes a guard before it
// sends and asks it after the answer: once a session has ended in between, the answer is not the present person's and is dropped.
let epoch = 0;

/** Returns a function that says whether the session is still the one it was taken in. Take it before the `await`, ask it after. */
export function sessionGuard(): () => boolean {
  const taken = epoch;
  return () => taken === epoch;
}
