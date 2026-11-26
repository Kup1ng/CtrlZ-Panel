// The fragment of a `hashchange`, taken from the event (gate-r21-1, -6, -7, -9).
//
// A link pasted into the address bar of a tab that is already on /invite is a same-document navigation: the browser
// fires `popstate` and then `hashchange`. Between the two, Next's router can write its own canonical URL (its
// HistoryUpdater commit after an earlier replaceState of ours), and that URL has no fragment. `location.hash` is empty
// by the time the `hashchange` listener runs, and the token is lost. The event's `newURL` was fixed when the navigation
// happened and keeps the fragment, so it is the one source that does not depend on the order of those two writers.

/** The fragment of the address a `hashchange` moved to, with its `#`, or the current one when the event carries no usable `newURL`. */
export function hashOfHashChange(newURL: unknown, currentHash: string): string {
  if (typeof newURL !== "string") return currentHash;
  try {
    return new URL(newURL).hash;
  } catch {
    return currentHash;
  }
}
