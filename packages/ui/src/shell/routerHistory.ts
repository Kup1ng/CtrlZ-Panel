// A write to the address bar from a mount effect has to wait for Next's router (gate-r21-9).
//
// React runs a child's effects before its parent's, and all the passive effects of one commit in a single flush. On the first
// load the effect of a page component therefore runs before AppRouter's effect has put its own `history.replaceState` in place,
// so a write made from the page reaches the browser's native one. The entry then loses the router's marker (`__NA`) and a Back to
// it is not restored by the router, which leaves the URL of one page on the screen of another; and the router's own canonical URL
// is never told of the change, so a later commit that keeps the URL writes the old address (a fragment with an invite code in it)
// back into the bar. Next's patched `replaceState` copies the marker and tells the router, so the write goes through it.
//
// There is no reliable way to ask whether the patch is installed (the 17.2 guard wraps `replaceState` from the start of the
// document, and so may an extension), so the write is made one task later: the flush that ran this effect has ended by then, and
// the router, an ancestor of every page, is in the same commit or an earlier one.

/**
 * Replaces the current history entry with the address `target` returns, one task from now, through whatever `replaceState` is then
 * on `window.history` (the router's). `target` is asked at that moment and not when this is called, so it reads the address as it
 * is then, and may return null for "no write needed". Returns a function that cancels a write that has not happened yet.
 */
export function replaceUrlAfterRouterMount(target: () => string | null): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
    timer = undefined;
    const next = target();
    if (next !== null) window.history.replaceState(null, "", next);
  }, 0);
  return () => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
  };
}
