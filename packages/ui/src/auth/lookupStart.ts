// Which link the invite page has started a lookup for (gate-r31). The page numbers its links in state: every link that is
// taken (the load, a pasted `hashchange`) is a new number, and the effect that starts the lookup claims its number here.
//
// Why a number and not a flag that the `hashchange` listener resets: the listener runs outside React's render and commit
// order. An effect that was queued by the render with the old link, and that React flushes before it renders the new one,
// would find a reset flag, spend it on the old code (the lookup drops it as the same code already on the wire) and leave
// the new link without a lookup, so the old invite's number would sit on a page whose token is the new one (wp8-r6-2).
// A stale effect carries the old number, which was claimed already, so it cannot spend the new link's turn.
export function createLookupStart() {
  let started = -1;
  return {
    /** True once per link number: the caller starts the lookup. A second call with the same number is a repeat. */
    claim(link: number): boolean {
      if (started === link) return false;
      started = link;
      return true;
    },
  };
}
