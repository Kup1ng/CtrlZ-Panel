"use client";

import {useSearchParams} from "next/navigation";
import {useEffect, useRef} from "react";

import {accountRowOf, ROW_LINK_EVENT, type SecurityActionId} from "../shell/securityNotice.ts";

// A security notice (Question 19) links to `/preferences/account#password`, `#sessions` and the rows that undo a passkey or new
// recovery codes. The page has no anchors of its own: its rows carry `data-row-id`, so the fragment is looked up there, the row
// is scrolled into view and its first control takes the focus, which is where a person who was told "change your password"
// wants to be. Only the row ids of securityNotice.ts are accepted, so a fragment typed by hand cannot select anything else with
// a selector.
//
// The search parameters are a dependency because the bell's dialog closes by dropping its parameter, and that is the moment the
// page under it should move; `pushState` fires no `hashchange`. But the fragment stays in the address bar, and `useUrlDialog`
// keeps it on every open and close of every dialog, so the effect also runs for each of those. A fragment is therefore acted on
// once, until the address has no row fragment again or names another row: otherwise opening Manage on the sessions row would
// scroll the page behind the modal and focus a button outside its focus trap, and closing it would leave the focus on the
// first button of the row instead of on the button that opened the dialog (webi-r1-1). A `hashchange` is a person's own
// navigation (the address bar, a link to the same page), so that one is always acted on.
//
// A link of a notice to the row the page is already at fires no `hashchange` and changes nothing in the address (a link in the
// bell drops only its own search parameter), so the link announces itself (ROW_LINK_EVENT) and the row it names is moved to
// again (webi-r2-2). From the open bell the move waits until the dialog has closed, because the focus must not go to a button
// behind a modal; the Escape key closes the bell too and is not a link, so it moves nothing.

/**
 * The row to move to, and what to remember afterwards. A pure function, so the rule is tested without a browser: `handled` is
 * the row the page already moved to for the fragment that is in the address now.
 */
export function rowToHandle(hash: string, handled: SecurityActionId | undefined, force: boolean): {row: SecurityActionId | undefined; handled: SecurityActionId | undefined} {
  const row = accountRowOf(hash);
  // No row in the address: the next one that appears is new.
  if (!row) return {row: undefined, handled: undefined};
  if (!force && row === handled) return {row: undefined, handled};
  return {row, handled};
}

/** The parameter of the bell's dialog (Bell.tsx). */
export const BELL_PARAM = "notificationsDialog";

/**
 * The row a link named while the bell was open, once the bell has just closed; `undefined` at every other moment. A pure
 * function, so the rule is tested without a browser.
 */
export function rowAfterBellClosed(pending: SecurityActionId | undefined, bellWasOpen: boolean, bellIsOpen: boolean): SecurityActionId | undefined {
  return bellWasOpen && !bellIsOpen ? pending : undefined;
}

/** How long the page waits for a row and its first control to be drawn: they come with the data of the page. */
const WAIT_MS = 5000;

export function useRowFragment(ready: boolean): void {
  const search = useSearchParams();
  const handled = useRef<SecurityActionId | undefined>(undefined);
  const bellWasOpen = useRef(false);
  const bellIsOpen = search.get(BELL_PARAM) !== null;
  // The row a link named while the bell is open: a note for the moment it closes, not state to render.
  const pending = useRef<SecurityActionId | undefined>(undefined);
  useEffect(() => {
    const linked = rowAfterBellClosed(pending.current, bellWasOpen.current, bellIsOpen);
    if (bellWasOpen.current && !bellIsOpen) pending.current = undefined;
    bellWasOpen.current = bellIsOpen;
    if (!ready) return;
    // True when there is nothing more to do: no row in the address, or the row has the focus. False when the row, or the
    // control that takes the focus, is not drawn yet.
    const go = (force: boolean, hash: string = window.location.hash): boolean => {
      const next = rowToHandle(hash, handled.current, force);
      handled.current = next.handled;
      if (!next.row) return true;
      const row = document.querySelector<HTMLElement>(`[data-row-id="${next.row}"]`);
      // A row has a control to start with. A section of the page (the passkeys) has a title of its own, a direct child, which takes the
      // focus and is read first; the rows inside it are `section` elements too, so the tag cannot tell them apart.
      const target = row ? (row.querySelector<HTMLElement>(":scope > h2") ?? row.querySelector<HTMLElement>("button")) : null;
      // Not drawn yet (a row is on the page before its button is): it is not remembered, so the next change of the page tries again.
      // A section that is still loading is replaced by the one that holds the list, and the focus would go with it.
      if (!row || !target || row.getAttribute("aria-busy") === "true") return false;
      handled.current = next.row;
      row.scrollIntoView({block: "center", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth"});
      target.focus({preventScroll: true});
      return true;
    };
    let frame = 0;
    let observer: MutationObserver | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const stop = () => {
      cancelAnimationFrame(frame);
      observer?.disconnect();
      clearTimeout(timer);
      observer = undefined;
    };
    // A frame later, and not in the effect itself: after a client navigation Next writes the address (the fragment) and moves the
    // focus to the new page from its own effects, which run after a child's. Acting now would find no fragment yet, or lose the focus
    // to the router a moment later. If the row or its control is not there yet, the page is watched until it is, for WAIT_MS. Everything
    // is cancelled when the effect runs again or the page leaves, so only the last run acts.
    const attempt = (force: boolean, hash?: string) => {
      stop();
      frame = requestAnimationFrame(() => {
        if (go(force, hash)) return;
        observer = new MutationObserver(() => {
          if (go(force, hash)) stop();
        });
        observer.observe(document.body, {childList: true, subtree: true});
        timer = setTimeout(stop, WAIT_MS);
      });
    };
    const onHashChange = () => attempt(true);
    // The link names the row itself: the address is not written yet when the click is handled, and a same-page navigation never tells.
    const onRowLink = (event: Event) => {
      const row = accountRowOf(String((event as CustomEvent<unknown>).detail));
      if (!row) return;
      if (bellIsOpen) pending.current = row;
      else attempt(true, `#${row}`);
    };
    if (linked) attempt(true, `#${linked}`);
    else attempt(false);
    window.addEventListener("hashchange", onHashChange);
    window.addEventListener(ROW_LINK_EVENT, onRowLink);
    return () => {
      stop();
      window.removeEventListener("hashchange", onHashChange);
      window.removeEventListener(ROW_LINK_EVENT, onRowLink);
    };
  }, [ready, search, bellIsOpen]);
}
