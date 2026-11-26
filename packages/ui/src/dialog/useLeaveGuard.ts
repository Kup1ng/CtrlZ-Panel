"use client";

import {guardRestoredPage, isSessionEnding} from "@ctrlz/api-client/session.ts";
import {useEffect, useId, useRef} from "react";

import {isPageLeaving} from "../shell/pageLeaving.ts";

// Spec 12.3 step 4 (wp9-r2-6). A dialog that holds a one-time secret (recovery codes) or waits for the call that
// returns one must not vanish because the person pressed Back, swiped back on a phone, reloaded or closed the tab:
// the server has committed the codes and nothing can show them again. Escape and the close button are the dialog's
// own business (DialogFrame `isLocked`, the confirm-before-close of CodesView); this hook covers what leaves the page.
//
// `beforeunload` covers reload, pull-to-refresh and closing the tab: the browser asks, and says nothing of why.
// Back is the History API's: while the guard is on, the page has pushed one entry that carries no secret, so one Back
// pops that entry instead of the page. The listener pushes it again and calls `onBack`, which is where a dialog that
// already shows the codes asks "close anyway?". The entry is taken back when the guard ends, but only when it is
// still the current one, so it never undoes a navigation the person made after it.
//
// The guard is for the person's own leaving, never for the session's. A logout in another tab, an idle or revoked
// session and a new identity in another tab all end in a full load that is the wipe of this tab's memory (spec 14.4,
// `logoutLocal`, `reloadForNewIdentity`): they set `isSessionEnding()` first, and then the guard stays out of the way.
// A prompt anyone can cancel would leave the codes on screen under a session that is gone (wp9-r3-3, wp9-r3-5). The reload of a page
// restored from the back/forward cache is the same kind of leaving: `guardRestoredPage` marks the page as ending before it reloads (gate-r11-4).
//
// A step back of more than one entry (the long-press history menu, `history.go(-2)`) lands on an older route, and the
// framework's own `popstate` listener, registered first, renders it before `onPop` runs. Where the Navigation API
// exists, its `navigate` event comes before all of that and a traversal can be cancelled there: the page stays and
// asks, whatever the distance (wp9-r3-6). `popstate` stays as the fallback for the other browsers and for a traversal
// the browser does not let a page cancel.
//
// Taking the guard's entry back follows the same rule. The guard usually ends because the call it guarded failed, and a
// call that answers session_expired has already started the full load of the login page: a `history.back()` queued by
// the cleanup then aborts that load in Chrome (a traversal cancels a pending cross-document navigation), the old
// document lives on with `isSessionEnding()` set for good, and the wipe never happens (wp9-r4-2). A load that is on its
// way drops the extra entry by itself, so while the session is ending or the page has started a load, the entry stays.
//
// Not `useUrlDialog`: that one puts a parameter in the address, and a secret's dialog must leave the address as it is.

const MARK = "ctrlzLeaveGuard";

type NavigateEventLike = Event & {navigationType?: string};

export function useLeaveGuard(active: boolean, onBack?: () => void) {
  const id = useId();
  const latest = useRef(onBack);
  const undo = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    latest.current = onBack;
  });

  useEffect(() => {
    if (!active) return;
    // A page restored from the back/forward cache is reloaded by guardRestoredPage, which marks the page as ending first, so the
    // `beforeunload` below steps aside for that reload (gate-r11-4). Every gated page has installed it already; a page that holds a
    // secret must not depend on that, because the prompt it would otherwise get keeps the secret in a document that someone else restored.
    guardRestoredPage();
    // A development double effect ends this guard and starts it again at once: the entry is kept.
    clearTimeout(undo.current);
    const mine = () => (window.history.state as Record<string, unknown> | null)?.[MARK] === id;
    // The state of the entry is copied, so the framework's own markers in it survive.
    const push = () => window.history.pushState({...(window.history.state as object | null), [MARK]: id}, "", window.location.href);
    if (!mine()) push();

    const onUnload = (event: BeforeUnloadEvent) => {
      if (isSessionEnding()) return;
      event.preventDefault();
      event.returnValue = "";
    };
    const onPop = () => {
      if (mine()) return;
      push();
      latest.current?.();
    };
    // A cancelled traversal leaves the page where it is, with this entry current, and fires no `popstate`.
    const onNavigate = (event: Event) => {
      if ((event as NavigateEventLike).navigationType !== "traverse" || !event.cancelable || isSessionEnding()) return;
      event.preventDefault();
      latest.current?.();
    };
    const navigation = (window as unknown as {navigation?: EventTarget}).navigation;
    navigation?.addEventListener("navigate", onNavigate);
    window.addEventListener("beforeunload", onUnload);
    window.addEventListener("popstate", onPop);
    return () => {
      navigation?.removeEventListener("navigate", onNavigate);
      window.removeEventListener("beforeunload", onUnload);
      window.removeEventListener("popstate", onPop);
      // Asked again inside the timer: the load may start between the cleanup and the tick.
      const loading = () => isSessionEnding() || isPageLeaving();
      if (loading()) return;
      undo.current = setTimeout(() => {
        if (!loading() && mine()) window.history.back();
      }, 0);
    };
  }, [active, id]);
}
