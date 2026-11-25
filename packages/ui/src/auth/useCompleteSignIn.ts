"use client";

import {meKeys} from "@ctrlz/api-client/hooks/me.ts";
import {completeSignIn} from "@ctrlz/api-client/session.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {useQueryClient} from "@tanstack/react-query";
import {useLocale} from "next-intl";
import {useSearchParams} from "next/navigation";
import {useCallback, useEffect, useRef} from "react";

import {PANEL_PROTECTED_PREFIXES} from "../proxy/prefixes.ts";
import {sanitizeNext} from "../proxy/safeNext.ts";
import {isPageLeaving} from "../shell/pageLeaving.ts";
import {authApi} from "./authApi.ts";

// Every success path of the pages here (password, OTP, TOTP, passkey, register, invite) ends the same way
// (spec 10.2): `completeSignIn()` first, which clears the saved-language flag of this tab and tells the
// other tabs to refetch /me, then the page the visitor came for. `next` is checked by the proxy's own
// function, so a value the proxy would refuse is refused here too, and the fallback is /profiles. A user
// who must change the password is sent on by the session gate, not decided here.
//
// A page that has been left does not finish (wp8-r7-3, r7-7). The visitor who pressed a link, the language menu
// or Back while a sign-in call ran is somewhere else when the answer comes, and a `router.replace` from here
// would pull them off the page they chose. The call has opened a session by then, which the page does not show,
// so it is ended instead of being left in the browser. One rule for every success path that uses this hook.
//
// A sign-in that moves on but never leaves the page does not spin for ever either (wp8-r11-2). The forms stay
// pending after a success until the route changes, and when the destination sends the visitor back to the very
// route they are on (the browser dropped the session cookie, so the proxy answers /profiles with
// /login?next=/profiles, or /me answers 401), nothing unmounts the page and nothing resets the form. A page
// that asked for the sign-in and is still mounted STALL_MS after the move asks the API whether the session holds
// (wp8-r12-1, r12-3), because a slow route change on a slow link looks exactly like a redirect back to /login:
//   - 401: the session is gone. The caller gets `onStall`, resets itself and says so.
//   - 200, or an answer that says nothing (429, 5xx, offline): the sign-in worked, so the page never claims
//     otherwise. The move is made again as a full page load of the same checked target, which does not depend on
//     the transition that is still pending, and the form stays pending until it lands. Resetting the form here
//     would tell the visitor the opposite of the truth, leave a live session behind an empty form, and a second
//     sign-in would then be ended by the left-page rule above.
// When the route change finishes first, the page unmounts and the timer (or the answer of the probe) is dropped.

export const STALL_MS = 12_000;

type Options = {
  /** The page is still here STALL_MS after a sign-in moved on and the API says the session is gone: put the form back and say so. */
  onStall?: () => void;
};

export function useCompleteSignIn({onStall}: Options = {}) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const params = useSearchParams();
  const locale = useLocale();
  const rawNext = params.get("next");
  // Set in the effect, not at first render, so a development remount (cleanup, then setup again) is still "here".
  const here = useRef(false);
  const stall = useRef<ReturnType<typeof setTimeout> | null>(null);
  // The latest callback, read when the timer fires, so a caller can pass a closure.
  const onStallRef = useRef(onStall);
  useEffect(() => {
    onStallRef.current = onStall;
  });
  useEffect(() => {
    here.current = true;
    return () => {
      here.current = false;
      if (stall.current !== null) clearTimeout(stall.current);
      stall.current = null;
    };
  }, []);

  // Returns whether the page moves on. `false` means the session was ended instead (see above), so the caller must
  // not keep its form pending for a page change that will not come: a language switch that was cancelled leaves
  // this page alive, and a form that spins for ever is a dead end (wp8-r10-3).
  return useCallback((): boolean => {
    // A page that has started a full load (the language switch) is left too, though React has not unmounted it.
    if (!here.current || isPageLeaving()) {
      void authApi.dropSession();
      return false;
    }
    completeSignIn();
    // Whatever /me held before is another visit's answer. The shell asks again.
    queryClient.removeQueries({queryKey: meKeys.all});
    const target = sanitizeNext(rawNext, PANEL_PROTECTED_PREFIXES) ?? "/profiles";
    router.replace(target);
    if (stall.current !== null) clearTimeout(stall.current);
    stall.current = setTimeout(() => {
      stall.current = null;
      if (!here.current) return;
      void authApi.sessionState().then((state) => {
        // The route change may have finished, or the visitor left, while the probe was in flight.
        if (!here.current || isPageLeaving()) return;
        if (state === "dead") onStallRef.current?.();
        else window.location.assign(`/${locale}${target}`);
      });
    }, STALL_MS);
    return true;
  }, [router, queryClient, rawNext, locale]);
}
