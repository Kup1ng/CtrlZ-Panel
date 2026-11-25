"use client";

import {useCallback, useEffect} from "react";
import {usePathname} from "@ctrlz/i18n/navigation.ts";
import {isLocale, type Locale} from "@ctrlz/i18n/locale.ts";

import {markPageLeaving} from "./pageLeaving.ts";

// Changing language is a full load, not a client navigation (spec 4.2): a client
// navigation re-renders <html>, which would drop the theme classes that
// ThemeScript added in `system` mode. A signed-in session also stores the choice
// (PATCH /account/preferences {locale}). This package does not depend on the API
// client, so that write is registered from outside, the way useTheme does it
// with onThemeModeChange.

type Listener = (locale: Locale) => void | Promise<void>;
const listeners = new Set<Listener>();

export function onLocaleChange(listener: Listener) {
  listeners.add(listener);
  return () => void listeners.delete(listener);
}

// A page that holds a secret only in its own state (the invite page, once its link's fragment is off the address
// bar) offers it here, and the switch puts it back into the destination's fragment: a fragment never reaches a
// server, and the page that loads takes it off the bar again, as it did the first time (wp8-r20-1). Without it the
// reload would lose the code and the visitor would have to find the original link.
let carriedFragment: string | null = null;

export function useCarryAcrossLocaleSwitch(fragment: string | null) {
  useEffect(() => {
    if (!fragment) return;
    carriedFragment = fragment;
    return () => {
      if (carriedFragment === fragment) carriedFragment = null;
    };
  }, [fragment]);
}

// A slow API must not trap the user on the wrong language.
const SAVE_BUDGET_MS = 1500;

export function useLocaleSwitch() {
  const pathname = usePathname();

  return useCallback(
    async (next: Locale) => {
      if (!isLocale(next)) return;
      // From here the page is on its way out, whatever its calls still do (wp8-r9-6).
      markPageLeaving();
      const saves = [...listeners].map((l) => Promise.resolve(l(next)).catch(() => undefined));
      await Promise.race([Promise.all(saves), new Promise((r) => setTimeout(r, SAVE_BUDGET_MS))]);
      const {search} = window.location;
      const hash = carriedFragment ? `#${encodeURIComponent(carriedFragment)}` : window.location.hash;
      window.location.replace(`/${next}${pathname === "/" ? "" : pathname}${search}${hash}`);
    },
    [pathname],
  );
}
