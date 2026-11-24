"use client";

import {useCallback} from "react";
import {usePathname} from "@ctrlz/i18n/navigation.ts";
import {isLocale, type Locale} from "@ctrlz/i18n/locale.ts";

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

// A slow API must not trap the user on the wrong language.
const SAVE_BUDGET_MS = 1500;

export function useLocaleSwitch() {
  const pathname = usePathname();

  return useCallback(
    async (next: Locale) => {
      if (!isLocale(next)) return;
      const saves = [...listeners].map((l) => Promise.resolve(l(next)).catch(() => undefined));
      await Promise.race([Promise.all(saves), new Promise((r) => setTimeout(r, SAVE_BUDGET_MS))]);
      const {search, hash} = window.location;
      window.location.replace(`/${next}${pathname === "/" ? "" : pathname}${search}${hash}`);
    },
    [pathname],
  );
}
