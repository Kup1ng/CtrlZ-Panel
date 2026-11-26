"use client";

import {useLayoutEffect} from "react";

import {ensureThemeApplied} from "./useTheme.ts";

/**
 * Renders nothing. When the document has no theme class on mount (the system theme of a first visit on Next's 404 shell, where ThemeScript
 * never runs, gate-r11-1) it applies the one the OS prefers, before the first paint of the recovered page. A layout effect, so there is no
 * frame in the wrong theme; on a page where ThemeScript or the server already chose, it does nothing.
 */
export function EnsureTheme() {
  useLayoutEffect(() => {
    ensureThemeApplied();
  }, []);
  return null;
}
