"use client";

import {useCallback, useSyncExternalStore} from "react";

import {applyTheme} from "./apply.ts";
import {parseThemeMode, THEME_COOKIE, THEME_COOKIE_MAX_AGE, type ResolvedMode, type ThemeMode} from "./config.ts";

// The one theme store (spec 5.1). `useTheme` from @heroui/react and next-themes
// are banned by lint: a second store would flash on load and could not hold the
// four theme names.

const QUERY = "(prefers-color-scheme: dark)";

function readCookie(): ThemeMode {
  try {
    const hit = document.cookie.split("; ").find((c) => c.startsWith(`${THEME_COOKIE}=`));
    return parseThemeMode(hit?.slice(THEME_COOKIE.length + 1));
  } catch {
    return "system";
  }
}

function writeCookie(mode: ThemeMode) {
  try {
    document.cookie = `${THEME_COOKIE}=${mode}; Path=/; Secure; SameSite=Lax; Max-Age=${THEME_COOKIE_MAX_AGE}`;
  } catch {
    // Cookies blocked: the in-memory mode below still works for this tab.
  }
}

let currentMode: ThemeMode | undefined;
const modeListeners = new Set<() => void>();
const changeListeners = new Set<(mode: ThemeMode) => void>();

function getMode(): ThemeMode {
  currentMode ??= readCookie();
  return currentMode;
}

function subscribeMode(cb: () => void) {
  modeListeners.add(cb);
  return () => void modeListeners.delete(cb);
}

function subscribeSystem(cb: () => void) {
  const mq = matchMedia(QUERY);
  mq.addEventListener("change", cb);
  return () => mq.removeEventListener("change", cb);
}

const systemDark = () => matchMedia(QUERY).matches;

function resolve(mode: ThemeMode): ResolvedMode {
  return mode === "system" ? (systemDark() ? "dark" : "light") : mode;
}

function commit(mode: ThemeMode) {
  currentMode = mode;
  writeCookie(mode);
  applyTheme(resolve(mode));
  modeListeners.forEach((l) => l());
}

/**
 * Sets the mode, writes the cookie and applies the classes. Listeners registered
 * with onThemeModeChange run afterwards: that is where a signed-in session sends
 * PATCH /account/preferences {theme}, so this package does not depend on the API client.
 */
export function setThemeMode(mode: ThemeMode) {
  commit(mode);
  changeListeners.forEach((l) => l(mode));
}

/**
 * Applies a mode that came from the server (`user.theme` after /me, spec 5.1
 * step 5: the server value wins). It does not notify listeners, so it cannot echo back as a PATCH.
 */
export function adoptServerThemeMode(mode: ThemeMode) {
  if (mode !== getMode()) commit(mode);
}

export function onThemeModeChange(listener: (mode: ThemeMode) => void) {
  changeListeners.add(listener);
  return () => void changeListeners.delete(listener);
}

/**
 * `mode` is what the user chose, `resolved` is what is painted. On the server and
 * during hydration they are `system` and `light`, which is what the markup holds
 * when the cookie is absent. The real values arrive in the first client render.
 */
export function useTheme() {
  const mode = useSyncExternalStore(subscribeMode, getMode, () => "system" as ThemeMode);
  const dark = useSyncExternalStore(subscribeSystem, systemDark, () => false);
  const resolved: ResolvedMode = mode === "system" ? (dark ? "dark" : "light") : mode;
  const setMode = useCallback((next: ThemeMode) => setThemeMode(next), []);

  return {mode, resolved, setMode};
}

if (typeof window !== "undefined") {
  // While the mode is `system`, a change of the OS preference re-applies the classes.
  // One listener for the page, not one per hook user.
  matchMedia(QUERY).addEventListener("change", () => {
    if (getMode() === "system") applyTheme(resolve("system"));
  });
}
