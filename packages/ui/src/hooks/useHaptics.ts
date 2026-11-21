"use client";

import {useCallback} from "react";

// T-310. Off by default, only on touch screens, and nothing on iOS Safari,
// which has no `vibrate`. The switch lives in Account (WP9), which writes the
// same key. Storage can throw in a private window, so every access is guarded.

const KEY = "ctrlz.haptics";

export function hapticsEnabled(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function setHapticsEnabled(on: boolean) {
  try {
    localStorage.setItem(KEY, on ? "1" : "0");
  } catch {
    // Storage blocked: the preference lasts until the page closes, which is none.
  }
}

/** `buzz` is for the `onPress` of a primary action. */
export function useHaptics() {
  const buzz = useCallback(() => {
    if (typeof navigator === "undefined" || typeof navigator.vibrate !== "function") return;
    if (!hapticsEnabled()) return;
    if (!matchMedia("(pointer: coarse)").matches) return;
    navigator.vibrate(10);
  }, []);
  return {buzz};
}
