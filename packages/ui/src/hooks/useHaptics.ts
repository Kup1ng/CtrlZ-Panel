"use client";

// T-310. Off by default, only on touch screens, and nothing on iOS Safari,
// which has no `vibrate`. The switch lives in Account (WP9), which writes the
// same key. Storage can throw in a private window, so every access is guarded.
//
// It is wired once, in `forms/PrimaryButton.tsx`, which is what every primary action of the product is
// (SubmitButton, the create button of a page header, and the other primary buttons that act). A page does not call it.

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

/**
 * One short pulse, when all three guards hold: the browser has `navigator.vibrate`, the person turned the preference on in Account,
 * and the pointer is coarse (a touch screen: a mouse click that buzzes a laptop is noise). Returns whether it buzzed, for the test.
 */
export function buzz(): boolean {
  if (typeof navigator === "undefined" || typeof navigator.vibrate !== "function") return false;
  if (!hapticsEnabled()) return false;
  try {
    if (!matchMedia("(pointer: coarse)").matches) return false;
  } catch {
    return false;
  }
  return navigator.vibrate(10);
}
