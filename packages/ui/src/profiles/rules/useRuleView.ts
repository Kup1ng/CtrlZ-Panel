"use client";

import {useCallback, useSyncExternalStore} from "react";

import type {RuleView} from "./rulesModel.ts";

// The large or small view of the Rules lists, kept in the browser (spec p2 9.6, T-196). It is a per-viewer convenience: the value is
// "large" or "small", it is read in `try/catch` because storage can be empty or refused (a private window), and the page is right without
// it. The server and the first client render are "large"; the saved value is read right after (`useSyncExternalStore` re-renders when the
// two differ), and a choice made while storage is refused still holds for the rest of the visit, in memory.

const KEY = "ctrlz.rules.view";
const listeners = new Set<() => void>();
let memory: RuleView | null = null;

export function readRuleView(): RuleView | null {
  try {
    const value = localStorage.getItem(KEY);
    return value === "large" || value === "small" ? value : null;
  } catch {
    return null;
  }
}

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
};
const snapshot = (): RuleView => memory ?? readRuleView() ?? "large";
const serverSnapshot = (): RuleView => "large";

export function useRuleView(): [RuleView, (view: RuleView) => void] {
  const view = useSyncExternalStore(subscribe, snapshot, serverSnapshot);
  const set = useCallback((next: RuleView) => {
    memory = next;
    try {
      localStorage.setItem(KEY, next);
    } catch {
      // The view is for this visit only.
    }
    for (const listener of listeners) listener();
  }, []);
  return [view, set];
}
