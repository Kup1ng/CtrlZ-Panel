"use client";

import {useSearchParams} from "next/navigation";
import {useCallback} from "react";

// Dialogs whose state is in the URL (T-117, spec 9). This is the part of
// dialog/useUrlDialog.ts (WP7) that the shell needs for its two parameters, with
// the same contract, so that WP7's hook can replace this file by changing the
// import. It differs from the spec in one way: it writes with the History API,
// not next-intl's router. Next 16 wires pushState and replaceState into
// useSearchParams, and a router push would ask the server for the page again on
// every open, which delays a dialog for nothing: nothing on it depends on the
// parameter.

export type ShellDialogParam = "notificationsDialog" | "helpPane";

// Did this tab push the entry that holds the dialog? If so Back closes it and
// leaves the app where it was. If the user arrived on the link directly, close
// must not call back(), which would leave the app.
const pushedKey = (param: string) => `ctrlz.dialog.pushed.${param}`;

function readPushed(param: string): boolean {
  try {
    return sessionStorage.getItem(pushedKey(param)) === "1";
  } catch {
    return false;
  }
}

function writePushed(param: string, on: boolean) {
  try {
    if (on) sessionStorage.setItem(pushedKey(param), "1");
    else sessionStorage.removeItem(pushedKey(param));
  } catch {
    // Storage blocked: close() then always strips the parameter, which is safe.
  }
}

function urlWith(param: string, value: string | null): string {
  const url = new URL(window.location.href);
  if (value === null) url.searchParams.delete(param);
  else url.searchParams.set(param, value);
  return `${url.pathname}${url.search}${url.hash}`;
}

export function useShellDialog(param: ShellDialogParam) {
  const value = useSearchParams().get(param) || null;

  const open = useCallback(
    (next = "1") => {
      window.history.pushState(null, "", urlWith(param, next));
      writePushed(param, true);
    },
    [param],
  );

  const close = useCallback(() => {
    if (readPushed(param)) {
      writePushed(param, false);
      window.history.back();
    } else {
      window.history.replaceState(null, "", urlWith(param, null));
    }
  }, [param]);

  return {value, isOpen: value !== null, open, close};
}

if (typeof window !== "undefined") {
  // A pushed entry is gone once the user went back past it or reloaded onto a
  // fresh navigation; a stale flag would make close() leave the app.
  const fresh = (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type === "navigate";
  window.addEventListener("popstate", () => {
    for (const p of ["notificationsDialog", "helpPane"]) {
      if (!new URL(window.location.href).searchParams.has(p)) writePushed(p, false);
    }
  });
  if (fresh) for (const p of ["notificationsDialog", "helpPane"]) writePushed(p, false);
}
