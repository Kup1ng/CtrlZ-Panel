"use client";

import {useSearchParams} from "next/navigation";
import {useCallback} from "react";

// Spec 9, T-117. A dialog whose state is a query parameter, so a direct link opens it, Back closes
// it, a reload keeps it, and Escape closes it and the URL changes with it.
//
// One difference from the spec text, decided by WP6 and kept: it writes with the History API and
// not next-intl's router. Next 16 wires pushState and replaceState into `useSearchParams`, and a
// router push would ask the server for the page again on every open, which delays a dialog for
// nothing: nothing on one of these pages depends on the parameter.
//
// Secrets never go in a URL (R21). A dialog that holds a TOTP secret, recovery codes, a one-time
// password, an invite link or a reauth step is state-only: it is not in this union, and it uses
// DialogFrame with its own state. Lint `no-secret-param` bans those words near this hook.

/** Closed union of T-117 (the wireframe notes), plus the shell's bell and the admin's own. */
export const DIALOG_PARAMS = [
  "profileDialog",
  "serviceDialog",
  "ruleDialog",
  "deviceDialog",
  "endpointGroupDialog",
  "ipDialog",
  "deviceId",
  "helpPane",
  "setupOs",
  "step",
  "notificationsDialog",
  "dialog",
  "enrollmentId",
  "pairId",
] as const;

export type DialogParam = (typeof DIALOG_PARAMS)[number];

export type UrlDialog = {
  /** The parameter's value, or null when it is absent or empty. */
  value: string | null;
  isOpen: boolean;
  /** Opens with `value` (default "1"). Opening one that is open changes its value without a new history entry. */
  open(value?: string): void;
  /** Back if this tab pushed the entry, so the user stays where they were; otherwise strips the parameter. */
  close(): void;
};

// Did this tab push the entry that holds the dialog? If so Back closes it and leaves the app where it
// was. If the user arrived on the link directly, close must not call back(), which would leave the app.
export const pushedKey = (param: string) => `ctrlz.dialog.pushed.${param}`;

export function readPushed(param: string): boolean {
  try {
    return sessionStorage.getItem(pushedKey(param)) === "1";
  } catch {
    return false;
  }
}

export function writePushed(param: string, on: boolean) {
  try {
    if (on) sessionStorage.setItem(pushedKey(param), "1");
    else sessionStorage.removeItem(pushedKey(param));
  } catch {
    // Storage blocked: close() then always strips the parameter, which is safe.
  }
}

/** The path, query and fragment of `href` with `param` set, or removed when `value` is null. Other parameters stay. */
export function urlWith(href: string, param: string, value: string | null): string {
  const url = new URL(href);
  if (value === null) url.searchParams.delete(param);
  else url.searchParams.set(param, value);
  return `${url.pathname}${url.search}${url.hash}`;
}

/** The same as `urlWith` for several parameters at once. A `null` removes one. */
export function urlWithMany(href: string, params: Partial<Record<DialogParam, string | null>>): string {
  const url = new URL(href);
  for (const [name, value] of Object.entries(params)) {
    if (value === null || value === undefined) url.searchParams.delete(name);
    else url.searchParams.set(name, value);
  }
  return `${url.pathname}${url.search}${url.hash}`;
}

/**
 * Opens a dialog that needs two parameters (`?dialog=confirmNode&enrollmentId=<id>`) with one history entry, so one Back closes it, and
 * remembers for each parameter that this tab pushed it. `wasPushed` tells the closer whether Back is the way out.
 */
export function pushDialogParams(values: Partial<Record<DialogParam, string>>): void {
  let target = new URL(window.location.href);
  for (const [param, value] of Object.entries(values)) target = new URL(urlWith(target.href, param, value ?? null), target);
  window.history.pushState(null, "", `${target.pathname}${target.search}${target.hash}`);
  for (const param of Object.keys(values) as DialogParam[]) writePushed(param, true);
}

export const wasPushed = (param: DialogParam): boolean => readPushed(param);

export function useUrlDialog(param: DialogParam): UrlDialog {
  const value = useSearchParams().get(param) || null;

  const open = useCallback(
    (next = "1") => {
      const target = urlWith(window.location.href, param, next);
      if (new URL(window.location.href).searchParams.get(param)) {
        // Already open: a second entry would make one Back leave a dialog open behind it.
        window.history.replaceState(null, "", target);
        return;
      }
      window.history.pushState(null, "", target);
      writePushed(param, true);
    },
    [param],
  );

  const close = useCallback(() => {
    if (readPushed(param)) {
      writePushed(param, false);
      window.history.back();
    } else {
      window.history.replaceState(null, "", urlWith(window.location.href, param, null));
    }
  }, [param]);

  return {value, isOpen: value !== null, open, close};
}

if (typeof window !== "undefined") {
  // A pushed entry is gone once the user went back past it or reloaded onto a fresh navigation; a
  // stale flag would make close() leave the app.
  const forget = () => {
    const params = new URL(window.location.href).searchParams;
    for (const p of DIALOG_PARAMS) if (!params.has(p)) writePushed(p, false);
  };
  window.addEventListener("popstate", forget);
  const fresh = (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type === "navigate";
  if (fresh) for (const p of DIALOG_PARAMS) writePushed(p, false);
}
