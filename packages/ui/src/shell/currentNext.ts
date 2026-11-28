import type {AppId} from "@ctrlz/i18n/namespaces.ts";

import {ADMIN_PROTECTED_PREFIXES, PANEL_PROTECTED_PREFIXES} from "../proxy/prefixes.ts";
import {sanitizeNext} from "../proxy/safeNext.ts";

/** The page the visitor was on, without the locale and checked like the proxy checks it, for `?next=`. */
export function currentNext(app: AppId): string | undefined {
  const [, , ...rest] = window.location.pathname.split("/");
  const path = `/${rest.join("/")}${window.location.search}`;
  return sanitizeNext(path, app === "admin" ? ADMIN_PROTECTED_PREFIXES : PANEL_PROTECTED_PREFIXES);
}
