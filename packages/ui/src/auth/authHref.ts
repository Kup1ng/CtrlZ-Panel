"use client";

import {useSearchParams} from "next/navigation";

import {PANEL_PROTECTED_PREFIXES} from "../proxy/prefixes.ts";
import {sanitizeNext} from "../proxy/safeNext.ts";

// The pages of the sign-in family (login, register, invite, forgot password) link to each other, and the one a
// visitor finishes on sends them to `next` (useCompleteSignIn reads it from its own URL). So a link between them
// carries the validated `next` along, or the page the visitor came for is forgotten at the first click (wp8-r9-5).
// Every link from one of these pages to another goes through this, and authHref.test.ts scans for a bare one.

/** `path` with `next` appended when it is a value the proxy would accept, else `path` as it is. */
export function hrefWithNext(path: string, rawNext: string | null | undefined): string {
  const next = sanitizeNext(rawNext, PANEL_PROTECTED_PREFIXES);
  return next === undefined ? path : `${path}?next=${encodeURIComponent(next)}`;
}

export function useAuthHref(): (path: string) => string {
  const rawNext = useSearchParams().get("next");
  return (path) => hrefWithNext(path, rawNext);
}
