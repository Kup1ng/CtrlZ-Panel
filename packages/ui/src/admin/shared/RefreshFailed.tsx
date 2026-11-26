"use client";

import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";

import {keepFocus} from "./restoreFocus.ts";

// A background refetch of a page's query failed (a reconnect, or the invalidation after a write) while the page still holds
// the data it fetched before. TanStack keeps that data and sets `error`; the page must keep showing it. Replacing the page with
// SectionError would unmount an open form with its edits, its conflict state and the Edit credentials dialog with the pasted
// key, and nothing would say so (wp10-r10-1). SectionError is for a page that has no data at all.
//
// role="alert", as SectionError has: the line is inserted already holding its text, and a polite live region that appears with its
// content is often not spoken, so a screen-reader admin would go on from values the page itself calls out of date (wp10-r11-2).
// The Retry button leaves with the line when the refetch succeeds, so it goes through keepFocus like every admin Retry and the focus
// does not fall to <body> (wp10-r11-1). `onRetry` returns the refetch promise so the focus is given back once it has settled.
export function RefreshFailed({error, onRetry}: {error: unknown; onRetry: () => unknown}) {
  const t = useTranslations("admin");
  const c = useTranslations("common");
  if (!error) return null;
  return (
    <div role="alert" className="mb-4 flex flex-wrap items-center justify-between gap-2 text-sm" data-testid="refresh-failed">
      <span className="text-(--danger-text)">{t("refreshFailed")}</span>
      <Button size="sm" variant="secondary" onPress={() => keepFocus(onRetry)}>
        {c("retry")}
      </Button>
    </div>
  );
}
