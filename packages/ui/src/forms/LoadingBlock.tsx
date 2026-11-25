"use client";

import {Skeleton} from "@heroui/react";
import {useTranslations} from "next-intl";

import {OfflineNotice} from "./FormError.tsx";

// The card content of a step that waits for an answer before it can show its form (/auth/config, /me, the invite
// lookup). The bars are decoration, so a screen reader gets "Please wait" in a status region that is marked busy
// instead (wp8-r17-4). The offline line sits beside it: with no connection TanStack pauses the request, so the
// state never becomes "failed" and would otherwise stay silent for as long as the browser is offline (wp8-r17-3).
// The same block serves every waiting screen, so none can forget either.

export function LoadingBlock({rows}: {/** Bars of the form-shaped placeholder (default: one tall block). */ rows?: number}) {
  const t = useTranslations("auth");
  return (
    <>
      <div role="status" aria-busy="true">
        <span className="sr-only">{t("form.waiting")}</span>
        {rows ? (
          <div aria-hidden className="flex flex-col gap-4">
            {Array.from({length: rows}, (_, index) => (
              <Skeleton key={index} className="h-10 w-full rounded-(--radius-box)" />
            ))}
          </div>
        ) : (
          <Skeleton aria-hidden className="h-24 w-full rounded-(--radius-box)" />
        )}
      </div>
      <OfflineNotice />
    </>
  );
}
