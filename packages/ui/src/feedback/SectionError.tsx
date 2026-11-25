"use client";

import {Button} from "@heroui/react";
import {EmptyState} from "@heroui-pro/react";
import {hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {Tech} from "../data/Tech.tsx";
import {useErrorText} from "./errorText.ts";

// Spec 8.7. The error of one section, used by each `error.tsx` and by the session gate. It shows
// a title, the text of `errors.<code>`, Retry, and the `request_id` in <Tech> so the owner can
// quote it. Never a stack, a URL or the thrown message: `useErrorText` maps anything to a
// catalogue line. `role="alert"` so the failure is announced.
//
// A `not_found` is not retried (the row is gone, or never was the tenant's: the text never says
// which, spec 14.3). Next hands an `error.tsx` an error whose `digest` is the server-side
// reference of a render that failed there; it stands in for the request id.

export type SectionErrorProps = {
  error: unknown;
  /** Retry button. Next's `reset` for an error boundary, a refetch for a query. */
  onRetry?: () => void;
  className?: string;
};

function referenceOf(error: unknown): string | undefined {
  if (isApiError(error)) return error.requestId;
  const digest = (error as {digest?: unknown} | null)?.digest;
  return typeof digest === "string" && /^[\w.-]{1,64}$/.test(digest) ? digest : undefined;
}

export function SectionError({error, onRetry, className}: SectionErrorProps) {
  const t = useTranslations("feedback");
  const c = useTranslations("common");
  const errorText = useErrorText();
  const missing = hasCode(error, "not_found");
  const reference = referenceOf(error);

  return (
    <div role="alert" className={className}>
      <EmptyState size="sm">
        <EmptyState.Header>
          <EmptyState.Media variant="icon">
            <Icon name={missing ? "search" : "warning"} className="size-5" />
          </EmptyState.Media>
          <EmptyState.Title>{missing ? t("error.notFoundTitle") : t("error.title")}</EmptyState.Title>
          <EmptyState.Description>{missing ? t("error.notFoundText") : errorText(error)}</EmptyState.Description>
        </EmptyState.Header>
        {onRetry && !missing ? (
          <EmptyState.Content>
            <Button variant="secondary" onPress={onRetry}>
              {c("retry")}
            </Button>
          </EmptyState.Content>
        ) : null}
        {reference ? (
          <p className="text-muted text-center text-xs">
            {t("error.reference")}: <Tech className="select-all">{reference}</Tech>
            <br />
            {t("error.referenceHint")}
          </p>
        ) : null}
      </EmptyState>
    </div>
  );
}
