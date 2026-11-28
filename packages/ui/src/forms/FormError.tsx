"use client";

import {hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {Alert, Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useDeferredValue} from "react";

import {Tech} from "../data/Tech.tsx";
import {useErrorText} from "../feedback/errorText.ts";
import {useFormBlocked} from "./AuthForm.tsx";
import type {ApiForm} from "./useApiForm.ts";
import {useOnlineStatus} from "./useOnlineStatus.ts";

// Spec 10, "FormError", and the table of 10.1: the error that belongs to no field. The live region
// is always in the page and only its content changes, because a screen reader announces a change
// inside a region it already knows and often misses a region that is inserted with its text.
//
//   503 server_busy, service_unavailable and a dropped connection   a Retry button
//   500 internal                                                     the request_id to quote
//   403 csrf_rejected                                                a reload button
//
// The region is also empty on the render in which it mounts: a step that is entered with a notice (a code
// that expired, a ticket that ended) mounts this component with the error already set, and a region that
// arrives with its text is the one a screen reader misses. `useDeferredValue` with an initial value of null
// gives the first commit an empty region and the next one the text, so every caller can mount it with its
// error and the announcement still happens (wp8-r1-4).
//
// A countdown (429) is shown on the submit button, not here: re-announcing "12 seconds" every second
// would drown the screen reader.

export function FormError({
  error: errorNow,
  message,
  smsDown,
  onRetry: submitRetry,
  form,
  className,
}: {
  error: unknown;
  /** Text for a case the screen words itself. Without it the text of `errors.<code>` is used. */
  message?: string;
  /**
   * The words for `sms_unavailable` on a page that sends a text and whose visitor cannot sign in with a password
   * (Register, Invite, Forgot Password). The generic line tells the visitor to sign in with a password, which is
   * wrong there (wp8-r17-2). Only the sign-in page leaves it out.
   */
  smsDown?: string;
  /** What Retry does: sends the form again. */
  onRetry?: () => void;
  /**
   * The form whose `formError` this shows. A failure of a call that is not the submit (a failed Resend) brings
   * its own Retry, so that Retry asks for the code again and does not verify it (wp8-r4-1).
   */
  form?: ApiForm;
  className?: string;
}) {
  const t = useTranslations("auth");
  const c = useTranslations("common");
  const errorText = useErrorText();
  const error = useDeferredValue(errorNow, null);
  // Retry sends the form again, so it waits out a 429 and an offline browser like the submit button does.
  const blocked = useFormBlocked();
  const shown = error !== null && error !== undefined;
  const override = form && errorNow === form.formError ? form.retryOverride : null;
  const onRetry = override ? override.run || undefined : submitRetry;

  const retryable =
    shown && onRetry !== undefined && (!isApiError(error) || hasCode(error, "service_unavailable", "server_busy", "unknown"));
  const reload = shown && hasCode(error, "csrf_rejected");
  const requestId = shown && hasCode(error, "internal") ? error.requestId : undefined;

  // `empty:hidden`: the region is always in the page, and takes no gap of the form's flex column while it has nothing to say.
  return (
    <div aria-live="polite" aria-atomic="true" className={["empty:hidden", className].filter(Boolean).join(" ")}>
      {shown ? (
        <Alert status="danger">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{message ?? (smsDown !== undefined && hasCode(error, "sms_unavailable") ? smsDown : errorText(error))}</Alert.Description>
            {requestId ? (
              <p className="text-muted mt-1 text-xs">{t.rich("form.reference", {id: requestId, tech: (chunks) => <Tech>{chunks}</Tech>})}</p>
            ) : null}
            {retryable || reload ? (
              <div className="mt-2">
                {retryable ? (
                  <Button size="sm" variant="tertiary" isDisabled={blocked} onPress={onRetry}>
                    {c("retry")}
                  </Button>
                ) : (
                  <Button size="sm" variant="tertiary" onPress={() => window.location.reload()}>
                    {t("form.reload")}
                  </Button>
                )}
              </div>
            ) : null}
          </Alert.Content>
        </Alert>
      ) : null}
    </div>
  );
}

/** The offline line of the table in 10.1. The submit button is disabled by `SubmitButton`. */
export function OfflineNotice() {
  const t = useTranslations("auth");
  const online = useOnlineStatus();
  return (
    <div role="status" aria-live="polite" className="empty:hidden">
      {online ? null : <p className="text-sm text-(--warning-text)">{t("form.offline")}</p>}
    </div>
  );
}
