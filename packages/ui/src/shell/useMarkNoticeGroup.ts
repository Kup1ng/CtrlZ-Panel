"use client";

import {useMarkNotificationsRead} from "@ctrlz/api-client/hooks/notifications.ts";
import {isApiError} from "@ctrlz/api-client/errors.ts";
import {toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useCallback} from "react";

import {useErrorText} from "../feedback/errorText.ts";

// One press of Mark as read, or the close button of a banner, on a group of security notices (webi-r2-3, webi-r2-8). The calls go
// one after another and in a bounded number (see markNotificationsReadOptions), and the person is told in a sentence when the
// press did not clear the whole group: a refusal (the rate limit) or a group larger than one press may send. A second press while
// the first is running is ignored, so two presses cannot double the calls. "Wait a minute and press again" is told only for the
// refusals that waiting cures (the write budget); any other failure reads as its own error text, and a 409 is no failure of the
// press at all (markNotificationsReadOptions skips it, webi-r3-2, webi-r3-4).

export function useMarkNoticeGroup(): (ids: string[]) => void {
  const t = useTranslations("shell");
  const errorText = useErrorText();
  const {mutate, isPending} = useMarkNotificationsRead();
  return useCallback(
    (ids: string[]) => {
      if (isPending || ids.length === 0) return;
      mutate(ids, {
        onSuccess: ({done, left}) => {
          if (left > 0) toast.info(t("bell.security.markPartial", {done, left}));
        },
        onError: (error) => toast.danger(isWaitable(error) ? t("bell.security.markFailed") : errorText(error)),
      });
    },
    [mutate, isPending, t, errorText],
  );
}

/** The answers that a minute's wait cures: the write budget of the session. */
function isWaitable(error: unknown): boolean {
  return isApiError(error) && (error.status === 429 || error.code === "rate_limited" || error.code === "too_many_attempts");
}
