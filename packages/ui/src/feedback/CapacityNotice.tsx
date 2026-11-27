"use client";

import {Alert} from "@heroui/react";
import {capOf, exceededCap, useLimits} from "@ctrlz/api-client/hooks/limits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";

// Spec p2 3.4 and p3 3.5. A write over a limit is 422 `validation_failed` with the field `<limit>` coded `exceeded`, and nothing is
// written. The answer names the limit, not its number, so this notice names what was reached ("the limit of profiles") and, when
// `GET /account/limits` has the figure, how many ("5"). It is a warning, with an icon and words, in the place where the write was
// asked; the form's own error line is not used for it, because nothing in the form is wrong.
//
// It renders nothing for an error that is not a limit, so a screen can put it beside `FormError` and let each take what is theirs.

export function CapacityNotice({error, className}: {error: unknown; className?: string}) {
  const t = useTranslations("errors");
  const format = useAppFormat();
  const cap = exceededCap(error);
  const limits = useLimits({enabled: cap !== null});
  if (!cap) return null;
  const limit = capOf(limits.data, cap.name);
  const what = t(`limits.names.${cap.name}`);
  return (
    <Alert status="warning" className={className}>
      <Alert.Indicator />
      <Alert.Content className="min-w-0">
        <Alert.Title>{limit === undefined ? t("limits.notice", {what}) : t("limits.noticeCap", {what, limit: format.number(limit)})}</Alert.Title>
      </Alert.Content>
    </Alert>
  );
}
