"use client";

import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";

import {keepFocus} from "../shared/restoreFocus.ts";

// The impact count of a Settings card could not be had. The Save or Confirm button waits for the numbers, so without a
// way to ask again the only exit was to pick another mode and then the first one again (wp10-r1-3).
export function ImpactFailed({onRetry}: {onRetry: () => unknown}) {
  const t = useTranslations("admin");
  const c = useTranslations("common");
  return (
    <div className="flex flex-wrap items-center justify-between gap-2" data-testid="impact-failed">
      <span className="text-(--danger-text)">{t("settings.impactFailed")}</span>
      <Button size="sm" variant="secondary" onPress={() => keepFocus(onRetry)}>
        {c("retry")}
      </Button>
    </div>
  );
}
