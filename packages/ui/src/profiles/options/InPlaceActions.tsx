"use client";

import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

import {useOnlineStatus} from "../../forms/useOnlineStatus.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// The Cancel and Save pair at the end of a value that opened in place (WF "Profile Options": "Save"). Both names carry the option's
// name, so a page of fifteen rows has no two buttons that read alike to a screen reader. The name starts with what the button shows,
// the visible word or the retry countdown that replaces it (WCAG 2.5.3), and the subject follows. Save waits out a 429 and an offline
// browser, like the buttons of the sign-in forms.

export function InPlaceActions({
  subject,
  isPending,
  retryIn = 0,
  isDisabled = false,
  onCancel,
  extra,
}: {
  subject: string;
  isPending: boolean;
  retryIn?: number;
  isDisabled?: boolean;
  onCancel: () => void;
  extra?: ReactNode;
}) {
  const c = useTranslations("common");
  const a = useTranslations("auth");
  const online = useOnlineStatus();
  const visibleSave = retryIn > 0 ? a("form.retryIn", {seconds: retryIn}) : c("save");
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="flex items-center gap-2">{extra}</div>
      <div className="flex items-center gap-2">
        <Button variant="tertiary" isDisabled={isPending || isDisabled} aria-label={`${c("cancel")}: ${subject}`} onPress={onCancel}>
          {c("cancel")}
        </Button>
        <PrimaryButton
          type="submit"
          isPending={isPending}
          isDisabled={isDisabled || !online || retryIn > 0}
          aria-label={`${visibleSave}: ${subject}`}
        >
          {visibleSave}
        </PrimaryButton>
      </div>
    </div>
  );
}
