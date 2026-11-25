"use client";

import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

import {useReportAuthBusy} from "./useAuthBusy.ts";
import {useHydrated} from "./useHydrated.ts";
import {useOnlineStatus} from "./useOnlineStatus.ts";
import {PrimaryButton} from "./PrimaryButton.tsx";

// The primary button of an auth form, with the three states of the table in 10.1 that belong to the
// button: `isPending` while the call runs (fields are disabled by the form), disabled while a 429 or a
// busy server asks to wait (the label says how long), and disabled while the browser is offline.
export function SubmitButton({
  children,
  isPending = false,
  retryIn = 0,
  isDisabled = false,
  className,
}: {
  children: ReactNode;
  isPending?: boolean;
  retryIn?: number;
  isDisabled?: boolean;
  className?: string;
}) {
  const t = useTranslations("auth");
  const online = useOnlineStatus();
  const hydrated = useHydrated();
  // The corner menu keeps the language switch off while a call runs (wp8-r9-6).
  useReportAuthBusy(isPending);
  return (
    <PrimaryButton
      type="submit"
      fullWidth
      isPending={isPending}
      isDisabled={isDisabled || !hydrated || !online || retryIn > 0}
      className={className}
    >
      {retryIn > 0 ? t("form.retryIn", {seconds: retryIn}) : children}
    </PrimaryButton>
  );
}
