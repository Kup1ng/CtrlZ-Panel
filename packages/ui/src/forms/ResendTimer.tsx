"use client";

import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useEffect, useState} from "react";

import {secondsLeft} from "./useCountdown.ts";

// Spec 10, "ResendTimer": disabled with a countdown from the `resend_after_s` of the last OTP. The
// caller mounts it with a `key` that changes for every new challenge, so the count starts again from
// the new `readyAt` without an effect that copies a prop into state.

export function ResendTimer({
  readyAt,
  onResend,
  isPending,
  isDisabled,
}: {
  /** `Date.now()` plus `resend_after_s`, taken when the challenge arrived. */
  readyAt: number;
  onResend: () => void;
  isPending?: boolean;
  isDisabled?: boolean;
}) {
  const t = useTranslations("auth");
  const [left, setLeft] = useState(() => secondsLeft(readyAt, Date.now()));
  const waiting = left > 0;

  useEffect(() => {
    if (!waiting) return;
    const id = setInterval(() => setLeft(secondsLeft(readyAt, Date.now())), 250);
    return () => clearInterval(id);
  }, [waiting, readyAt]);

  return (
    <Button size="sm" variant="ghost" isPending={isPending} isDisabled={waiting || isDisabled} onPress={onResend}>
      {waiting ? t("resend.wait", {seconds: left}) : t("resend.action")}
    </Button>
  );
}
