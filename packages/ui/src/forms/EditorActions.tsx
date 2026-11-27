"use client";

import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

import {retryText} from "./retryWait.ts";
import {useOnlineStatus} from "./useOnlineStatus.ts";

// The Continue and Cancel pair at the end of an inline editor (spec 12, WF "Preferences"). Cancel comes
// first in the markup and Continue last, so in either direction the primary action is at the end of the
// line. The submit button follows the same waits as an auth form's: disabled while a 429 asks for a pause
// (and says how long) and while the browser is offline. It is a plain button, not `SubmitButton`, because
// that one is full width and tells the auth corner menu that a call is running.

export function EditorActions({
  submitLabel,
  isPending = false,
  retryIn = 0,
  isDisabled = false,
  onCancel,
  cancelLabel,
  variant = "primary",
  form,
  children,
}: {
  submitLabel: string;
  isPending?: boolean;
  retryIn?: number;
  isDisabled?: boolean;
  /** Cancel is left out when the editor has nothing to cancel back to. */
  onCancel?: () => void;
  cancelLabel?: string;
  variant?: "primary" | "danger";
  /** The id of the form this submits, when the buttons sit outside it (a dialog's fixed footer). */
  form?: string;
  /** Extra controls at the start of the line (a Resend button). */
  children?: ReactNode;
}) {
  const t = useTranslations("auth");
  const c = useTranslations("common");
  const online = useOnlineStatus();
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="flex items-center gap-2">{children}</div>
      <div className="flex items-center gap-2">
        {onCancel ? (
          <Button variant="tertiary" isDisabled={isPending} onPress={onCancel}>
            {cancelLabel ?? c("cancel")}
          </Button>
        ) : null}
        <Button type="submit" form={form} variant={variant} isPending={isPending} isDisabled={isDisabled || !online || retryIn > 0}>
          {retryIn > 0 ? retryText(t, retryIn) : submitLabel}
        </Button>
      </div>
    </div>
  );
}
