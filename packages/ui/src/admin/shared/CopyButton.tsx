"use client";

import {copyOneTimeSecret} from "@ctrlz/api-client/clipboard.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, toast} from "@heroui/react";
import {useTranslations} from "next-intl";

import {useWipeCopiedOnClose} from "../../dialog/useWipeCopiedOnClose.ts";

// A copy button for a value that is shown once (a one-time password, an invite link, a TOTP secret). The
// clipboard is the browser's, so a failure (a page without permission, an insecure context) is said, never silent.
// The write goes through copyOneTimeSecret, the one writer of the clipboard (gate-r5-8), and the button empties the clipboard
// again when it goes away: it is on screen exactly as long as the value is, so its unmount is the moment the value is gone
// (the panel's account dialogs do the same, see useWipeCopiedOnClose).
// The label names what is copied, so two of these on one screen are not both called "Copy". The text is read when
// the button is pressed and kept nowhere else.

export function CopyButton({
  text,
  label,
  size = "sm",
  onCopied,
}: {
  text: string;
  label: string;
  size?: "sm" | "md";
  /** Called after the clipboard took the text: a screen that must know the value was taken (OneTimeResult) listens. */
  onCopied?: () => void;
}) {
  const t = useTranslations("admin");
  const c = useTranslations("common");
  useWipeCopiedOnClose();
  return (
    <Button
      size={size}
      variant="tertiary"
      aria-label={label}
      onPress={async () => {
        try {
          await copyOneTimeSecret(text);
          toast.success(c("copied"));
          onCopied?.();
        } catch {
          toast.danger(t("copyFailed"));
        }
      }}
    >
      <Icon name="copy" className="size-4" />
      {c("copy")}
    </Button>
  );
}
