"use client";

import {copyPlainText} from "@ctrlz/api-client/clipboard.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, toast} from "@heroui/react";
import {useTranslations} from "next-intl";

// A copy button for text that is not a secret (an advertised address). It does not use the one-time-secret copy of the admin's
// `CopyButton`, which empties the clipboard again when the page goes: here the person copies the address to paste it elsewhere.
// The accessible name says what is copied, so two of these on one screen are not both "Copy", and it holds the visible word.

export function PlainCopyButton({text, label}: {text: string; label: string}) {
  const t = useTranslations("admin");
  const c = useTranslations("common");
  return (
    <Button
      size="sm"
      variant="tertiary"
      aria-label={label}
      onPress={async () => {
        try {
          await copyPlainText(text);
          toast.success(c("copied"));
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
