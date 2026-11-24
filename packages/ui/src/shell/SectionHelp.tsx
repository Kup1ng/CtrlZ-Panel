"use client";

import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";

import {ShellModal} from "./ShellModal.tsx";
import {useShellDialog} from "./useShellDialog.ts";

// T-120. Opens from the "?" in PageHeader, bound to `?helpPane=<key>`. Later
// phases replace the stub text in shell.help.<key>, and add keys with their page.

export const HELP_KEYS = ["account", "profiles", "endpoints", "statistics", "activityLog", "domainTest", "apiTokens"] as const;
export type HelpKey = (typeof HELP_KEYS)[number];

export function isHelpKey(value: string | null): value is HelpKey {
  return value !== null && (HELP_KEYS as readonly string[]).includes(value);
}

export function SectionHelp() {
  const t = useTranslations("shell");
  const dialog = useShellDialog("helpPane");
  // An unknown key in a hand-typed URL opens nothing.
  const key = isHelpKey(dialog.value) ? dialog.value : null;

  return (
    <ShellModal
      isOpen={key !== null}
      onClose={dialog.close}
      title={key ? t(`help.${key}.title`) : ""}
      footer={
        <Button className="w-full" variant="secondary" onPress={dialog.close}>
          {t("help.close")}
        </Button>
      }
    >
      {key ? <p className="text-sm leading-relaxed">{t(`help.${key}.body`)}</p> : null}
    </ShellModal>
  );
}
