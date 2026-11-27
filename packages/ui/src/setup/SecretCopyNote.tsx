"use client";

import {useTranslations} from "next-intl";

/**
 * The note FE 12.3 asks for under the Copy controls of a secret: closing empties the whole clipboard, a refused write is retried, and the
 * clipboard history of the system is out of reach. Shown once under the secret rows of a screen, not under each.
 */
export function SecretCopyNote() {
  const t = useTranslations("setup");
  return (
    <p className="text-muted text-xs" data-testid="copy-note">
      {t("copyNote")}
    </p>
  );
}
