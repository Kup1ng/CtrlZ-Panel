"use client";

import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {useNameList} from "./pairNames.ts";
import type {PairWarning} from "./pairParts.ts";

// The warnings of SC 8a.9 ("F0 reads no tracker") that apply to the change in front of the admin, each naming its nodes. A warning is a
// sentence with an icon, so the colour never carries it, and the list is a note region the screen reader reaches by name.

export function PairWarningList({warnings, testId = "pair-warnings"}: {warnings: readonly PairWarning[]; testId?: string}) {
  const t = useTranslations("nodes");
  const list = useNameList();
  if (warnings.length === 0) return null;
  return (
    <section aria-labelledby={`${testId}-title`} className="bg-surface-secondary flex flex-col gap-2 rounded-(--radius-box) p-4" data-testid={testId}>
      <h3 id={`${testId}-title`} className="text-sm font-medium">
        {t("pair.warnings.title")}
      </h3>
      <p className="text-muted text-xs">{t("pair.warnings.intro")}</p>
      <ul className="flex flex-col gap-2">
        {warnings.map((w) => (
          <li key={w.id} className="flex items-start gap-2 text-sm" data-warning={w.id}>
            <Icon name="warning" className="mt-0.5 size-4 shrink-0" />
            <span>{t(`pair.warning.${w.id}`, {names: list(w.names), count: w.names.length})}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
