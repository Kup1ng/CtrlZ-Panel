"use client";

import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useLocale, useTranslations} from "next-intl";

// SC 8a.9, Replacement order: at four nodes every slot is held, and a paired node cannot be removed, so the way to replace one is not
// "remove one" but this order. The Nodes page and the enrolment page say it when no slot is free (T-341, T-342), the Pair page has its own
// copy in the notes. The list is the page's own text with Persian digits in fa.

const STEPS = ["put", "remove", "approve"] as const;

export function ReplacementSteps({className}: {className?: string}) {
  const t = useTranslations("nodes");
  const numbering = useLocale() === "fa" ? "persian" : "decimal";
  return (
    <>
      <ol className={`flex list-decimal flex-col gap-1.5 ps-6 text-sm ${className ?? ""}`} style={{listStyleType: numbering}} data-testid="replacement-steps">
        {STEPS.map((step) => (
          <li key={step}>{t(`replacement.steps.${step}`)}</li>
        ))}
      </ol>
      <p className="text-sm" data-testid="replacement-address">
        {t("replacement.address")}
      </p>
    </>
  );
}

/** The note of the Nodes page: shown only when every slot is held. */
export function ReplacementOrder() {
  const t = useTranslations("nodes");
  return (
    <div role="note" className="bg-surface-secondary flex max-w-3xl items-start gap-3 rounded-(--radius-box) p-4 text-sm" data-testid="replacement-order">
      <Icon name="warning" className="mt-0.5 size-4 shrink-0" />
      <div className="flex min-w-0 flex-col gap-2">
        <span className="font-medium">{t("replacement.title")}</span>
        <span className="text-muted">{t("replacement.intro")}</span>
        <ReplacementSteps />
        <Link href="/runbook" className="self-start underline underline-offset-2">
          {t("replacement.runbook")}
        </Link>
      </div>
    </div>
  );
}
