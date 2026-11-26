"use client";

import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {buttonVariants} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";

import {PageHeader} from "../../shell/PageHeader.tsx";

// T-561, T-546. The page the Nodes page links to. It holds the steps that happen outside the panel, as the shared contract writes them
// (8a.4, Addresses given up; 5.2a, 8a.9): retiring a node, moving it to a new address, and the free DNS cases. It is the stub of the
// runbook, in the app so that the link never leaves the origin: the full runbook of the Panel repository (docs/runbooks/p4-nodes.md)
// replaces the text when the docs package lands. The compromise runbook (SC 8a.9, eight steps) is the first section, because the hold note and
// the revoke dialog of a node link to it.

const RETIRE = ["replace", "parent", "remove", "giveBack"] as const;
const COMPROMISE = ["revoke", "replace", "stop", "keys", "transparency", "caa", "registrar", "remove"] as const;
const FREE = ["listed", "resolver", "interface"] as const;

export function RunbookPage() {
  const t = useTranslations("nodes");
  // The numbers of a list are the page's own digits: Persian in fa (the marker is drawn by the browser, so the style says it).
  const numbering = useLocale() === "fa" ? "persian" : "decimal";
  return (
    <>
      <PageHeader icon="runbook" title={t("pages.runbook.title")} subtitle={t("pages.runbook.subtitle")} />
      <div className="flex max-w-3xl flex-col gap-8" data-testid="runbook">
        <section id="compromise" aria-labelledby="runbook-compromise" className="flex scroll-mt-20 flex-col gap-2" data-testid="runbook-compromise">
          <h2 id="runbook-compromise" className="text-base font-medium">
            {t("runbook.compromise.title")}
          </h2>
          <p className="text-sm">{t("runbook.compromise.intro")}</p>
          <p className="text-muted text-sm">{t("runbook.compromise.hold")}</p>
          <ol className="flex list-decimal flex-col gap-2 ps-6 text-sm" style={{listStyleType: numbering}}>
            {COMPROMISE.map((step) => (
              <li key={step}>{t(`runbook.compromise.steps.${step}`)}</li>
            ))}
          </ol>
        </section>
        <section aria-labelledby="runbook-retire" className="flex flex-col gap-2">
          <h2 id="runbook-retire" className="text-base font-medium">
            {t("runbook.retire.title")}
          </h2>
          <ol className="flex list-decimal flex-col gap-2 ps-6 text-sm" style={{listStyleType: numbering}}>
            {RETIRE.map((step) => (
              <li key={step}>{t(`runbook.retire.steps.${step}`)}</li>
            ))}
          </ol>
        </section>
        <section aria-labelledby="runbook-move" className="flex flex-col gap-2">
          <h2 id="runbook-move" className="text-base font-medium">
            {t("runbook.move.title")}
          </h2>
          <p className="text-sm">{t("runbook.move.text")}</p>
        </section>
        <section aria-labelledby="runbook-free" className="flex flex-col gap-2">
          <h2 id="runbook-free" className="text-base font-medium">
            {t("runbook.free.title")}
          </h2>
          <ul className="flex list-disc flex-col gap-2 ps-6 text-sm">
            {FREE.map((step) => (
              <li key={step}>{t(`runbook.free.steps.${step}`)}</li>
            ))}
          </ul>
        </section>
        <section aria-labelledby="runbook-outside" className="flex flex-col gap-2">
          <h2 id="runbook-outside" className="text-base font-medium">
            {t("runbook.outside.title")}
          </h2>
          <p className="text-sm">{t("runbook.outside.text")}</p>
        </section>
        <Link href="/nodes" className={buttonVariants({variant: "secondary", size: "sm"})}>
          <Icon name="chevron" className="size-4 rotate-180 rtl:rotate-0" />
          {t("runbook.back")}
        </Link>
      </div>
    </>
  );
}
