"use client";

// /docs (spec p3 10, Plan T-125): the index of the guides. Rows of the same shape as the lists of the panel (ListRow, one main link each), in two
// sections. Every destination is inside the panel; nothing here leaves the origin (guideIndex.ts, and logo-links.spec.ts reads the page).

import {useTranslations} from "next-intl";

import {ListRow, RowList} from "../data/ListRow.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {PageHeader} from "../shell/PageHeader.tsx";
import {GUIDE_SECTIONS} from "./guideIndex.ts";

export function DocsScreen() {
  const t = useTranslations("api");
  return (
    <div data-screen="docs">
      <PageHeader icon="help" title={t("docsPage.title")} subtitle={t("docsPage.subtitle")} helpKey="docs" />
      <div className="flex w-full max-w-3xl flex-col gap-8 pb-8">
        {GUIDE_SECTIONS.map((section) => (
          <section key={section.id} aria-labelledby={`docs-${section.id}`} className="flex flex-col gap-2" data-docs-section={section.id}>
            <h2 id={`docs-${section.id}`} className="text-muted text-xs font-medium">
              {t(`docsPage.sections.${section.id}`)}
            </h2>
            <RowList aria-label={t(`docsPage.sections.${section.id}`)}>
              {section.entries.map((entry) => (
                <ListRow
                  key={entry.id}
                  icon={<Icon name={entry.icon} className="size-5" />}
                  title={t(`docsPage.entries.${entry.id}.title`)}
                  subtitle={t(`docsPage.entries.${entry.id}.text`)}
                  href={entry.href}
                />
              ))}
            </RowList>
          </section>
        ))}
      </div>
    </div>
  );
}
