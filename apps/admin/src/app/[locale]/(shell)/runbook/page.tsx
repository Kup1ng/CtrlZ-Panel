import {getTranslations} from "next-intl/server";

import {RunbookPage} from "@ctrlz/ui/admin/runbook/RunbookPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("nodes");
  return {title: t("pages.runbook.title")};
}

export default function Page() {
  return <RunbookPage />;
}
