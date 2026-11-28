import {getTranslations} from "next-intl/server";

import {OverviewPage} from "@ctrlz/ui/admin/overview/OverviewPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("nodes");
  return {title: t("pages.overview.title")};
}

export default function Page() {
  return <OverviewPage />;
}
