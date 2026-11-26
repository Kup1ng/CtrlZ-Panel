import {getTranslations} from "next-intl/server";

import {DomainPage} from "@ctrlz/ui/admin/domain/DomainPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("nodes");
  return {title: t("pages.domain.title")};
}

export default function Page() {
  return <DomainPage />;
}
