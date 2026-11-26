import {getTranslations} from "next-intl/server";

import {PairPage} from "@ctrlz/ui/admin/nodes/PairPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("nodes");
  return {title: t("pages.pair.title")};
}

export default function Page() {
  return <PairPage />;
}
