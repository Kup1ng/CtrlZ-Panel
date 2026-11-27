import {getTranslations} from "next-intl/server";

import {NodesPage} from "@ctrlz/ui/admin/nodes/NodesPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("nodes");
  return {title: t("pages.nodes.title")};
}

export default function Page() {
  return <NodesPage />;
}
