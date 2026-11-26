import {getTranslations} from "next-intl/server";

import {NodeDetailPage} from "@ctrlz/ui/admin/nodes/NodeDetailPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("nodes");
  return {title: t("pages.node.title")};
}

export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <NodeDetailPage id={id} />;
}
