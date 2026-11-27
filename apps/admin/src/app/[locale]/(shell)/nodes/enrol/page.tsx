import {getTranslations} from "next-intl/server";

import {EnrolPage} from "@ctrlz/ui/admin/nodes/EnrolPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("nodes");
  return {title: t("pages.enrol.title")};
}

export default function Page() {
  return <EnrolPage />;
}
