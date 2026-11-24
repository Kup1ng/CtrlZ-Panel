import {getTranslations} from "next-intl/server";

import {AuditPage} from "@ctrlz/ui/admin/audit/AuditPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("admin");
  return {title: t("pages.audit.title")};
}

export default function Page() {
  return <AuditPage />;
}
