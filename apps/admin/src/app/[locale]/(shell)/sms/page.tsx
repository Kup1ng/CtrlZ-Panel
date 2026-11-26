import {getTranslations} from "next-intl/server";

import {SmsPage} from "@ctrlz/ui/admin/sms/SmsPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("admin");
  return {title: t("pages.sms.title")};
}

export default function Page() {
  return <SmsPage />;
}
