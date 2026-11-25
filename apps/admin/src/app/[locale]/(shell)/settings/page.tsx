import {getTranslations} from "next-intl/server";

import {SettingsPage} from "@ctrlz/ui/admin/settings/SettingsPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("admin");
  return {title: t("pages.settings.title")};
}

export default function Page() {
  return <SettingsPage />;
}
