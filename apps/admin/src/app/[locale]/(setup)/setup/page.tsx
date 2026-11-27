import {getTranslations} from "next-intl/server";

import {SetupFlow} from "@ctrlz/ui/admin/auth/SetupFlow.tsx";

export async function generateMetadata() {
  const t = await getTranslations("admin");
  return {title: t("setup.title")};
}

export default function Page() {
  return <SetupFlow />;
}
