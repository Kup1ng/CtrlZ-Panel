import {getTranslations} from "next-intl/server";

import {AdminLoginFlow} from "@ctrlz/ui/admin/auth/AdminLoginFlow.tsx";

export async function generateMetadata() {
  const t = await getTranslations("admin");
  return {title: t("login.title")};
}

export default function Page() {
  return <AdminLoginFlow />;
}
