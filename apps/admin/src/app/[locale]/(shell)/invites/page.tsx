import {getTranslations} from "next-intl/server";

import {InvitesPage} from "@ctrlz/ui/admin/invites/InvitesPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("admin");
  return {title: t("pages.invites.title")};
}

export default function Page() {
  return <InvitesPage />;
}
