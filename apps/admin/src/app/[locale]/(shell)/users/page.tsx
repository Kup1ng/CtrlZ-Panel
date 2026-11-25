import {getTranslations} from "next-intl/server";

import {UsersPage} from "@ctrlz/ui/admin/users/UsersPage.tsx";

export async function generateMetadata() {
  const t = await getTranslations("admin");
  return {title: t("pages.users.title")};
}

// The page is a client component: every row comes from the browser through the generated client (spec 14.1), and the
// shell's gate has already asked `/me`.
export default function Page() {
  return <UsersPage />;
}
