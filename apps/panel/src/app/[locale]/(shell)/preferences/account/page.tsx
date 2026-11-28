import {AccountPage} from "@ctrlz/ui/account/AccountPage.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("account");
  return {title: t("page.title")};
}

// Spec 12. The page is a client component: everything on it comes from the browser through the
// generated client (spec 14.1), and the session gate of the shell has already asked `/me`.
export default function Page() {
  return <AccountPage />;
}
