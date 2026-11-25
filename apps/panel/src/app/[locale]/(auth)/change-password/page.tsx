import {ChangePasswordPage} from "@ctrlz/ui/auth/ChangePasswordForm.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("auth");
  return {title: t("changePassword.title")};
}

export default function Page() {
  return <ChangePasswordPage />;
}
