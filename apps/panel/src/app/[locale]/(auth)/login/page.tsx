import {LoginFlow} from "@ctrlz/ui/auth/LoginFlow.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("auth");
  return {title: t("login.title")};
}

export default function Page() {
  return <LoginFlow />;
}
