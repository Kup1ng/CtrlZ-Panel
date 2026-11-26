import {ForgotFlow} from "@ctrlz/ui/auth/ForgotFlow.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("auth");
  return {title: t("forgot.title")};
}

export default function Page() {
  return <ForgotFlow />;
}
