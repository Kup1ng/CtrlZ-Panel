import {RegisterFlow} from "@ctrlz/ui/auth/RegisterFlow.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("auth");
  return {title: t("register.title")};
}

export default function Page() {
  return <RegisterFlow />;
}
