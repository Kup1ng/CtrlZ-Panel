import {StatusScreen} from "@ctrlz/ui/status/StatusScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("api");
  return {title: t("statusPage.title")};
}

export default function Page() {
  return <StatusScreen />;
}
