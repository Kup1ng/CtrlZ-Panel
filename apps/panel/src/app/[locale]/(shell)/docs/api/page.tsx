import {ApiDocsScreen} from "@ctrlz/ui/docs/ApiDocsScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("api");
  return {title: t("apiDocsPage.title")};
}

export default function Page() {
  return <ApiDocsScreen />;
}
