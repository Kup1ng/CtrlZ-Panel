import {DocsScreen} from "@ctrlz/ui/docs/DocsScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("api");
  return {title: t("docsPage.title")};
}

export default function Page() {
  return <DocsScreen />;
}
