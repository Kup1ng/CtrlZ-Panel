import {StubPage} from "@ctrlz/ui/shell/StubPage.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("shell");
  return {title: t("nav.api")};
}

// Stub of a later phase (spec 8.9). Its owner phase replaces this file.
export default async function Page() {
  const t = await getTranslations("shell");
  return (
    <StubPage
      icon="api"
      title={t("nav.api")}
      subtitle={t("pages.api.subtitle")}
      helpKey="apiTokens"
    />
  );
}
