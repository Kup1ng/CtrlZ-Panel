import {StubPage} from "@ctrlz/ui/shell/StubPage.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("shell");
  return {title: t("nav.endpoints")};
}

// Stub of a later phase (spec 8.9). Its owner phase replaces this file.
export default async function Page() {
  const t = await getTranslations("shell");
  return (
    <StubPage
      icon="endpoints"
      title={t("nav.endpoints")}
      subtitle={t("pages.endpoints.subtitle")}
      helpKey="endpoints"
    />
  );
}
