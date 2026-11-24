import {SuspendedView} from "@ctrlz/ui/auth/SuspendedView.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("auth");
  return {title: t("suspended.title")};
}

export default function Page() {
  return <SuspendedView />;
}
