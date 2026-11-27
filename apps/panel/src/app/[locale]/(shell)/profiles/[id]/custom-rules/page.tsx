import {ProfileRulesScreen} from "@ctrlz/ui/profiles/ProfileRulesScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("profiles");
  return {title: t("frame.tabs.rules")};
}

export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <ProfileRulesScreen profileId={id} />;
}
