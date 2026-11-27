import {ProfileOptionsScreen} from "@ctrlz/ui/profiles/ProfileOptionsScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("profiles");
  return {title: t("frame.tabs.options")};
}

export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <ProfileOptionsScreen profileId={id} />;
}
