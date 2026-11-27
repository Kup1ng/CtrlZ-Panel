import {ProfileServicesScreen} from "@ctrlz/ui/profiles/ProfileServicesScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("profiles");
  return {title: t("frame.tabs.services")};
}

export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <ProfileServicesScreen profileId={id} />;
}
