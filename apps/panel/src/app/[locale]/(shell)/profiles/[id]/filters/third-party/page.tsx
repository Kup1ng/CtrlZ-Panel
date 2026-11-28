import {ProfileThirdPartyScreen} from "@ctrlz/ui/profiles/ProfileThirdPartyScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("profiles");
  return {title: t("frame.tabs.filters")};
}

export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <ProfileThirdPartyScreen profileId={id} />;
}
