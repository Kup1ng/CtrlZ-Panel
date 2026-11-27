import {ProfileFolderScreen} from "@ctrlz/ui/profiles/ProfileFolderScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("profiles");
  return {title: t("frame.tabs.rules")};
}

export default async function Page({params}: {params: Promise<{id: string; folderId: string}>}) {
  const {id, folderId} = await params;
  return <ProfileFolderScreen profileId={id} folderId={folderId} />;
}
