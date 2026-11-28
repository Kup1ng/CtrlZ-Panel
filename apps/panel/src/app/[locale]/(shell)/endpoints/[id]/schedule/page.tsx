import {EndpointScheduleScreen} from "@ctrlz/ui/endpoints/EndpointScheduleScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("endpoints");
  return {title: t("frame.tabs.schedule")};
}

export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <EndpointScheduleScreen endpointId={id} />;
}
