import {EndpointClientsScreen} from "@ctrlz/ui/endpoints/EndpointClientsScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("endpoints");
  return {title: t("frame.tabs.clients")};
}

export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <EndpointClientsScreen endpointId={id} />;
}
