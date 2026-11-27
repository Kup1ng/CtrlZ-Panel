import {EndpointIpsScreen} from "@ctrlz/ui/endpoints/EndpointIpsScreen.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("endpoints");
  return {title: t("frame.tabs.ips")};
}

export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <EndpointIpsScreen endpointId={id} />;
}
