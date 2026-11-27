import {ShareScreen} from "@ctrlz/ui/endpoints/ShareScreen.tsx";
import {getTranslations} from "next-intl/server";
import type {Metadata} from "next";

// Spec p3 7.2. A page opened from a link that is a secret: it is not indexed, and it sends no Referer to anything it links to, so the
// value in the address never reaches another page's log. The value is read from the path here and handed to the screen, which sends it in
// the body of POST /public/share and nowhere else.
export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("setup");
  return {title: t("share.title"), robots: {index: false, follow: false, nocache: true}, referrer: "no-referrer"};
}

export default async function Page({params}: {params: Promise<{token: string}>}) {
  const {token} = await params;
  return <ShareScreen token={token} />;
}
